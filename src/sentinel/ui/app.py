"""Qt application bootstrap.

Threading is the thing to get right here. The scan engine is blocking and
runs on worker threads; Qt widgets may only be touched from the GUI thread.
The bridge is :class:`ScanWorker`, which runs a scan on a ``QThread`` and
re-publishes engine events as Qt signals. Views connect to those signals and
never see the engine's threads.
"""

from __future__ import annotations

import sys
from typing import Any

from sentinel.core.config import Config, load_config
from sentinel.core.events import Event, EventBus, EventType
from sentinel.core.logger import get_logger, setup_logging
from sentinel.version import __version__

log = get_logger(__name__)

try:
    from PySide6.QtCore import QObject, QThread, QTimer, Signal
    from PySide6.QtGui import QIcon
    from PySide6.QtWidgets import QApplication

    PYSIDE_AVAILABLE = True
except ImportError as exc:  # pragma: no cover - depends on the environment
    PYSIDE_AVAILABLE = False
    _IMPORT_ERROR = exc

    # Stubs so the module imports (and gives a good error) without PySide6.
    class QObject:  # type: ignore[no-redef]
        pass

    class QThread:  # type: ignore[no-redef]
        pass

    # Named to match Qt's API, not PEP 8, because it stands in for it.
    def Signal(*args: Any, **kwargs: Any) -> Any:  # type: ignore[no-redef] # noqa: N802
        return None


APPLICATION_NAME = "Sentinel Scan"
ORGANISATION_NAME = "sentinel-scan"

#: How often the tray re-derives its state from the world. Slow enough to be
#: free at idle, fast enough that a vault emptied elsewhere is reflected
#: before the user goes looking for it.
TRAY_REFRESH_MS = 15_000


class ScanWorker(QObject):
    """Runs a scan off the GUI thread and re-emits its events as signals.

    Every signal is delivered on the GUI thread by Qt's queued-connection
    machinery, so slots may touch widgets freely.
    """

    #: Full progress payload: counts, totals, fraction and time remaining.
    progress = Signal(dict)
    #: Counting the tree, before any of it is read.
    enumerating = Signal(dict)
    threat_found = Signal(dict)           # verdict payload
    suspicious_found = Signal(dict)
    file_error = Signal(str, str)         # path, error
    finished = Signal(object)             # ScanResult
    failed = Signal(str)
    started = Signal(list)                # roots

    def __init__(
        self,
        config: Config,
        roots: list[str],
        quarantine: bool = False,
        detectors: list[str] | None = None,
    ) -> None:
        super().__init__()
        self.config = config
        self.roots = roots
        self.quarantine = quarantine
        self.detectors = detectors
        self.bus = EventBus()
        self._scanner: Any = None
        self._cancelled = False

    def run(self) -> None:
        """Entry point connected to ``QThread.started``."""
        from sentinel.engine.scanner import Scanner
        from sentinel.engine.verdict import Severity
        from sentinel.signatures.updater import refresh_revocations_in_background

        self.bus.subscribe(EventType.SCAN_ENUMERATING, self._on_enumerating)
        self.bus.subscribe(EventType.SCAN_PROGRESS, self._on_progress)
        self.bus.subscribe(EventType.THREAT_FOUND, self._on_threat)
        self.bus.subscribe(EventType.SUSPICIOUS_FOUND, self._on_suspicious)
        self.bus.subscribe(EventType.FILE_ERROR, self._on_error)

        try:
            self._scanner = Scanner(self.config, bus=self.bus, detectors=self.detectors)
            # Pick up newly revoked rules on the way past. Backgrounded and
            # rate limited; a dead mirror delays the scan by nothing.
            refresh_revocations_in_background(self.config, self._scanner.db)
            self.started.emit(self.roots)
            result = self._scanner.scan_paths(
                self.roots, self.quarantine, Severity.HIGH
            )
            self.finished.emit(result)
        except Exception as exc:
            log.exception("scan failed")
            self.failed.emit(str(exc))
        finally:
            # Stop delivering events before the worker object goes away, or a
            # late event can call into a deleted Qt object.
            self.bus.mute()
            if self._scanner is not None:
                self._scanner.close()
                self._scanner = None

    def cancel(self) -> None:
        """Ask the running scan to stop. Safe to call from the GUI thread."""
        self._cancelled = True
        if self._scanner is not None:
            self._scanner.cancel()

    # -- event bridge --------------------------------------------------

    def _on_progress(self, event: Event) -> None:
        self.progress.emit(dict(event.payload))

    def _on_enumerating(self, event: Event) -> None:
        self.enumerating.emit(dict(event.payload))

    def _on_threat(self, event: Event) -> None:
        self.threat_found.emit(dict(event.payload))

    def _on_suspicious(self, event: Event) -> None:
        self.suspicious_found.emit(dict(event.payload))

    def _on_error(self, event: Event) -> None:
        self.file_error.emit(event.get("path", ""), event.get("error", ""))


class ScanController(QObject):
    """Owns the worker thread and exposes a simple start/cancel API."""

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._thread: QThread | None = None
        self._worker: ScanWorker | None = None

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.isRunning()

    def start(
        self,
        config: Config,
        roots: list[str],
        quarantine: bool = False,
        detectors: list[str] | None = None,
    ) -> ScanWorker:
        """Begin a scan. Raises if one is already running."""
        if self.is_running:
            raise RuntimeError("a scan is already running")

        worker = ScanWorker(config, roots, quarantine, detectors)
        thread = QThread()
        worker.moveToThread(thread)

        thread.started.connect(worker.run)
        worker.finished.connect(thread.quit)
        worker.failed.connect(thread.quit)
        thread.finished.connect(self._cleanup)

        self._worker, self._thread = worker, thread
        thread.start()
        return worker

    def cancel(self) -> None:
        if self._worker is not None:
            self._worker.cancel()

    def wait(self, timeout_ms: int = 10_000) -> bool:
        """Block until the scan thread exits. Used on window close."""
        if self._thread is None:
            return True
        return self._thread.wait(timeout_ms)

    def _cleanup(self) -> None:
        if self._worker is not None:
            self._worker.deleteLater()
        if self._thread is not None:
            self._thread.deleteLater()
        self._worker = None
        self._thread = None


def load_stylesheet() -> str:
    """Read the bundled Qt stylesheet, returning "" if it is missing."""
    from pathlib import Path

    path = Path(__file__).resolve().parent / "styles" / "theme.qss"
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        log.debug("stylesheet not loaded: %s", exc)
        return ""


class SentinelApp(QObject):
    """Owns the tray, and builds the main window only if it is asked for.

    The split exists for memory. On the machines this is built for, idle RAM
    is a budget with a number on it, and the main window's four pages cost
    around 35 MB that most users never look at — the design says the flyout
    *is* the application and the window is one click away for the rare
    occasion somebody needs it. Constructing it at startup spends that on
    everybody to save a moment for the few.

    So the tray comes up alone, and :meth:`window` builds the rest on first
    use. After that it stays: somebody who has opened it once will open it
    again, and rebuilding is slower than keeping.
    """

    def __init__(self, config: Config) -> None:
        super().__init__()
        from sentinel.core.db import Database
        from sentinel.system.hardware import tune_once
        from sentinel.ui.tray import SentinelTray, status_from_world

        self.config = config
        self.db = Database(config.paths.db_file)
        self._status_from_world = status_from_world
        self._window: Any = None
        self._quitting = False

        # Measured before anything is shown, so the first scan uses the
        # settings chosen for this machine rather than the defaults.
        self.tuning = tune_once(config, self.db)

        self.tray: Any = None
        if SentinelTray.available():
            self.tray = SentinelTray(self)
            self.tray.scan_requested.connect(self.scan_now)
            self.tray.open_requested.connect(self.show_window)
            self.tray.review_requested.connect(self.review)
            self.tray.quit_requested.connect(self.quit)
            self.tray.show()

            self._timer = QTimer(self)
            self._timer.setInterval(TRAY_REFRESH_MS)
            self._timer.timeout.connect(self.refresh_tray)
            self._timer.start()
            self.refresh_tray()
        else:
            log.info("no system tray on this desktop; opening the window")
            self.show_window()

    # -- the window ----------------------------------------------------

    @property
    def has_window(self) -> bool:
        return self._window is not None

    def window(self) -> Any:
        """The main window, built on first request."""
        if self._window is None:
            from sentinel.ui.windows.main_window import MainWindow

            log.debug("building the main window")
            self._window = MainWindow(self.config, controller=self)
        return self._window

    def show_window(self) -> None:
        window = self.window()
        window.showNormal()
        window.raise_()
        window.activateWindow()

    def review(self) -> None:
        """Open on whichever page has the thing needing attention."""
        self.show_window()
        try:
            row = 2 if self.db.list_quarantine() else 1
        except Exception:
            row = 1
        self._window.sidebar.setCurrentRow(row)

    def scan_now(self) -> None:
        """Start (or stop) a scan, building the window if it does not exist.

        The window carries the scan machinery, so a scan from the tray costs
        the memory the tray was saving — but only while somebody is actually
        scanning, which is what the peak budget is for.
        """
        window = self.window()
        if window.controller.is_running:
            window.controller.cancel()
            return
        window.start_default_scan()

    # -- tray ----------------------------------------------------------

    def refresh_tray(self) -> None:
        if self.tray is None:
            return
        window = self._window
        try:
            status = self._status_from_world(
                self.config, self.db,
                scanning=bool(window and window.controller.is_running),
                scan_fraction=getattr(window, "_scan_fraction", None),
                scan_eta_seconds=getattr(window, "_scan_eta", None),
                unresolved_threats=window.unresolved_threats() if window else 0,
            )
        except Exception as exc:  # pragma: no cover - defensive
            log.debug("cannot refresh the tray: %s", exc)
            return
        self.tray.set_status(status)

    # -- shutdown ------------------------------------------------------

    @property
    def quitting(self) -> bool:
        return self._quitting

    def quit(self) -> None:
        self._quitting = True
        if self._window is not None:
            self._window.close()
        if self.tray is not None:
            self.tray.hide()
        self.db.close()
        QApplication.quit()


def main(config_file: str | None = None) -> int:
    """Launch the desktop application. Returns a process exit code."""
    if not PYSIDE_AVAILABLE:
        print(
            "The Sentinel Scan GUI requires PySide6.\n"
            "Install it with:  pip install 'sentinel-scan[gui]'\n"
            f"({_IMPORT_ERROR})",
            file=sys.stderr,
        )
        return 2

    config = load_config(config_file)
    config.paths.ensure()
    setup_logging(config.log_level, config.paths.log_file, force=True)

    app = QApplication(sys.argv)
    app.setApplicationName(APPLICATION_NAME)
    app.setApplicationDisplayName(APPLICATION_NAME)
    app.setOrganizationName(ORGANISATION_NAME)
    app.setApplicationVersion(__version__)
    # The tray keeps the process alive on its own; without this, hiding the
    # window would quit the application.
    app.setQuitOnLastWindowClosed(False)

    stylesheet = load_stylesheet()
    if stylesheet:
        app.setStyleSheet(stylesheet)

    icon = QIcon.fromTheme("security-high")
    if not icon.isNull():
        app.setWindowIcon(icon)

    controller = SentinelApp(config)
    app.aboutToQuit.connect(controller.db.close)

    log.info("GUI started (Sentinel Scan %s)", __version__)
    return app.exec()


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
