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
    from PySide6.QtCore import QObject, QThread, Signal
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


class ScanWorker(QObject):
    """Runs a scan off the GUI thread and re-emits its events as signals.

    Every signal is delivered on the GUI thread by Qt's queued-connection
    machinery, so slots may touch widgets freely.
    """

    progress = Signal(int, int, str)      # files_scanned, bytes_scanned, current
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

        self.bus.subscribe(EventType.SCAN_PROGRESS, self._on_progress)
        self.bus.subscribe(EventType.THREAT_FOUND, self._on_threat)
        self.bus.subscribe(EventType.SUSPICIOUS_FOUND, self._on_suspicious)
        self.bus.subscribe(EventType.FILE_ERROR, self._on_error)

        try:
            self._scanner = Scanner(self.config, bus=self.bus, detectors=self.detectors)
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
        self.progress.emit(
            event.get("files_scanned", 0),
            event.get("bytes_scanned", 0),
            event.get("current", ""),
        )

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

    from sentinel.ui.windows.main_window import MainWindow

    config = load_config(config_file)
    config.paths.ensure()
    setup_logging(config.log_level, config.paths.log_file, force=True)

    app = QApplication(sys.argv)
    app.setApplicationName(APPLICATION_NAME)
    app.setApplicationDisplayName(APPLICATION_NAME)
    app.setOrganizationName(ORGANISATION_NAME)
    app.setApplicationVersion(__version__)

    stylesheet = load_stylesheet()
    if stylesheet:
        app.setStyleSheet(stylesheet)

    icon = QIcon.fromTheme("security-high")
    if not icon.isNull():
        app.setWindowIcon(icon)

    window = MainWindow(config)
    window.show()

    log.info("GUI started (Sentinel Scan %s)", __version__)
    return app.exec()


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
