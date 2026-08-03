"""The main application window.

A stacked layout with a sidebar: Scan, Results, Quarantine, Settings. The
window owns the :class:`ScanController` and routes its signals to whichever
views care.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from PySide6.QtCore import Qt, QTimer, Slot
from PySide6.QtGui import QAction, QCloseEvent, QKeySequence
from PySide6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QStackedWidget,
    QStatusBar,
    QVBoxLayout,
    QWidget,
)

from sentinel.core.config import Config
from sentinel.core.db import Database
from sentinel.core.logger import get_logger
from sentinel.engine.verdict import ScanResult
from sentinel.ui.app import ScanController
from sentinel.ui.tray import SentinelTray, status_from_world
from sentinel.ui.windows.quarantine_view import QuarantineView
from sentinel.ui.windows.results_view import ResultsView
from sentinel.ui.windows.scan_view import ScanView
from sentinel.ui.windows.settings_view import SettingsView
from sentinel.utils.humanize import human_count, human_duration
from sentinel.version import __version__

log = get_logger(__name__)

_PAGES = (
    ("Scan", "Start and monitor a scan"),
    ("Results", "Findings from the last scan"),
    ("Quarantine", "Files held in the vault"),
    ("Settings", "Configuration and privacy"),
)

#: How often the tray re-derives its state from the world. Slow enough to be
#: free at idle, fast enough that a vault emptied elsewhere is reflected
#: before the user goes looking for it.
TRAY_REFRESH_MS = 15_000


class MainWindow(QMainWindow):
    """Top-level window."""

    def __init__(self, config: Config) -> None:
        super().__init__()
        self.config = config
        self.db = Database(config.paths.db_file)
        self.controller = ScanController(self)
        self._last_result: ScanResult | None = None
        self._scan_fraction: float | None = None
        self._scan_eta: float | None = None
        self._quitting = False

        self.setWindowTitle(f"Sentinel Scan {__version__}")
        self.resize(1100, 720)
        self.setMinimumSize(860, 560)

        self._build_ui()
        self._build_menu()
        self._connect()
        self._build_tray()

        # Refreshes the icon from the world rather than from events, so a
        # vault emptied from the CLI, or a threat list updated in the
        # background, still reaches the tray.
        self._tray_timer = QTimer(self)
        self._tray_timer.setInterval(TRAY_REFRESH_MS)
        self._tray_timer.timeout.connect(self.refresh_tray)
        self._tray_timer.start()

    # -- construction --------------------------------------------------

    def _build_ui(self) -> None:
        central = QWidget()
        layout = QHBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self.sidebar = QListWidget()
        self.sidebar.setObjectName("sidebar")
        self.sidebar.setFixedWidth(180)
        for title, tooltip in _PAGES:
            item = QListWidgetItem(title)
            item.setToolTip(tooltip)
            item.setTextAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
            self.sidebar.addItem(item)
        self.sidebar.setCurrentRow(0)

        self.pages = QStackedWidget()
        self.scan_view = ScanView(self.config)
        self.results_view = ResultsView(self.config, self.db)
        self.quarantine_view = QuarantineView(self.config, self.db)
        self.settings_view = SettingsView(self.config)

        for view in (
            self.scan_view, self.results_view,
            self.quarantine_view, self.settings_view,
        ):
            self.pages.addWidget(view)

        layout.addWidget(self.sidebar)

        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.addWidget(self.pages)
        layout.addWidget(right, stretch=1)

        self.setCentralWidget(central)

        self.status = QStatusBar()
        self.status_label = QLabel("Ready")
        self.status.addWidget(self.status_label)
        self.setStatusBar(self.status)

    def _build_menu(self) -> None:
        file_menu = self.menuBar().addMenu("&File")

        scan_action = QAction("&New scan", self)
        scan_action.setShortcut(QKeySequence.StandardKey.New)
        scan_action.triggered.connect(lambda: self.sidebar.setCurrentRow(0))
        file_menu.addAction(scan_action)

        export_action = QAction("&Export last report…", self)
        export_action.setShortcut(QKeySequence.StandardKey.Save)
        export_action.triggered.connect(self._export_report)
        file_menu.addAction(export_action)

        file_menu.addSeparator()
        quit_action = QAction("&Quit", self)
        quit_action.setShortcut(QKeySequence.StandardKey.Quit)
        quit_action.triggered.connect(self.close)
        file_menu.addAction(quit_action)

        tools_menu = self.menuBar().addMenu("&Tools")

        update_action = QAction("&Update signatures", self)
        update_action.triggered.connect(self._update_signatures)
        tools_menu.addAction(update_action)

        system_action = QAction("&System report", self)
        system_action.triggered.connect(self._show_system_report)
        tools_menu.addAction(system_action)

        help_menu = self.menuBar().addMenu("&Help")
        about_action = QAction("&About", self)
        about_action.triggered.connect(self._show_about)
        help_menu.addAction(about_action)

    def _connect(self) -> None:
        self.sidebar.currentRowChanged.connect(self.pages.setCurrentIndex)
        self.scan_view.scan_requested.connect(self._start_scan)
        self.scan_view.cancel_requested.connect(self.controller.cancel)
        self.results_view.rescan_requested.connect(self._start_scan)

    def _build_tray(self) -> None:
        """Attach the tray icon, if this desktop has one.

        Several Linux sessions do not, so the window has to work without it
        rather than becoming unreachable.
        """
        self.tray: SentinelTray | None = None
        if not SentinelTray.available():
            log.info("no system tray on this desktop; running windowed only")
            return

        self.tray = SentinelTray(self)
        self.tray.scan_requested.connect(self._scan_from_tray)
        self.tray.open_requested.connect(self._show_from_tray)
        self.tray.review_requested.connect(self._review_from_tray)
        self.tray.quit_requested.connect(self._quit_from_tray)
        self.tray.show()
        self.refresh_tray()

    # -- tray ----------------------------------------------------------

    def refresh_tray(self) -> None:
        """Rebuild the tray status from what is currently true."""
        if self.tray is None:
            return

        running = self.controller.is_running
        unresolved = 0
        if self._last_result is not None:
            # A finding the user has neither had moved nor dismissed.
            unresolved = sum(
                1 for v in self._last_result.threats
                if v.action in ("none", "reported")
            )

        try:
            status = status_from_world(
                self.config, self.db,
                scanning=running,
                scan_fraction=self._scan_fraction,
                scan_eta_seconds=self._scan_eta,
                unresolved_threats=unresolved,
            )
        except Exception as exc:  # pragma: no cover - defensive
            log.debug("cannot refresh the tray: %s", exc)
            return

        self.tray.set_status(status)

    @Slot(dict)
    def _on_tray_progress(self, payload: dict[str, Any]) -> None:
        self._scan_fraction = payload.get("fraction")
        self._scan_eta = payload.get("eta_seconds")
        self.refresh_tray()

    @Slot()
    def _scan_from_tray(self) -> None:
        if self.controller.is_running:
            self.controller.cancel()
            return
        self._start_scan(self.scan_view.default_roots(), False)

    @Slot()
    def _show_from_tray(self) -> None:
        self.showNormal()
        self.raise_()
        self.activateWindow()

    @Slot()
    def _review_from_tray(self) -> None:
        self._show_from_tray()
        # Quarantine if anything is in it, otherwise the findings list.
        try:
            row = 2 if self.db.list_quarantine() else 1
        except Exception:
            row = 1
        self.sidebar.setCurrentRow(row)

    @Slot()
    def _quit_from_tray(self) -> None:
        self._quitting = True
        QApplication.quit()

    # -- scan lifecycle ------------------------------------------------

    @Slot(list, bool)
    def _start_scan(self, roots: list[str], quarantine: bool = False) -> None:
        if self.controller.is_running:
            QMessageBox.information(
                self, "Scan in progress",
                "A scan is already running. Cancel it before starting another.",
            )
            return

        if not roots:
            QMessageBox.warning(
                self, "Nothing selected", "Choose at least one folder or drive to scan."
            )
            return

        self.results_view.clear()
        self.scan_view.set_running(True)

        worker = self.controller.start(self.config, roots, quarantine)
        worker.enumerating.connect(self.scan_view.on_enumerating)
        worker.progress.connect(self.scan_view.on_progress)
        worker.progress.connect(self._on_tray_progress)
        worker.threat_found.connect(self._on_threat)
        worker.suspicious_found.connect(self.results_view.add_finding)
        worker.file_error.connect(self.scan_view.on_file_error)
        worker.finished.connect(self._on_finished)
        worker.failed.connect(self._on_failed)

        self.status_label.setText(f"Scanning {human_count(len(roots), 'location')}…")
        self.refresh_tray()

    @Slot(dict)
    def _on_threat(self, payload: dict[str, Any]) -> None:
        self.results_view.add_finding(payload)
        self.scan_view.on_threat(payload)

    @Slot(object)
    def _on_finished(self, result: ScanResult) -> None:
        self._last_result = result
        self.scan_view.set_running(False)
        self.scan_view.on_finished(result)
        self.results_view.load_result(result)

        verb = "cancelled" if result.cancelled else "finished"
        self.status_label.setText(
            f"Scan {verb}: {human_count(result.files_scanned, 'file')} in "
            f"{human_duration(result.duration)} — "
            f"{human_count(result.threat_count, 'threat')}"
        )

        self._scan_fraction = None
        self._scan_eta = None
        self.refresh_tray()

        if result.threat_count:
            self.sidebar.setCurrentRow(1)  # jump to Results

    @Slot(str)
    def _on_failed(self, message: str) -> None:
        self.scan_view.set_running(False)
        self.status_label.setText("Scan failed")
        QMessageBox.critical(self, "Scan failed", message)

    # -- menu actions --------------------------------------------------

    def _export_report(self) -> None:
        from PySide6.QtWidgets import QFileDialog

        if self._last_result is None:
            QMessageBox.information(
                self, "No report", "Run a scan first, then export its report."
            )
            return

        path, _ = QFileDialog.getSaveFileName(
            self, "Export report", "sentinel-report.json", "JSON files (*.json)"
        )
        if not path:
            return

        import json

        try:
            Path(path).write_text(
                json.dumps(self._last_result.to_dict(), indent=2), encoding="utf-8"
            )
        except OSError as exc:
            QMessageBox.critical(self, "Export failed", str(exc))
            return
        self.status_label.setText(f"Report exported to {path}")

    def _update_signatures(self) -> None:
        from sentinel.signatures.updater import SignatureUpdater, UpdateError

        try:
            updater = SignatureUpdater(self.config)
            result = updater.update()
        except UpdateError as exc:
            QMessageBox.warning(self, "Update failed", str(exc))
            return

        QMessageBox.information(self, "Signature update", result.summary())
        self.settings_view.refresh()

    def _show_system_report(self) -> None:
        from sentinel.system import system_report

        report = system_report()
        autoruns = report["autoruns"]
        processes = report["processes"]["flagged"]
        hosts = report["hosts"]

        lines = [
            f"Running as: {report['privileges']['user']} "
            f"({report['privileges']['label']})",
            "",
            f"Autorun entries: {autoruns['total']} "
            f"({len(autoruns['flagged'])} worth a look)",
            f"Processes worth a look: {len(processes)}",
            f"Hosts file findings: {len(hosts['findings'])}",
        ]
        if autoruns["flagged"]:
            lines += ["", "Autoruns:"]
            lines += [f"  • {e['name']} — {e['flags'][0]}"
                      for e in autoruns["flagged"][:8]]

        QMessageBox.information(self, "System report", "\n".join(lines))

    def _show_about(self) -> None:
        QMessageBox.about(
            self,
            "About Sentinel Scan",
            f"<b>Sentinel Scan {__version__}</b><br><br>"
            f"An open-source, cross-platform malware scanner.<br><br>"
            f"Data directory:<br><code>{self.config.paths.data_dir}</code><br><br>"
            f"This build performs no network requests unless you configure a "
            f"server and opt in.",
        )

    # -- shutdown ------------------------------------------------------

    def closeEvent(self, event: QCloseEvent) -> None:  # noqa: N802 (Qt override)
        """Close to the tray, or stop a running scan and quit."""
        # With a tray, closing the window hides it rather than ending the
        # application — the tray is the product, and quitting a background
        # protector because somebody clicked X is not what they meant.
        # Quit is explicit, from the tray menu.
        if self.tray is not None and not self._quitting:
            event.ignore()
            self.hide()
            return

        if self.controller.is_running:
            answer = QMessageBox.question(
                self,
                "Scan in progress",
                "A scan is still running. Cancel it and quit?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if answer != QMessageBox.StandardButton.Yes:
                event.ignore()
                return

            self.controller.cancel()
            if not self.controller.wait(10_000):
                log.warning("scan thread did not stop within 10s")

        self.db.close()
        event.accept()
