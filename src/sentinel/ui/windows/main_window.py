"""The main application window.

A stacked layout with a sidebar: Scan, Results, Quarantine, Settings. The
window owns the :class:`ScanController` and routes its signals to whichever
views care.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from PySide6.QtCore import Qt, Slot
from PySide6.QtGui import QAction, QCloseEvent, QKeySequence
from PySide6.QtWidgets import (
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
from sentinel.system.hardware import stored_summary
from sentinel.ui.app import ScanController
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


class MainWindow(QMainWindow):
    """Top-level window."""

    def __init__(self, config: Config, controller: Any = None) -> None:
        super().__init__()
        self.config = config
        self.db = Database(config.paths.db_file)
        #: The application controller that owns the tray, or None when the
        #: window is running on its own (no tray on this desktop).
        self.app = controller
        self.controller = ScanController(self)
        self._last_result: ScanResult | None = None
        self._scan_fraction: float | None = None
        self._scan_eta: float | None = None

        self.setWindowTitle(f"Sentinel Scan {__version__}")
        self.resize(1100, 720)
        self.setMinimumSize(860, 560)
        self._ensure_theme()

        self._build_ui()
        self._build_menu()
        self._connect()

    # -- construction --------------------------------------------------

    def _ensure_theme(self) -> None:
        """Apply the stylesheet if whoever started us has not.

        ``ui/app.main`` sets it on the QApplication, which covers the shipping
        path. Nothing else does — so a window built directly, which is what
        the CI smoke check and any embedding caller do, came up in Qt's
        default palette. The check still passed, because a window renders
        perfectly well unstyled; it just does not look like this application,
        which means the theme could break and nothing would notice.

        Set on the window rather than the application so a caller who has
        already chosen a stylesheet keeps it.
        """
        from PySide6.QtWidgets import QApplication

        instance = QApplication.instance()
        if instance is not None and instance.styleSheet():
            return

        from sentinel.ui.app import load_stylesheet

        stylesheet = load_stylesheet()
        if stylesheet:
            self.setStyleSheet(stylesheet)

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
        self.settings_view = SettingsView(self.config, stored_summary(self.db))

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

    # -- tray ----------------------------------------------------------

    def unresolved_threats(self) -> int:
        """Findings the user has neither had moved nor dismissed."""
        if self._last_result is None:
            return 0
        return sum(
            1 for v in self._last_result.threats
            if v.action in ("none", "reported")
        )

    def refresh_tray(self) -> None:
        """Ask the controller to re-derive the tray state.

        The window does not own the tray -- the controller does, because the
        tray has to exist before the window does and outlive it being closed.
        """
        if self.app is not None:
            self.app.refresh_tray()

    def start_default_scan(self) -> None:
        """Scan whatever the Scan page is currently set to.

        Used by the tray's "Check my computer", so it does the same thing as
        the button the user can see.
        """
        self._start_scan(self.scan_view.default_roots(), False)

    @Slot(dict)
    def _track_progress(self, payload: dict[str, Any]) -> None:
        """Keep the figures the tray reads, and push them to it."""
        self._scan_fraction = payload.get("fraction")
        self._scan_eta = payload.get("eta_seconds")
        self.refresh_tray()

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
        worker.progress.connect(self._track_progress)
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
        if self.app is not None and not self.app.quitting:
            # With a tray, closing the window hides it rather than ending the
            # application -- the tray is the product, and quitting a
            # background protector because somebody clicked X is not what
            # they meant. Quit is explicit, from the tray menu.
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
