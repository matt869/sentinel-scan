"""The scan page: choose what to scan, start it, watch it run."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from PySide6.QtCore import Qt, Signal, Slot
from PySide6.QtWidgets import (
    QCheckBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QProgressBar,
    QPushButton,
    QRadioButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from sentinel.core.config import Config
from sentinel.engine.verdict import SEVERITY_COLORS, ScanResult, Severity
from sentinel.ui.widgets import Section
from sentinel.utils.humanize import human_bytes, human_count, human_duration, shorten_path

#: How many lines of live activity to keep. Unbounded growth would eat
#: memory on a multi-million-file scan.
MAX_LOG_LINES = 500


class ScanView(QWidget):
    """Scan configuration and live progress."""

    #: (roots, quarantine)
    scan_requested = Signal(list, bool)
    cancel_requested = Signal()

    def __init__(self, config: Config) -> None:
        super().__init__()
        self.config = config
        self._custom_paths: list[str] = []
        self._threat_count = 0
        self._build()

    def _build(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(32, 28, 32, 28)
        # The gap between sections is what groups them, now that none of them
        # is drawn inside a box. It has to be clearly larger than the spacing
        # between controls within a section (8px) or the grouping inverts.
        layout.setSpacing(26)

        heading = QLabel("Scan")
        heading.setObjectName("heading")
        layout.addWidget(heading)

        layout.addWidget(self._build_target_box())
        layout.addWidget(self._build_options_box())
        layout.addLayout(self._build_buttons())

        progress = self._build_progress_box()
        progress.setVisible(False)
        layout.addWidget(progress, stretch=1)
        layout.addStretch()

    # -- construction --------------------------------------------------

    def _build_target_box(self) -> Section:
        box = Section("What to scan")
        layout = box.body

        self.radio_quick = QRadioButton(
            "Quick — Downloads, temp folders and autostart locations"
        )
        self.radio_quick.setChecked(True)
        self.radio_full = QRadioButton("Full — every fixed drive (slow)")
        self.radio_custom = QRadioButton("Custom — choose folders")

        layout.addWidget(self.radio_quick)
        layout.addWidget(self.radio_full)
        layout.addWidget(self.radio_custom)

        # The folder picker lives inside its own widget so it can be hidden
        # outright rather than greyed out. A disabled list box and two dead
        # buttons, shown to everybody who picked Quick, is a third of this
        # page spent on a mode they are not in — and a control you can see but
        # cannot use is a question the user has to stop and answer.
        self.custom_panel = QWidget()
        custom_row = QHBoxLayout(self.custom_panel)
        custom_row.setContentsMargins(26, 2, 0, 0)

        self.path_list = QListWidget()
        self.path_list.setMaximumHeight(96)
        custom_row.addWidget(self.path_list, stretch=1)

        button_column = QVBoxLayout()
        self.add_button = QPushButton("Add folder…")
        self.add_button.clicked.connect(self._add_path)
        self.remove_button = QPushButton("Remove")
        self.remove_button.clicked.connect(self._remove_path)
        button_column.addWidget(self.add_button)
        button_column.addWidget(self.remove_button)
        button_column.addStretch()
        custom_row.addLayout(button_column)

        self.custom_panel.setVisible(False)
        layout.addWidget(self.custom_panel)

        self.radio_custom.toggled.connect(self._on_custom_toggled)
        return box

    def _build_options_box(self) -> Section:
        box = Section("Options")
        layout = box.body

        self.check_quarantine = QCheckBox(
            "Automatically quarantine high-severity findings"
        )
        self.check_quarantine.setToolTip(
            "Moves files scoring 70 or above into the encrypted vault. "
            "Anything quarantined can be restored from the Quarantine page."
        )
        layout.addWidget(self.check_quarantine)

        self.check_archives = QCheckBox("Look inside archives")
        self.check_archives.setChecked(self.config.scan.archive_depth > 0)
        self.check_archives.toggled.connect(self._on_archives_toggled)
        layout.addWidget(self.check_archives)

        return box

    def _build_buttons(self) -> QHBoxLayout:
        row = QHBoxLayout()
        self.start_button = QPushButton("Start scan")
        self.start_button.setObjectName("primary")
        self.start_button.setMinimumHeight(36)
        self.start_button.clicked.connect(self._on_start)

        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.setMinimumHeight(36)
        self.cancel_button.setEnabled(False)
        self.cancel_button.clicked.connect(self.cancel_requested)

        row.addWidget(self.start_button)
        row.addWidget(self.cancel_button)
        row.addStretch()
        return row

    def _build_progress_box(self) -> Section:
        """Progress, hidden until there is any.

        Before the first scan this section is a title, the words "Not
        running", and a large empty black rectangle — a third of the page
        given over to saying nothing has happened. The page is about starting
        a scan until one is running, and about watching it after that.
        """
        box = Section("Progress")
        self.progress_section = box
        layout = box.body

        self.progress = QProgressBar()
        # Starts indeterminate. The scan counts the tree before reading any
        # of it, and until that finishes a percentage would be a guess that
        # jumps backwards the moment a large directory turns up. The bar
        # switches to a real range in _switch_to_measured once the total is
        # known.
        self.progress.setRange(0, 0)
        self.progress.setVisible(False)
        layout.addWidget(self.progress)

        self.stats_label = QLabel("Not running")
        self.stats_label.setObjectName("stats")
        layout.addWidget(self.stats_label)

        self.current_label = QLabel("")
        self.current_label.setObjectName("dim")
        self.current_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        layout.addWidget(self.current_label)

        self.activity = QTextEdit()
        self.activity.setReadOnly(True)
        self.activity.setObjectName("activity")
        layout.addWidget(self.activity, stretch=1)

        return box

    # -- interaction ---------------------------------------------------

    @Slot(bool)
    def _on_custom_toggled(self, checked: bool) -> None:
        self.custom_panel.setVisible(checked)

    @Slot(bool)
    def _on_archives_toggled(self, checked: bool) -> None:
        # 2 is the default depth; 0 disables the archive detector entirely.
        self.config.scan.archive_depth = 2 if checked else 0

    def _add_path(self) -> None:
        directory = QFileDialog.getExistingDirectory(self, "Choose a folder to scan")
        if not directory:
            return
        if directory in self._custom_paths:
            return
        self._custom_paths.append(directory)
        self.path_list.addItem(QListWidgetItem(directory))

    def _remove_path(self) -> None:
        for item in self.path_list.selectedItems():
            self._custom_paths.remove(item.text())
            self.path_list.takeItem(self.path_list.row(item))

    def _on_start(self) -> None:
        self.scan_requested.emit(self._roots(), self.check_quarantine.isChecked())

    def default_roots(self) -> list[str]:
        """What a scan started from the tray should look at.

        Whatever the user last chose here, so "Check my computer" in the
        flyout does the same thing as the button they can see.
        """
        return self._roots()

    def _roots(self) -> list[str]:
        if self.radio_custom.isChecked():
            return list(self._custom_paths)
        if self.radio_full.isChecked():
            from sentinel.system.drives import scannable_roots

            return scannable_roots(
                skip_network=self.config.scan.skip_network_drives,
                skip_removable=self.config.scan.skip_removable_drives,
            )
        from sentinel.system import high_value_scan_paths

        return high_value_scan_paths() or [str(Path.home())]

    # -- state ---------------------------------------------------------

    def set_running(self, running: bool) -> None:
        self.start_button.setEnabled(not running)
        self.cancel_button.setEnabled(running)
        self.progress.setVisible(running)
        # Stays visible once a scan has been run: the result of the last one
        # is the thing somebody comes back to the page to read.
        self.progress_section.setVisible(
            running or self.progress_section.isVisible()
        )
        for widget in (
            self.radio_quick, self.radio_full, self.radio_custom,
            self.check_quarantine, self.check_archives,
        ):
            widget.setEnabled(not running)
        self._on_custom_toggled(self.radio_custom.isChecked() and not running)

        if running:
            self._threat_count = 0
            self.activity.clear()
            self.stats_label.setText("Starting…")
            # Back to indeterminate for the counting phase of the next scan.
            self.progress.setRange(0, 0)

    # -- slots ---------------------------------------------------------

    @Slot(dict)
    def on_enumerating(self, payload: dict[str, Any]) -> None:
        """Phase one: counting the tree. No percentage is possible yet.

        The running count and the scrolling path are what tell a worried
        user the app has not frozen — which is the whole job of this phase.
        """
        found = int(payload.get("files_total") or 0)
        self.stats_label.setText(f"Looking through your files — {found:,} so far")
        self.current_label.setText(shorten_path(str(payload.get("current", "")), 90))

    @Slot(dict)
    def on_progress(self, payload: dict[str, Any]) -> None:
        """Phase two: real totals, so a real bar and a real estimate."""
        from sentinel.engine.progress import format_eta

        self.current_label.setText(shorten_path(str(payload.get("current", "")), 90))
        done = int(payload.get("files_scanned") or 0)
        fraction = payload.get("fraction")

        if fraction is None:
            # Enumeration was skipped or cancelled. An indeterminate bar is
            # the honest answer; a made-up percentage is not.
            self.progress.setRange(0, 0)
            self.stats_label.setText(
                f"{done:,} files · {human_bytes(int(payload.get('bytes_scanned') or 0))}"
                f" · {self._threat_count} threat(s)"
            )
            return

        # A permille range rather than 0-100: on a scan of a million files a
        # percentage bar visibly stalls for tens of seconds per step.
        if self.progress.maximum() != 1000:
            self.progress.setRange(0, 1000)
        self.progress.setValue(int(float(fraction) * 1000))

        total = int(payload.get("files_total") or 0)
        self.stats_label.setText(
            f"{done:,} of {total:,} files · "
            f"{format_eta(payload.get('eta_seconds'))} left · "
            f"{self._threat_count} threat(s)"
        )

    @Slot(dict)
    def on_threat(self, payload: dict[str, Any]) -> None:
        self._threat_count += 1
        severity = payload.get("severity", "medium")
        try:
            colour = SEVERITY_COLORS[Severity(severity)]
        except ValueError:
            colour = "red"
        # Qt understands a subset of CSS colour names; map Rich's names.
        colour = {"bright_red": "#ff5555", "cyan": "#22aaaa"}.get(colour, colour)

        self._append(
            f'<span style="color:{colour}"><b>{severity.upper()}</b></span> '
            f'{_escape(payload.get("name", "?"))} — '
            f'<span style="color:#888">{_escape(shorten_path(payload.get("path", ""), 70))}</span>'
        )

    @Slot(str, str)
    def on_file_error(self, path: str, error: str) -> None:
        self._append(
            f'<span style="color:#888">error: {_escape(shorten_path(path, 60))} '
            f'— {_escape(error)}</span>'
        )

    def on_finished(self, result: ScanResult) -> None:
        self.progress.setVisible(False)
        self.current_label.setText("")
        verb = "cancelled" if result.cancelled else "complete"
        self.stats_label.setText(
            f"Scan {verb} — {human_count(result.files_scanned, 'file')} in "
            f"{human_duration(result.duration)}, "
            f"{human_count(result.threat_count, 'threat')}, "
            f"{result.errors} error(s)"
        )
        self._append(f"<b>Scan {verb}.</b>")

    # -- helpers -------------------------------------------------------

    def _append(self, html: str) -> None:
        """Append a line, trimming the buffer when it gets long."""
        document = self.activity.document()
        if document.blockCount() > MAX_LOG_LINES:
            cursor = self.activity.textCursor()
            cursor.movePosition(cursor.MoveOperation.Start)
            for _ in range(MAX_LOG_LINES // 4):
                cursor.select(cursor.SelectionType.BlockUnderCursor)
                cursor.removeSelectedText()
                cursor.deleteChar()
        self.activity.append(html)


def _escape(text: str) -> str:
    """Escape text for insertion into the rich-text activity log."""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )
