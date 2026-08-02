"""The results page: a table of findings with a detail pane."""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import Qt, Signal, Slot
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from sentinel.core.config import Config
from sentinel.core.logger import get_logger
from sentinel.engine.verdict import ScanResult, Severity, Verdict
from sentinel.utils.humanize import human_bytes, shorten_path

log = get_logger(__name__)

#: Table colours per severity, tuned for the dark stylesheet.
_SEVERITY_QCOLOR = {
    Severity.CRITICAL: QColor("#ff5555"),
    Severity.HIGH: QColor("#ff8844"),
    Severity.MEDIUM: QColor("#ddbb44"),
    Severity.LOW: QColor("#44aacc"),
    Severity.CLEAN: QColor("#66bb66"),
}

_COLUMNS = ("Severity", "Score", "Threat", "File", "Size", "Action")


class ResultsView(QWidget):
    """Findings table plus an explanation pane for the selected row."""

    rescan_requested = Signal(list, bool)

    def __init__(self, config: Config, db: Any) -> None:
        super().__init__()
        self.config = config
        self.db = db
        self._verdicts: list[Verdict] = []
        self._result: ScanResult | None = None
        self._build()

    def _build(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(12)

        heading = QLabel("Results")
        heading.setObjectName("heading")
        layout.addWidget(heading)

        self.summary_label = QLabel("No scan has been run yet.")
        self.summary_label.setObjectName("dim")
        layout.addWidget(self.summary_label)

        splitter = QSplitter(Qt.Orientation.Vertical)

        self.table = QTableWidget(0, len(_COLUMNS))
        self.table.setHorizontalHeaderLabels(_COLUMNS)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSortingEnabled(True)
        self.table.verticalHeader().setVisible(False)

        header = self.table.horizontalHeader()
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        for column in (0, 1, 2, 4, 5):
            header.setSectionResizeMode(column, QHeaderView.ResizeMode.ResizeToContents)

        self.table.itemSelectionChanged.connect(self._on_selection)
        splitter.addWidget(self.table)

        self.detail = QTextBrowser()
        self.detail.setObjectName("detail")
        self.detail.setOpenExternalLinks(False)
        splitter.addWidget(self.detail)
        splitter.setSizes([420, 260])

        layout.addWidget(splitter, stretch=1)
        layout.addLayout(self._build_actions())

    def _build_actions(self) -> QHBoxLayout:
        row = QHBoxLayout()

        self.quarantine_button = QPushButton("Quarantine selected")
        self.quarantine_button.setEnabled(False)
        self.quarantine_button.clicked.connect(self._quarantine_selected)

        self.whitelist_button = QPushButton("Mark as safe")
        self.whitelist_button.setToolTip(
            "Add this file's SHA-256 to the whitelist so it is not flagged again."
        )
        self.whitelist_button.setEnabled(False)
        self.whitelist_button.clicked.connect(self._whitelist_selected)

        self.report_button = QPushButton("Report false positive…")
        self.report_button.setEnabled(False)
        self.report_button.clicked.connect(self._report_selected)

        row.addWidget(self.quarantine_button)
        row.addWidget(self.whitelist_button)
        row.addWidget(self.report_button)
        row.addStretch()
        return row

    # -- population ----------------------------------------------------

    def clear(self) -> None:
        self.table.setRowCount(0)
        self._verdicts.clear()
        self._result = None
        self.detail.clear()
        self.summary_label.setText("Scanning…")
        self._set_actions_enabled(False)

    @Slot(dict)
    def add_finding(self, payload: dict[str, Any]) -> None:
        """Add a finding streamed from a running scan.

        The payload comes from a THREAT_FOUND event and carries only summary
        fields; the full verdict arrives with :meth:`load_result`.
        """
        try:
            severity = Severity(payload.get("severity", "medium"))
        except ValueError:
            severity = Severity.MEDIUM

        self._append_row(
            severity=severity,
            score=float(payload.get("score", 0)),
            name=str(payload.get("name", "")),
            path=str(payload.get("path", "")),
            size=0,
            action="none",
        )

    def load_result(self, result: ScanResult) -> None:
        """Replace the table with the completed scan's verdicts."""
        self._result = result
        self._verdicts = sorted(
            result.threats + result.suspicious, key=lambda v: -v.score
        )

        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)
        for verdict in self._verdicts:
            self._append_row(
                severity=verdict.severity,
                score=verdict.score,
                name=verdict.name,
                path=verdict.path,
                size=verdict.size,
                action=verdict.action,
            )
        self.table.setSortingEnabled(True)

        if result.threat_count or result.suspicious_count:
            self.summary_label.setText(
                f"{result.threat_count} threat(s) and {result.suspicious_count} "
                f"suspicious file(s) out of {result.files_scanned:,} scanned."
            )
        else:
            self.summary_label.setText(
                f"No threats found in {result.files_scanned:,} files."
            )

        if self._verdicts:
            self.table.selectRow(0)

    def _append_row(
        self, severity: Severity, score: float, name: str, path: str,
        size: int, action: str,
    ) -> None:
        row = self.table.rowCount()
        self.table.insertRow(row)

        severity_item = QTableWidgetItem(severity.value)
        severity_item.setForeground(_SEVERITY_QCOLOR.get(severity, QColor("#cccccc")))

        # Numeric sorting needs the value, not the string.
        score_item = QTableWidgetItem()
        score_item.setData(Qt.ItemDataRole.DisplayRole, round(score))

        size_item = QTableWidgetItem()
        size_item.setData(Qt.ItemDataRole.DisplayRole, size)
        size_item.setText(human_bytes(size) if size else "—")

        path_item = QTableWidgetItem(shorten_path(path, 70))
        path_item.setToolTip(path)
        # Stash the full path so the detail pane can find the verdict again.
        path_item.setData(Qt.ItemDataRole.UserRole, path)

        for column, item in enumerate(
            (
                severity_item,
                score_item,
                QTableWidgetItem(name or "—"),
                path_item,
                size_item,
                QTableWidgetItem(action),
            )
        ):
            self.table.setItem(row, column, item)

    # -- selection -----------------------------------------------------

    def _selected_verdict(self) -> Verdict | None:
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return None
        item = self.table.item(rows[0].row(), 3)
        if item is None:
            return None
        path = item.data(Qt.ItemDataRole.UserRole)
        return next((v for v in self._verdicts if v.path == path), None)

    def _on_selection(self) -> None:
        verdict = self._selected_verdict()
        self._set_actions_enabled(verdict is not None)
        self.detail.setHtml(_detail_html(verdict) if verdict else "")

    def _set_actions_enabled(self, enabled: bool) -> None:
        for button in (
            self.quarantine_button, self.whitelist_button, self.report_button
        ):
            button.setEnabled(enabled)

    # -- actions -------------------------------------------------------

    def _quarantine_selected(self) -> None:
        verdict = self._selected_verdict()
        if verdict is None:
            return

        answer = QMessageBox.question(
            self,
            "Quarantine file",
            f"Move this file into the encrypted vault?\n\n{verdict.path}\n\n"
            f"You can restore it later from the Quarantine page.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return

        from sentinel.engine.quarantine import Quarantine, QuarantineError

        try:
            Quarantine(self.config, self.db).quarantine(verdict)
        except QuarantineError as exc:
            QMessageBox.critical(self, "Quarantine failed", str(exc))
            return

        verdict.action = "quarantined"
        rows = self.table.selectionModel().selectedRows()
        if rows:
            self.table.setItem(rows[0].row(), 5, QTableWidgetItem("quarantined"))
        self._on_selection()

    def _whitelist_selected(self) -> None:
        verdict = self._selected_verdict()
        if verdict is None or not verdict.sha256:
            QMessageBox.warning(
                self, "Cannot whitelist",
                "This file has no recorded hash, so it cannot be whitelisted safely.",
            )
            return

        answer = QMessageBox.question(
            self,
            "Mark as safe",
            f"Add this file's SHA-256 to the whitelist?\n\n"
            f"{verdict.sha256}\n\n"
            f"It will no longer be flagged, wherever it is on disk. Only do "
            f"this if you are confident the file is genuinely safe.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return

        from sentinel.engine.whitelist import Whitelist, WhitelistError

        try:
            Whitelist(self.db).add(verdict.sha256, "sha256", note="marked safe in the GUI")
        except WhitelistError as exc:
            QMessageBox.critical(self, "Whitelist failed", str(exc))
            return

        QMessageBox.information(
            self, "Marked as safe", "This file will not be flagged again."
        )

    def _report_selected(self) -> None:
        verdict = self._selected_verdict()
        if verdict is None:
            return

        from sentinel.ui.windows.feedback_dialog import FeedbackDialog

        dialog = FeedbackDialog(self.config, verdict, parent=self)
        dialog.exec()


def _detail_html(verdict: Verdict) -> str:
    """Render the explanation pane for one finding."""
    colour = _SEVERITY_QCOLOR.get(verdict.severity, QColor("#cccccc")).name()

    parts = [
        f'<h3 style="margin-bottom:2px">{_escape(verdict.name or "Finding")}</h3>',
        f'<p style="color:{colour};margin-top:0">'
        f'<b>{verdict.severity.value.upper()}</b> — score {verdict.score:.0f}/100</p>',
        f'<p style="color:#999;font-family:monospace;font-size:11px">'
        f'{_escape(verdict.path)}</p>',
    ]
    if verdict.sha256:
        parts.append(
            f'<p style="color:#777;font-family:monospace;font-size:11px">'
            f'sha256 {verdict.sha256}<br>{human_bytes(verdict.size)}</p>'
        )

    parts.append("<hr><h4>Why this was flagged</h4>")
    if not verdict.detections:
        parts.append("<p>No detections recorded.</p>")
    else:
        parts.append("<ul>")
        for detection in verdict.detections:
            marker = " <b>(conclusive)</b>" if detection.conclusive else ""
            parts.append(
                f"<li><b>{_escape(detection.name)}</b> "
                f'<span style="color:#888">[{_escape(detection.detector)}, '
                f"{detection.confidence:.0f}%]{marker}</span>"
            )
            if detection.description:
                parts.append(
                    f'<br><span style="color:#aaa">'
                    f"{_escape(detection.description)}</span>"
                )
            parts.append("</li>")
        parts.append("</ul>")

    parts.append(
        '<p style="color:#777;font-size:11px">Heuristic findings are '
        "probabilistic. If you believe this file is safe, use "
        "<i>Report false positive</i> — it helps fix the rule for everyone.</p>"
    )
    return "".join(parts)


def _escape(text: str) -> str:
    return (
        str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    )
