"""The quarantine page: list, restore, delete and verify vault entries."""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import Qt, Slot
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from sentinel.core.config import Config
from sentinel.core.logger import get_logger
from sentinel.engine.quarantine import Quarantine, QuarantineEntry, QuarantineError
from sentinel.utils.humanize import human_bytes, human_count, shorten_path

log = get_logger(__name__)

_COLUMNS = ("Threat", "Original location", "Size", "Quarantined", "Severity")


class QuarantineView(QWidget):
    """Vault management."""

    def __init__(self, config: Config, db: Any) -> None:
        super().__init__()
        self.config = config
        self.db = db
        self.vault = Quarantine(config, db)
        self._entries: list[QuarantineEntry] = []
        self._build()
        self.refresh()

    def _build(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(12)

        heading = QLabel("Quarantine")
        heading.setObjectName("heading")
        layout.addWidget(heading)

        self.summary_label = QLabel("")
        self.summary_label.setObjectName("dim")
        layout.addWidget(self.summary_label)

        explanation = QLabel(
            "Quarantined files are stored obfuscated so they cannot be run or "
            "opened by accident. Restoring puts the original back exactly as it "
            "was — including, if the detection was correct, its malicious behaviour."
        )
        explanation.setWordWrap(True)
        explanation.setObjectName("dim")
        layout.addWidget(explanation)

        self.table = QTableWidget(0, len(_COLUMNS))
        self.table.setHorizontalHeaderLabels(_COLUMNS)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSortingEnabled(True)
        self.table.verticalHeader().setVisible(False)
        self.table.itemSelectionChanged.connect(self._on_selection)

        header = self.table.horizontalHeader()
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        for column in (0, 2, 3, 4):
            header.setSectionResizeMode(column, QHeaderView.ResizeMode.ResizeToContents)

        layout.addWidget(self.table, stretch=1)
        layout.addLayout(self._build_actions())

    def _build_actions(self) -> QHBoxLayout:
        row = QHBoxLayout()

        self.restore_button = QPushButton("Restore…")
        self.restore_button.clicked.connect(self._restore)

        self.delete_button = QPushButton("Delete permanently")
        self.delete_button.setObjectName("danger")
        self.delete_button.clicked.connect(self._delete)

        self.verify_button = QPushButton("Verify integrity")
        self.verify_button.clicked.connect(self._verify)

        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.clicked.connect(self.refresh)

        for button in (
            self.restore_button, self.delete_button, self.verify_button
        ):
            button.setEnabled(False)
            row.addWidget(button)
        row.addWidget(self.refresh_button)
        row.addStretch()
        return row

    # -- data ----------------------------------------------------------

    @Slot()
    def refresh(self) -> None:
        self._entries = self.vault.list_entries()

        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)
        for entry in self._entries:
            row = self.table.rowCount()
            self.table.insertRow(row)

            threat_item = QTableWidgetItem(entry.name or "Unknown")
            threat_item.setData(Qt.ItemDataRole.UserRole, entry.token)

            path_item = QTableWidgetItem(shorten_path(entry.original_path, 60))
            path_item.setToolTip(entry.original_path)

            size_item = QTableWidgetItem()
            size_item.setData(Qt.ItemDataRole.DisplayRole, entry.size)
            size_item.setText(human_bytes(entry.size))

            age_item = QTableWidgetItem(f"{entry.age_days:.0f} days ago")
            age_item.setData(Qt.ItemDataRole.UserRole, entry.created_at)

            for column, item in enumerate(
                (threat_item, path_item, size_item, age_item,
                 QTableWidgetItem(entry.severity))
            ):
                self.table.setItem(row, column, item)

        self.table.setSortingEnabled(True)

        total = self.vault.total_size()
        if self._entries:
            self.summary_label.setText(
                f"{human_count(len(self._entries), 'file')} in the vault, "
                f"using {human_bytes(total)}."
            )
        else:
            self.summary_label.setText("The vault is empty.")
        self._on_selection()

    def _selected(self) -> QuarantineEntry | None:
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return None
        item = self.table.item(rows[0].row(), 0)
        if item is None:
            return None
        token = item.data(Qt.ItemDataRole.UserRole)
        return next((e for e in self._entries if e.token == token), None)

    def _on_selection(self) -> None:
        enabled = self._selected() is not None
        for button in (
            self.restore_button, self.delete_button, self.verify_button
        ):
            button.setEnabled(enabled)

    # -- actions -------------------------------------------------------

    def _restore(self) -> None:
        entry = self._selected()
        if entry is None:
            return

        answer = QMessageBox.warning(
            self,
            "Restore quarantined file",
            f"This file was flagged as <b>{entry.name}</b>.<br><br>"
            f"Restoring it puts the original back at:<br>"
            f"<code>{entry.original_path}</code><br><br>"
            f"If the detection was correct, the file will be dangerous again. "
            f"Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return

        destination = None
        if QMessageBox.question(
            self,
            "Where to restore",
            "Restore to the original location?\n\n"
            "Choose No to pick a different folder.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.Yes,
        ) == QMessageBox.StandardButton.No:
            chosen = QFileDialog.getExistingDirectory(self, "Restore to folder")
            if not chosen:
                return
            from pathlib import Path

            destination = str(Path(chosen) / entry.original_name)

        try:
            path = self.vault.restore(entry.token, destination, overwrite=False)
        except QuarantineError as exc:
            QMessageBox.critical(self, "Restore failed", str(exc))
            return

        QMessageBox.information(self, "Restored", f"The file was restored to:\n{path}")
        self.refresh()

    def _delete(self) -> None:
        entry = self._selected()
        if entry is None:
            return

        answer = QMessageBox.warning(
            self,
            "Delete permanently",
            f"Permanently destroy this file?\n\n"
            f"{entry.name}\n{entry.original_path}\n\n"
            f"This cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return

        try:
            self.vault.delete(entry.token)
        except QuarantineError as exc:
            QMessageBox.critical(self, "Delete failed", str(exc))
            return
        self.refresh()

    def _verify(self) -> None:
        entry = self._selected()
        if entry is None:
            return

        if self.vault.verify(entry.token):
            QMessageBox.information(
                self, "Integrity verified",
                "The stored copy matches the hash recorded when it was "
                "quarantined. It can be restored safely.",
            )
        else:
            QMessageBox.warning(
                self, "Integrity check failed",
                "The stored copy does not match its recorded hash. The vault "
                "file may be damaged; restoring it will be refused.",
            )
