"""Dialog for reporting a false positive.

The design rule here: the user sees the exact payload before anything is
sent, and sample upload requires a separate, deliberate action. There is no
"remember my choice" for uploads.
"""

from __future__ import annotations

from typing import Any

from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QTabWidget,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from sentinel.core.config import Config
from sentinel.core.logger import get_logger
from sentinel.engine.verdict import Verdict

log = get_logger(__name__)

MIN_COMMENT_LENGTH = 10


class FeedbackDialog(QDialog):
    """Collects an explanation and submits a false-positive report."""

    def __init__(
        self, config: Config, verdict: Verdict, parent: QWidget | None = None
    ) -> None:
        super().__init__(parent)
        self.config = config
        self.verdict = verdict
        self._report: Any = None

        self.setWindowTitle("Report a false positive")
        self.setMinimumSize(640, 560)
        self._build()
        self._refresh_preview()

    def _build(self) -> None:
        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        header = QLabel(
            f"<b>{_escape(self.verdict.name or 'Finding')}</b><br>"
            f'<span style="color:#888;font-family:monospace;font-size:11px">'
            f"{_escape(self.verdict.path)}</span>"
        )
        header.setWordWrap(True)
        layout.addWidget(header)

        explanation = QLabel(
            "Reporting a false positive helps fix the rule for everyone. "
            "Nothing is sent until you press Submit, and the exact payload is "
            "shown in the Preview tab."
        )
        explanation.setWordWrap(True)
        explanation.setObjectName("dim")
        layout.addWidget(explanation)

        tabs = QTabWidget()
        tabs.addTab(self._build_form_tab(), "Report")
        tabs.addTab(self._build_preview_tab(), "Preview")
        layout.addWidget(tabs, stretch=1)

        self.buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        self.buttons.button(QDialogButtonBox.StandardButton.Ok).setText("Submit")
        self.buttons.accepted.connect(self._submit)
        self.buttons.rejected.connect(self.reject)
        layout.addWidget(self.buttons)

        self._validate()

    def _build_form_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)

        layout.addWidget(QLabel("What is this file, and why do you believe it is safe?"))
        self.comment = QPlainTextEdit()
        self.comment.setPlaceholderText(
            "For example: this is my own build output from a Rust project; the "
            "packed-section warning is just the release binary."
        )
        self.comment.textChanged.connect(self._on_changed)
        layout.addWidget(self.comment, stretch=1)

        layout.addWidget(QLabel("Where did the file come from? (optional)"))
        self.origin = QLineEdit()
        self.origin.setPlaceholderText("Built locally / vendor website / app store…")
        self.origin.textChanged.connect(self._on_changed)
        layout.addWidget(self.origin)

        self.include_sample = QCheckBox("Also upload the file itself")
        self.include_sample.setToolTip(
            "Sends the complete file contents. Only do this if the file "
            "contains nothing private."
        )
        self.include_sample.toggled.connect(self._on_sample_toggled)
        layout.addWidget(self.include_sample)

        self.sample_note = QLabel("")
        self.sample_note.setWordWrap(True)
        self.sample_note.setObjectName("warning")
        layout.addWidget(self.sample_note)

        privacy = getattr(self.config, "privacy", None)
        if not getattr(privacy, "allow_sample_upload", False):
            self.include_sample.setEnabled(False)
            self.include_sample.setToolTip(
                "Enable 'Allow uploading file contents' in Settings first."
            )

        return page

    def _build_preview_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)

        label = QLabel("This is exactly what will be sent:")
        layout.addWidget(label)

        self.preview = QTextBrowser()
        self.preview.setObjectName("detail")
        self.preview.setLineWrapMode(QTextBrowser.LineWrapMode.NoWrap)
        layout.addWidget(self.preview, stretch=1)

        note = QLabel(
            "Note that the full path is not included — only the file name, its "
            "size and its hashes."
        )
        note.setWordWrap(True)
        note.setObjectName("dim")
        layout.addWidget(note)

        return page

    # -- state ---------------------------------------------------------

    def _on_changed(self) -> None:
        self._validate()
        self._refresh_preview()

    def _on_sample_toggled(self, checked: bool) -> None:
        if not checked:
            self.sample_note.setText("")
            self._refresh_preview()
            return

        from sentinel.feedback.sample_upload import check_sample

        result = check_sample(self.verdict.path, self.config)
        if not result.allowed:
            self.sample_note.setText(f"This file cannot be uploaded: {result.reason}")
            self.include_sample.setChecked(False)
            return

        if result.needs_extra_confirmation:
            answer = QMessageBox.warning(
                self,
                "Confirm upload",
                result.reason,
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if answer != QMessageBox.StandardButton.Yes:
                self.include_sample.setChecked(False)
                return

        self.sample_note.setText(
            "The complete contents of this file will be uploaded with the report."
        )
        self._refresh_preview()

    def _validate(self) -> None:
        ok = len(self.comment.toPlainText().strip()) >= MIN_COMMENT_LENGTH
        self.buttons.button(QDialogButtonBox.StandardButton.Ok).setEnabled(ok)

    def _build_report(self) -> Any:
        from sentinel.feedback.report import build_false_positive

        return build_false_positive(
            self.verdict,
            self.comment.toPlainText().strip(),
            self.origin.text().strip(),
            self.include_sample.isChecked(),
        )

    def _refresh_preview(self) -> None:
        try:
            report = self._build_report()
        except Exception as exc:  # pragma: no cover - defensive
            self.preview.setPlainText(f"Could not build a preview: {exc}")
            return
        self.preview.setPlainText(report.to_json())

    # -- submission ----------------------------------------------------

    def _submit(self) -> None:
        report = self._build_report()

        problems = report.validate()
        if problems:
            QMessageBox.warning(self, "Not ready", "\n".join(problems))
            return

        from sentinel.feedback.report import submit

        try:
            outcome = submit(
                report,
                self.config,
                self.verdict.path if self.include_sample.isChecked() else None,
            )
        except Exception as exc:
            log.exception("report submission failed")
            QMessageBox.critical(self, "Could not submit", str(exc))
            return

        if outcome.get("method") == "server":
            QMessageBox.information(
                self, "Report submitted",
                f"Thank you. Report id: {outcome.get('report_id', '—')}",
            )
        else:
            url = outcome.get("url", "")
            answer = QMessageBox.question(
                self,
                "Open GitHub issue",
                "No reporting server is configured, so this has been turned "
                "into a pre-filled GitHub issue.\n\n"
                "Open it in your browser? You can review and edit it before "
                "submitting.",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.Yes,
            )
            if answer == QMessageBox.StandardButton.Yes and url:
                from sentinel.feedback.github_fallback import open_in_browser

                if not open_in_browser(url):
                    QMessageBox.information(
                        self, "Copy this link",
                        "A browser could not be opened. The issue URL is:\n\n" + url,
                    )

        self.accept()


def _escape(text: str) -> str:
    return (
        str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    )
