"""The settings page.

Privacy settings are grouped first and stated in plain language, because
they are the ones with consequences the user cannot undo.
"""

from __future__ import annotations

from PySide6.QtCore import Slot
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from sentinel.core.config import Config, save_config
from sentinel.core.logger import get_logger
from sentinel.utils.humanize import human_bytes

log = get_logger(__name__)


class SettingsView(QWidget):
    """Edits the configuration and writes it back to disk."""

    def __init__(self, config: Config, tuning_summary: str = "") -> None:
        super().__init__()
        self.config = config
        self._tuning_summary = tuning_summary
        self._build()
        self.refresh()

    def _build(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(24, 24, 24, 24)
        outer.setSpacing(12)

        heading = QLabel("Settings")
        heading.setObjectName("heading")
        outer.addWidget(heading)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setSpacing(16)

        if self._tuning_summary:
            layout.addWidget(self._build_hardware_box())
        layout.addWidget(self._build_privacy_box())
        layout.addWidget(self._build_scan_box())
        layout.addWidget(self._build_detector_box())
        layout.addWidget(self._build_signature_box())
        layout.addStretch()

        scroll.setWidget(container)
        outer.addWidget(scroll, stretch=1)

        buttons = QHBoxLayout()
        self.save_button = QPushButton("Save")
        self.save_button.setObjectName("primary")
        self.save_button.clicked.connect(self._save)
        self.reset_button = QPushButton("Reload from disk")
        self.reset_button.clicked.connect(self.refresh)
        buttons.addWidget(self.save_button)
        buttons.addWidget(self.reset_button)
        buttons.addStretch()
        outer.addLayout(buttons)

    # -- sections ------------------------------------------------------

    def _build_hardware_box(self) -> QGroupBox:
        """What Sentinel measured, and what it chose because of it.

        Shown first, and worded so somebody who knows nothing about scanners
        can still check it against what they know about their own computer.
        Nobody is asked to pick a performance mode — but they are told, which
        is what turns an automatic decision into evidence the software looked
        at their machine rather than guessing.
        """
        box = QGroupBox("Set up for your computer")
        layout = QVBoxLayout(box)

        summary = QLabel(self._tuning_summary)
        summary.setWordWrap(True)
        layout.addWidget(summary)

        note = QLabel(
            "Sentinel chose these when it first ran. You can change anything "
            "below if you would rather."
        )
        note.setObjectName("dim")
        note.setWordWrap(True)
        layout.addWidget(note)
        return box

    def _build_privacy_box(self) -> QGroupBox:
        box = QGroupBox("Privacy")
        layout = QVBoxLayout(box)

        note = QLabel(
            "By default Sentinel Scan makes no network requests at all. "
            "Everything below is off unless you turn it on."
        )
        note.setWordWrap(True)
        note.setObjectName("dim")
        layout.addWidget(note)

        form = QFormLayout()

        self.server_url = QLineEdit()
        self.server_url.setPlaceholderText("https://api.example.com  (leave empty to stay offline)")
        form.addRow("Reporting server", self.server_url)

        self.api_token = QLineEdit()
        self.api_token.setEchoMode(QLineEdit.EchoMode.Password)
        self.api_token.setPlaceholderText("Only needed if your server requires one")
        form.addRow("API token", self.api_token)

        layout.addLayout(form)

        self.telemetry = QCheckBox("Send anonymous detection counters")
        self.telemetry.setToolTip(
            "Counts only — never file names, paths, hashes or contents. "
            "Batches carry no identifier, so they cannot be linked to you."
        )
        layout.addWidget(self.telemetry)

        self.cloud_lookup = QCheckBox("Look up file hashes against the server")
        self.cloud_lookup.setToolTip(
            "Sends SHA-256 hashes during a scan. Never sends file contents."
        )
        layout.addWidget(self.cloud_lookup)

        self.sample_upload = QCheckBox(
            "Allow uploading file contents with a report"
        )
        self.sample_upload.setToolTip(
            "Even with this on, every individual file still requires explicit "
            "confirmation before it is uploaded."
        )
        layout.addWidget(self.sample_upload)

        warning = QLabel(
            "Uploading a sample sends the entire file. Files that look like "
            "keys, password stores or credentials are never uploaded, whatever "
            "this setting says."
        )
        warning.setWordWrap(True)
        warning.setObjectName("warning")
        layout.addWidget(warning)

        return box

    def _build_scan_box(self) -> QGroupBox:
        box = QGroupBox("Scanning")
        form = QFormLayout(box)

        self.threads = QSpinBox()
        self.threads.setRange(0, 64)
        self.threads.setSpecialValueText("Automatic")
        self.threads.setToolTip("0 picks a thread count based on your CPU.")
        form.addRow("Worker threads", self.threads)

        self.max_file_size = QSpinBox()
        self.max_file_size.setRange(1, 8192)
        self.max_file_size.setSuffix(" MB")
        self.max_file_size.setToolTip(
            "Files above this size are hashed but skip the content detectors."
        )
        form.addRow("Max file size", self.max_file_size)

        self.archive_depth = QSpinBox()
        self.archive_depth.setRange(0, 5)
        self.archive_depth.setToolTip("0 disables looking inside archives.")
        form.addRow("Archive depth", self.archive_depth)

        self.threat_threshold = QSpinBox()
        self.threat_threshold.setRange(1, 100)
        self.threat_threshold.setToolTip(
            "Aggregate score at which a file is reported as a threat. "
            "Lower catches more and produces more false positives."
        )
        form.addRow("Threat threshold", self.threat_threshold)

        self.follow_symlinks = QCheckBox("Follow symbolic links")
        form.addRow("", self.follow_symlinks)

        self.skip_network = QCheckBox("Skip network drives")
        form.addRow("", self.skip_network)

        return box

    def _build_detector_box(self) -> QGroupBox:
        box = QGroupBox("Detectors")
        layout = QVBoxLayout(box)

        self.detector_checks: dict[str, QCheckBox] = {}
        for name, label in (
            ("hash", "Hash database — exact matches against known samples"),
            ("yara", "YARA — pattern rules"),
            ("pe_heuristic", "PE heuristics — Windows executable structure"),
            ("script", "Script heuristics — obfuscated scripts and droppers"),
            ("archive", "Archives — look inside zip, tar and gzip"),
            ("clamav", "ClamAV — requires a running clamd daemon"),
            ("cloud", "Cloud lookup — requires a server and consent above"),
        ):
            check = QCheckBox(label)
            self.detector_checks[name] = check
            layout.addWidget(check)

        self.log_level = QComboBox()
        self.log_level.addItems(["DEBUG", "INFO", "WARNING", "ERROR"])
        row = QFormLayout()
        row.addRow("Log level", self.log_level)
        layout.addLayout(row)

        return box

    def _build_signature_box(self) -> QGroupBox:
        box = QGroupBox("Signatures")
        layout = QVBoxLayout(box)

        self.signature_label = QLabel("")
        self.signature_label.setWordWrap(True)
        layout.addWidget(self.signature_label)

        self.auto_update = QCheckBox("Check for signature updates automatically")
        layout.addWidget(self.auto_update)

        return box

    # -- load / save ---------------------------------------------------

    @Slot()
    def refresh(self) -> None:
        """Populate every widget from the current config."""
        privacy = self.config.privacy
        self.server_url.setText(privacy.server_url)
        self.api_token.setText(privacy.api_token)
        self.telemetry.setChecked(privacy.telemetry)
        self.cloud_lookup.setChecked(privacy.allow_cloud_lookup)
        self.sample_upload.setChecked(privacy.allow_sample_upload)

        scan = self.config.scan
        self.threads.setValue(scan.threads)
        self.max_file_size.setValue(max(1, scan.max_file_size // (1024 * 1024)))
        self.archive_depth.setValue(scan.archive_depth)
        self.threat_threshold.setValue(scan.threat_threshold)
        self.follow_symlinks.setChecked(scan.follow_symlinks)
        self.skip_network.setChecked(scan.skip_network_drives)

        detectors = self.config.detectors
        for name, check in self.detector_checks.items():
            check.setChecked(bool(getattr(detectors, name, False)))

        self.log_level.setCurrentText(self.config.log_level.upper())
        self.auto_update.setChecked(self.config.updates.auto_update)

        self._refresh_signature_label()

    def _refresh_signature_label(self) -> None:
        from sentinel.signatures.loader import SignatureStore

        summary = SignatureStore(self.config).summary()
        self.signature_label.setText(
            f"Version {summary['version']} (updated {summary['updated']})\n"
            f"{summary['hash_count']:,} hash signatures · "
            f"{summary['yara_files']} YARA rule file(s) · "
            f"{summary['clamav_bundles']} ClamAV bundle(s)"
        )

    def _save(self) -> None:
        """Write the widgets back to the config and persist it."""
        privacy = self.config.privacy
        privacy.server_url = self.server_url.text().strip()
        privacy.api_token = self.api_token.text().strip()
        privacy.telemetry = self.telemetry.isChecked()
        privacy.allow_cloud_lookup = self.cloud_lookup.isChecked()
        privacy.allow_sample_upload = self.sample_upload.isChecked()

        scan = self.config.scan
        scan.threads = self.threads.value()
        scan.max_file_size = self.max_file_size.value() * 1024 * 1024
        scan.archive_depth = self.archive_depth.value()
        scan.threat_threshold = self.threat_threshold.value()
        # Keep the suspicious threshold below the threat one, or validation
        # rejects the whole config.
        scan.suspicious_threshold = min(scan.suspicious_threshold, scan.threat_threshold)
        scan.follow_symlinks = self.follow_symlinks.isChecked()
        scan.skip_network_drives = self.skip_network.isChecked()

        for name, check in self.detector_checks.items():
            setattr(self.config.detectors, name, check.isChecked())

        self.config.log_level = self.log_level.currentText()
        self.config.updates.auto_update = self.auto_update.isChecked()

        from sentinel.core.config import ConfigError

        try:
            self.config.validate()
        except ConfigError as exc:
            QMessageBox.warning(self, "Invalid settings", str(exc))
            return

        try:
            path = save_config(self.config)
        except OSError as exc:
            QMessageBox.critical(self, "Could not save", str(exc))
            return

        from sentinel.core.logger import set_level

        set_level(self.config.log_level)

        QMessageBox.information(
            self, "Settings saved",
            f"Written to:\n{path}\n\n"
            f"Detector changes take effect on the next scan.",
        )

    def _describe_size(self) -> str:
        return human_bytes(self.config.scan.max_file_size)
