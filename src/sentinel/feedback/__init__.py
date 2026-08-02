"""Optional reporting: detection feedback, sample upload, telemetry.

Everything in this package is off by default. A default install performs no
network I/O at all — see docs/privacy.md for the complete statement.
"""

from sentinel.feedback.client import ServerClient, ServerError, SubmissionResult
from sentinel.feedback.github_fallback import build_issue_body, build_issue_url
from sentinel.feedback.report import (
    FileFacts,
    Report,
    ReportKind,
    build_false_positive,
    build_missed_detection,
    save_local,
    submit,
)
from sentinel.feedback.sample_upload import SampleCheck, check_sample, upload_sample
from sentinel.feedback.telemetry import TelemetryBatch, TelemetryCollector

__all__ = [
    "FileFacts",
    "Report",
    "ReportKind",
    "SampleCheck",
    "ServerClient",
    "ServerError",
    "SubmissionResult",
    "TelemetryBatch",
    "TelemetryCollector",
    "build_false_positive",
    "build_issue_body",
    "build_issue_url",
    "build_missed_detection",
    "check_sample",
    "save_local",
    "submit",
    "upload_sample",
]
