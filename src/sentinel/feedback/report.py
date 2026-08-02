"""Building and submitting detection-quality reports.

Two kinds:

**False positive** — the scanner flagged something the user believes is
clean. These are the reports that matter most: every false positive erodes
trust, and a scanner nobody trusts gets uninstalled.

**Missed detection** — the user believes a file is malicious and the scanner
said nothing.

A report is assembled locally, shown to the user in full, and only then sent.
Nothing is submitted silently. When no server is configured the report is
turned into a pre-filled GitHub issue instead (see
:mod:`sentinel.feedback.github_fallback`).
"""

from __future__ import annotations

import json
import platform
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from sentinel.core.logger import get_logger
from sentinel.engine.verdict import Verdict
from sentinel.utils.hashing import hash_file_multi
from sentinel.version import REPORT_FORMAT_VERSION, __version__

log = get_logger(__name__)


class ReportKind(str, Enum):
    FALSE_POSITIVE = "false_positive"
    MISSED_DETECTION = "missed_detection"
    BUG = "bug"


@dataclass(slots=True)
class FileFacts:
    """Non-identifying facts about the file being reported.

    Deliberately excludes the full path: it contains the username, and often
    a project or client name. Only the basename and extension go in, and
    even the basename is included because it is frequently the whole point
    of a false-positive report ("your scanner flags my build output").
    """

    name: str
    extension: str
    size: int
    sha256: str
    md5: str = ""
    sha1: str = ""
    file_type: str = ""

    @classmethod
    def from_path(cls, path: str | Path) -> FileFacts:
        p = Path(path)
        digests: dict[str, str] = {}
        size = 0
        try:
            size = p.stat().st_size
            digests = hash_file_multi(p)
        except OSError as exc:
            log.warning("cannot read %s for the report: %s", p, exc)

        file_type = ""
        try:
            from sentinel.utils.file_types import guess_type

            file_type = guess_type(p).file_type.value
        except Exception:
            pass

        return cls(
            name=p.name,
            extension=p.suffix.lower(),
            size=size,
            sha256=digests.get("sha256", ""),
            md5=digests.get("md5", ""),
            sha1=digests.get("sha1", ""),
            file_type=file_type,
        )


@dataclass(slots=True)
class Report:
    """A complete, reviewable report."""

    kind: ReportKind
    file: FileFacts
    #: The user's own explanation. Required — an unexplained report is noise.
    comment: str = ""
    #: Detections the scanner produced, for a false positive.
    detections: list[dict[str, Any]] = field(default_factory=list)
    #: Where the user says the file came from, if they said.
    origin: str = ""
    #: Whether the user consented to attaching the file itself.
    sample_consented: bool = False
    environment: dict[str, str] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    format_version: int = REPORT_FORMAT_VERSION

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["kind"] = self.kind.value
        return data

    def to_json(self, indent: int = 2) -> str:
        """The exact bytes that would be sent — show this to the user."""
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    def summary(self) -> str:
        label = {
            ReportKind.FALSE_POSITIVE: "False positive",
            ReportKind.MISSED_DETECTION: "Missed detection",
            ReportKind.BUG: "Bug",
        }[self.kind]
        return f"{label}: {self.file.name} ({self.file.sha256[:16]}…)"

    def validate(self) -> list[str]:
        """Return a list of problems; empty means ready to submit."""
        problems: list[str] = []
        if not self.file.sha256:
            problems.append("the file could not be hashed, so it cannot be identified")
        if len(self.comment.strip()) < 10:
            problems.append(
                "please describe what you expected — a report without an "
                "explanation cannot be acted on"
            )
        if self.kind is ReportKind.FALSE_POSITIVE and not self.detections:
            problems.append("a false-positive report needs the detections it disputes")
        return problems


def environment_facts() -> dict[str, str]:
    """Non-identifying environment details that help reproduce an issue.

    No hostname, no username, no local IP addresses, no serial numbers.
    """
    return {
        "sentinel_version": __version__,
        "python_version": platform.python_version(),
        "os": platform.system(),
        "os_release": platform.release(),
        "machine": platform.machine(),
    }


def build_false_positive(
    verdict: Verdict, comment: str, origin: str = "", sample_consented: bool = False
) -> Report:
    """Build a false-positive report from a scan verdict."""
    return Report(
        kind=ReportKind.FALSE_POSITIVE,
        file=FileFacts.from_path(verdict.path),
        comment=comment,
        detections=[d.to_dict() for d in verdict.detections],
        origin=origin,
        sample_consented=sample_consented,
        environment=environment_facts(),
    )


def build_missed_detection(
    path: str | Path, comment: str, origin: str = "", sample_consented: bool = False
) -> Report:
    """Build a missed-detection report for a file the scanner called clean."""
    return Report(
        kind=ReportKind.MISSED_DETECTION,
        file=FileFacts.from_path(path),
        comment=comment,
        origin=origin,
        sample_consented=sample_consented,
        environment=environment_facts(),
    )


def submit(
    report: Report,
    config: Any,
    sample_path: str | Path | None = None,
) -> dict[str, Any]:
    """Send *report* to the configured server, or fall back to GitHub.

    Args:
        report: A validated report.
        config: The application config.
        sample_path: File to attach. Only used when
            ``report.sample_consented`` is True **and** the config permits
            sample upload — both, not either.

    Returns:
        A dict with ``method`` ("server" or "github"), plus ``report_id`` and
        ``url`` where applicable.

    Raises:
        ValueError: the report failed :meth:`Report.validate`.
    """
    problems = report.validate()
    if problems:
        raise ValueError("; ".join(problems))

    privacy = getattr(config, "privacy", None)
    server_url = str(getattr(privacy, "server_url", "") or "")

    if not server_url:
        from sentinel.feedback.github_fallback import build_issue_url

        url = build_issue_url(report, config)
        log.info("no server configured; prepared a GitHub issue instead")
        return {"method": "github", "url": url, "report_id": ""}

    from sentinel.feedback.client import ServerClient, ServerError

    with ServerClient(privacy) as client:
        try:
            result = client.submit_report(report.to_dict())
        except ServerError as exc:
            log.error("could not submit report: %s", exc)
            from sentinel.feedback.github_fallback import build_issue_url

            return {
                "method": "github",
                "url": build_issue_url(report, config),
                "report_id": "",
                "error": str(exc),
            }

        outcome: dict[str, Any] = {
            "method": "server",
            "report_id": result.report_id,
            "url": result.url,
            "accepted": result.accepted,
            "message": result.message,
        }

        if sample_path and report.sample_consented and result.report_id:
            from sentinel.feedback.sample_upload import upload_sample

            outcome["sample"] = upload_sample(
                client, result.report_id, sample_path, config
            )

        return outcome


def save_local(report: Report, config: Any) -> Path:
    """Write a report to disk so the user can send it another way."""
    directory = Path(config.paths.data_dir) / "reports"
    directory.mkdir(parents=True, exist_ok=True)
    name = f"{int(report.created_at)}-{report.kind.value}-{report.file.sha256[:12]}.json"
    path = directory / name
    path.write_text(report.to_json(), encoding="utf-8")
    log.info("report saved to %s", path)
    return path
