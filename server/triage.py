"""Automatic triage of incoming reports.

Maintainer attention is the scarce resource, so every report gets a priority
score (0-100) and a short list of notes explaining it. The goal is to float
the reports that will improve detection quality the most.

The weighting reflects a deliberate stance: **false positives outrank missed
detections.** A missed sample is one file a scanner did not catch. A false
positive on a popular application is thousands of users seeing their own
software condemned, and it is the fastest way to lose their trust in every
other verdict the tool produces.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from server.models import Report, ReportKind

#: Detector names whose findings are heuristic rather than definitive. A
#: false positive from one of these is expected occasionally and is tuneable;
#: a false positive from a hash match means the signature database is wrong,
#: which is far more serious.
HEURISTIC_DETECTORS = frozenset(
    {"pe_heuristic", "script", "archive", "yara"}
)
DEFINITIVE_DETECTORS = frozenset({"hash", "clamav"})

#: Paths and names suggesting widely-installed software. A false positive
#: here affects many users at once.
COMMON_SOFTWARE_MARKERS = (
    "setup", "install", "update", "launcher", "runtime", "redist",
    "python", "node", "java", "dotnet", "electron", "chrome", "firefox",
    "steam", "discord", "zoom", "teams", "slack", "vscode",
)

#: File types where a false positive is especially disruptive because the
#: file is something the user made.
USER_CONTENT_TYPES = frozenset({"pdf", "ole", "zip", "text", "image"})


@dataclass
class TriageResult:
    """Priority and the reasoning behind it."""

    priority: int = 0
    notes: list[str] = field(default_factory=list)
    #: Suggested status, when triage is confident enough to set one.
    suggested_status: str | None = None

    def add(self, points: int, note: str) -> None:
        self.priority = max(0, min(self.priority + points, 100))
        self.notes.append(note)


def triage(report: Report | Any, duplicate_count: int = 0) -> TriageResult:
    """Score a report.

    Args:
        report: The stored report, or anything with the same attributes.
        duplicate_count: How many earlier reports share this sha256. Repeat
            reports of the same file are strong evidence the detection is
            genuinely wrong.
    """
    result = TriageResult()

    if report.kind == ReportKind.FALSE_POSITIVE:
        result.add(40, "False positive: affects user trust directly")
        _score_false_positive(report, result)
    elif report.kind == ReportKind.MISSED_DETECTION:
        result.add(25, "Missed detection: a gap in coverage")
        _score_missed(report, result)
    else:
        result.add(15, "Bug report")

    if duplicate_count > 0:
        points = min(5 * duplicate_count, 30)
        result.add(
            points,
            f"{duplicate_count} earlier report(s) for the same file — "
            f"repeat reports mean this is not a one-off",
        )
        if duplicate_count >= 3 and report.kind == ReportKind.FALSE_POSITIVE:
            result.suggested_status = "confirmed"
            result.notes.append(
                "Auto-flagged for confirmation: reported repeatedly by "
                "different submitters"
            )

    if report.has_sample:
        result.add(10, "A sample was provided, so this is reproducible")
    elif report.kind == ReportKind.MISSED_DETECTION:
        result.add(
            -10, "No sample provided; a missed detection is hard to act on without one"
        )

    comment = (report.comment or "").strip()
    if len(comment) > 200:
        result.add(5, "Detailed explanation provided")
    elif len(comment) < 30:
        result.add(-5, "Very short explanation")

    return result


def _score_false_positive(report: Report | Any, result: TriageResult) -> None:
    """Weight a false positive by how much damage the detection does."""
    detectors = {
        str(d.get("detector", "")).split(":")[0]
        for d in (report.detections or [])
    }

    if detectors & DEFINITIVE_DETECTORS:
        result.add(
            30,
            "Flagged by a signature match, not a heuristic. A wrong signature "
            "is a data error affecting every user, and can be fixed immediately.",
        )
    elif detectors & HEURISTIC_DETECTORS:
        result.add(
            10, f"Flagged by heuristics ({', '.join(sorted(detectors & HEURISTIC_DETECTORS))})"
        )

    # A conclusive detection that turns out to be wrong is the worst case:
    # the client short-circuits the rest of the pipeline on it.
    if any(d.get("conclusive") for d in (report.detections or [])):
        result.add(
            15,
            "The detection was marked conclusive, which stops all other "
            "detectors from running — a wrong conclusive verdict cannot be "
            "outvoted",
        )

    name = (report.file_name or "").lower()
    if any(marker in name for marker in COMMON_SOFTWARE_MARKERS):
        result.add(
            15,
            f"Filename suggests widely-installed software ('{report.file_name}'), "
            f"so this likely affects many users",
        )

    if (report.file_type or "") in USER_CONTENT_TYPES:
        result.add(
            10,
            f"The file is a {report.file_type}, likely the user's own content "
            f"rather than a program",
        )

    high_confidence = [
        d for d in (report.detections or [])
        if _confidence(d) >= 80
    ]
    if high_confidence:
        result.add(
            10,
            f"{len(high_confidence)} detection(s) fired at 80%+ confidence, so "
            f"the rule is badly calibrated rather than marginally off",
        )


def _score_missed(report: Report | Any, result: TriageResult) -> None:
    """Weight a missed detection by how learnable it is."""
    if report.file_size and report.file_size > 64 * 1024 * 1024:
        result.add(
            -5, "Large file; may have exceeded the client's content-scan limit"
        )

    file_type = report.file_type or ""
    if file_type in {"pe", "elf", "macho", "script"}:
        result.add(10, f"Executable content ({file_type}) — squarely in scope")
    elif file_type in {"zip", "rar", "7z"}:
        result.add(5, "Archive — check whether extraction limits were hit")

    origin = (report.origin or "").lower()
    if any(marker in origin for marker in ("email", "attachment", "phish", "download")):
        result.add(10, f"Reported delivery vector: {report.origin}")


def _confidence(detection: dict[str, Any]) -> float:
    try:
        return float(detection.get("confidence", 0))
    except (TypeError, ValueError):
        return 0.0


def priority_label(priority: int) -> str:
    """Human-readable band for a priority score."""
    if priority >= 80:
        return "urgent"
    if priority >= 60:
        return "high"
    if priority >= 35:
        return "normal"
    return "low"
