"""Detections, severities, and how several weak signals become one verdict.

Scoring model
-------------
Each detector returns zero or more :class:`Detection` objects carrying a
*confidence* in 0-100. The aggregator combines them with a noisy-OR:

    combined = 1 - Π (1 - confidence_i)

That has the properties we want. Two independent 50% signals give 75, not
100 — suspicious, but not enough to act on alone. Five weak 20% signals give
67, which is the "lots of small smells" case that catches obfuscated
droppers. And no amount of weak evidence ever reaches certainty.

A detector that is genuinely certain — an exact hash match against a known
sample, a ClamAV signature hit — sets ``conclusive=True`` and short-circuits
the whole calculation to 100.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """How bad a finding is. Ordered; use :meth:`rank` to compare."""

    CLEAN = "clean"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_ORDER[self]

    # All four comparisons must be defined. Severity inherits from str, so
    # any operator left undefined falls back to str's lexicographic version
    # — under which "critical" >= "medium" is False, silently turning every
    # threat check into a no-op. Ordering is by rank, never by name.
    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank <= other.rank

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank > other.rank

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank >= other.rank

    @classmethod
    def from_score(cls, score: float) -> Severity:
        """Map an aggregate 0-100 score onto a severity band."""
        if score >= 90:
            return cls.CRITICAL
        if score >= 70:
            return cls.HIGH
        if score >= 50:
            return cls.MEDIUM
        if score >= 30:
            return cls.LOW
        return cls.CLEAN


_SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CLEAN: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

#: Console colours, shared by the CLI and the GUI stylesheet.
SEVERITY_COLORS: dict[Severity, str] = {
    Severity.CLEAN: "green",
    Severity.LOW: "cyan",
    Severity.MEDIUM: "yellow",
    Severity.HIGH: "red",
    Severity.CRITICAL: "bright_red",
}


@dataclass(frozen=True, slots=True)
class Detection:
    """One signal from one detector.

    Attributes:
        detector: Name of the producing detector, e.g. ``"yara"``.
        name: Identifier for what matched — a rule name, signature name or
            heuristic id. This is what the user sees.
        confidence: 0-100. How sure *this detector alone* is.
        description: One line of plain English explaining the signal.
        conclusive: Set when the match is definitive on its own (exact hash
            of a known sample). Forces the aggregate score to 100.
        metadata: Detector-specific extras (offsets, rule tags, matched
            strings). Must be JSON-serialisable and must never contain file
            contents beyond short excerpts.
    """

    detector: str
    name: str
    confidence: float
    description: str = ""
    conclusive: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not 0 <= self.confidence <= 100:
            raise ValueError(
                f"{self.detector}: confidence must be 0-100, got {self.confidence}"
            )

    @property
    def severity(self) -> Severity:
        """Severity of this signal considered in isolation."""
        return Severity.from_score(100.0 if self.conclusive else self.confidence)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class Verdict:
    """The aggregate conclusion about one file."""

    path: str
    sha256: str = ""
    size: int = 0
    detections: list[Detection] = field(default_factory=list)
    score: float = 0.0
    severity: Severity = Severity.CLEAN
    #: Set when scanning failed rather than concluded.
    error: str | None = None
    #: True when a whitelist entry suppressed a would-be finding.
    whitelisted: bool = False
    #: Seconds spent scanning this file.
    duration: float = 0.0
    #: What was done about it: none | quarantined | deleted | ignored.
    action: str = "none"

    @property
    def is_threat(self) -> bool:
        return self.severity >= Severity.MEDIUM and not self.whitelisted

    @property
    def is_suspicious(self) -> bool:
        return self.severity is Severity.LOW and not self.whitelisted

    @property
    def is_clean(self) -> bool:
        return self.severity is Severity.CLEAN or self.whitelisted

    @property
    def top_detection(self) -> Detection | None:
        """The detection that contributed most, for the summary line."""
        if not self.detections:
            return None
        return max(
            self.detections,
            key=lambda d: (d.conclusive, d.confidence),
        )

    @property
    def name(self) -> str:
        """Display name for the threat, e.g. ``Trojan.GenericKD.12345``."""
        top = self.top_detection
        return top.name if top else ""

    @property
    def detector_names(self) -> list[str]:
        """Distinct detectors that fired, in order of first appearance."""
        seen: dict[str, None] = {}
        for d in self.detections:
            seen.setdefault(d.detector, None)
        return list(seen)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "sha256": self.sha256,
            "size": self.size,
            "score": round(self.score, 1),
            "severity": self.severity.value,
            "name": self.name,
            "detections": [d.to_dict() for d in self.detections],
            "whitelisted": self.whitelisted,
            "error": self.error,
            "duration": round(self.duration, 4),
            "action": self.action,
        }

    def summary(self) -> str:
        """One-line description for logs and the CLI table."""
        if self.error:
            return f"error: {self.error}"
        if self.whitelisted:
            return "whitelisted"
        if not self.detections:
            return "clean"
        top = self.top_detection
        assert top is not None
        extra = len(self.detector_names) - 1
        suffix = f" (+{extra} more)" if extra > 0 else ""
        return f"{top.name} [{top.detector}]{suffix}"


#: Ceiling for a purely heuristic score. A score of exactly 100 is reserved
#: for conclusive detections, so "100" always means "identified", never
#: "many things looked odd at once".
MAX_HEURISTIC_SCORE = 99.0


def aggregate(detections: Iterable[Detection]) -> float:
    """Combine detection confidences into a single 0-100 score.

    Returns 0.0 for an empty iterable, and exactly 100.0 if any detection is
    marked conclusive.

    Non-conclusive scores are capped at :data:`MAX_HEURISTIC_SCORE`. Without
    the cap, enough weak signals saturate the noisy-OR to 100.0 — twenty
    detections at 30% already reach 99.92 — and a pile of guesses becomes
    indistinguishable from an exact hash match. Heuristics do not get to
    claim certainty no matter how many of them fire.
    """
    items = list(detections)
    if not items:
        return 0.0
    if any(d.conclusive for d in items):
        return 100.0

    # Noisy-OR in probability space.
    inverse = 1.0
    for detection in items:
        inverse *= 1.0 - (detection.confidence / 100.0)
    return min(round((1.0 - inverse) * 100.0, 2), MAX_HEURISTIC_SCORE)


def build_verdict(
    path: str,
    detections: Iterable[Detection],
    *,
    sha256: str = "",
    size: int = 0,
    duration: float = 0.0,
    whitelisted: bool = False,
    error: str | None = None,
) -> Verdict:
    """Assemble a :class:`Verdict` from raw detections."""
    items = sorted(
        detections,
        key=lambda d: (d.conclusive, d.confidence),
        reverse=True,
    )
    score = aggregate(items)
    return Verdict(
        path=path,
        sha256=sha256,
        size=size,
        detections=items,
        score=score,
        severity=Severity.CLEAN if whitelisted else Severity.from_score(score),
        whitelisted=whitelisted,
        error=error,
        duration=duration,
    )


@dataclass(slots=True)
class ScanResult:
    """Everything a completed scan produced."""

    scan_id: int = 0
    roots: list[str] = field(default_factory=list)
    verdicts: list[Verdict] = field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0
    bytes_scanned: int = 0
    errors: int = 0
    duration: float = 0.0
    cancelled: bool = False
    started_at: float = 0.0

    @property
    def threats(self) -> list[Verdict]:
        return [v for v in self.verdicts if v.is_threat]

    @property
    def suspicious(self) -> list[Verdict]:
        return [v for v in self.verdicts if v.is_suspicious]

    @property
    def threat_count(self) -> int:
        return len(self.threats)

    @property
    def suspicious_count(self) -> int:
        return len(self.suspicious)

    @property
    def worst_severity(self) -> Severity:
        return max((v.severity for v in self.verdicts), default=Severity.CLEAN)

    @property
    def files_per_second(self) -> float:
        return self.files_scanned / self.duration if self.duration > 0 else 0.0

    def to_dict(self) -> dict[str, Any]:
        """JSON-serialisable report body.

        Only threats and suspicious files are included — a full scan produces
        millions of clean verdicts that nobody wants in a report.
        """
        return {
            "scan_id": self.scan_id,
            "roots": self.roots,
            "started_at": self.started_at,
            "duration": round(self.duration, 3),
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "bytes_scanned": self.bytes_scanned,
            "errors": self.errors,
            "cancelled": self.cancelled,
            "threats": [v.to_dict() for v in self.threats],
            "suspicious": [v.to_dict() for v in self.suspicious],
            "summary": {
                "threats": self.threat_count,
                "suspicious": self.suspicious_count,
                "worst_severity": self.worst_severity.value,
            },
        }

    def exit_code(self) -> int:
        """Process exit status, following the ClamAV convention.

        0 = clean, 1 = threats found, 2 = errors occurred.
        """
        if self.threat_count:
            return 1
        if self.errors:
            return 2
        return 0
