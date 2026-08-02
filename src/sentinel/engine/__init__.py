"""The scan engine: traversal, detection, scoring, quarantine."""

from sentinel.engine.detectors import Detector, ScanTarget, registry
from sentinel.engine.quarantine import Quarantine, QuarantineEntry, QuarantineError
from sentinel.engine.scanner import Scanner
from sentinel.engine.verdict import (
    Detection,
    ScanResult,
    Severity,
    Verdict,
    aggregate,
    build_verdict,
)
from sentinel.engine.walker import FileEntry, FileWalker
from sentinel.engine.whitelist import Whitelist, WhitelistError

__all__ = [
    "Detection",
    "Detector",
    "FileEntry",
    "FileWalker",
    "Quarantine",
    "QuarantineEntry",
    "QuarantineError",
    "ScanResult",
    "ScanTarget",
    "Scanner",
    "Severity",
    "Verdict",
    "Whitelist",
    "WhitelistError",
    "aggregate",
    "build_verdict",
    "registry",
]
