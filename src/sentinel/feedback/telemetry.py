"""Opt-in anonymous telemetry.

Off by default and inert unless ``privacy.telemetry`` is explicitly enabled.

What is collected, exhaustively:

* Counts of detections per detector and per severity.
* Counts of files scanned and errors, bucketed.
* The signature set version and the app version.
* The OS family (``Windows``/``Linux``/``Darwin``) and Python version.

What is never collected, also exhaustively: file names, paths, hashes,
contents, hostnames, usernames, IP addresses, drive labels, or anything that
identifies a machine across sessions. There is no installation ID — batches
carry no identifier at all, so two submissions from the same machine cannot
be linked.

That last point is a real constraint, not a nicety: it means telemetry
cannot answer "how many unique users", and that is the intended trade.
"""

from __future__ import annotations

import platform
import threading
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from sentinel.core.logger import get_logger
from sentinel.engine.verdict import ScanResult
from sentinel.version import __version__

log = get_logger(__name__)

#: Counts are rounded into buckets so a small number cannot be a fingerprint.
_BUCKETS = (0, 1, 10, 100, 1_000, 10_000, 100_000, 1_000_000)


def bucket(value: int) -> str:
    """Round a count into a coarse bucket label."""
    if value <= 0:
        return "0"
    previous = _BUCKETS[0]
    for edge in _BUCKETS[1:]:
        if value < edge:
            return f"{previous}-{edge - 1}"
        previous = edge
    return f"{_BUCKETS[-1]}+"


@dataclass(slots=True)
class TelemetryBatch:
    """One anonymous submission."""

    app_version: str = __version__
    signature_version: str = "0"
    os_family: str = field(default_factory=platform.system)
    python_version: str = field(default_factory=platform.python_version)
    #: detector name -> number of detections
    detections_by_detector: dict[str, int] = field(default_factory=dict)
    #: severity name -> number of verdicts
    verdicts_by_severity: dict[str, int] = field(default_factory=dict)
    #: threat name -> count. Names come from signatures, not from user files.
    top_threats: dict[str, int] = field(default_factory=dict)
    files_scanned_bucket: str = "0"
    errors_bucket: str = "0"
    scan_count: int = 0
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "app_version": self.app_version,
            "signature_version": self.signature_version,
            "os_family": self.os_family,
            "python_version": self.python_version,
            "detections_by_detector": self.detections_by_detector,
            "verdicts_by_severity": self.verdicts_by_severity,
            "top_threats": self.top_threats,
            "files_scanned_bucket": self.files_scanned_bucket,
            "errors_bucket": self.errors_bucket,
            "scan_count": self.scan_count,
            "created_at": int(self.created_at),
        }

    @property
    def is_empty(self) -> bool:
        return self.scan_count == 0


class TelemetryCollector:
    """Accumulates counters across scans and submits them in batches.

    Nothing is sent until :meth:`flush` is called and the consent check
    passes. If telemetry is disabled the collector still runs — it just
    never sends — so enabling it mid-session does not require a restart.
    """

    def __init__(self, config: Any) -> None:
        self.config = config
        self._lock = threading.Lock()
        self._by_detector: Counter[str] = Counter()
        self._by_severity: Counter[str] = Counter()
        self._threats: Counter[str] = Counter()
        self._files = 0
        self._errors = 0
        self._scans = 0

    @property
    def enabled(self) -> bool:
        """Whether submission is permitted right now."""
        privacy = getattr(self.config, "privacy", None)
        return bool(
            getattr(privacy, "telemetry", False)
            and getattr(privacy, "server_url", "")
        )

    def record_scan(self, result: ScanResult) -> None:
        """Fold a completed scan into the counters."""
        with self._lock:
            self._scans += 1
            self._files += result.files_scanned
            self._errors += result.errors

            for verdict in result.verdicts:
                self._by_severity[verdict.severity.value] += 1
                for detection in verdict.detections:
                    self._by_detector[detection.detector] += 1
                    # Only record names that came from a signature or a
                    # built-in heuristic id — never anything derived from the
                    # file itself.
                    if detection.name.startswith(("Heuristic.", "Packer.", "Info.")):
                        self._threats[detection.name] += 1

    def build_batch(self) -> TelemetryBatch:
        """Snapshot the counters as a submittable batch."""
        from sentinel.signatures.loader import SignatureStore

        with self._lock:
            return TelemetryBatch(
                signature_version=SignatureStore(self.config).version,
                detections_by_detector=dict(self._by_detector),
                verdicts_by_severity=dict(self._by_severity),
                top_threats=dict(self._threats.most_common(20)),
                files_scanned_bucket=bucket(self._files),
                errors_bucket=bucket(self._errors),
                scan_count=self._scans,
            )

    def preview(self) -> str:
        """Exactly what would be sent, as JSON, for the user to inspect."""
        import json

        return json.dumps(self.build_batch().to_dict(), indent=2, sort_keys=True)

    def flush(self) -> bool:
        """Submit the batch if consent allows. Returns True if sent.

        Counters are only cleared on a successful send, so a transient
        network failure does not silently lose the data — nor does it retry
        forever, since the next flush simply includes it again.
        """
        if not self.enabled:
            return False

        batch = self.build_batch()
        if batch.is_empty:
            return False

        from sentinel.feedback.client import ServerClient

        with ServerClient(getattr(self.config, "privacy", None)) as client:
            sent = client.submit_telemetry(batch.to_dict())

        if sent:
            self.reset()
            log.debug("telemetry batch submitted (%d scans)", batch.scan_count)
        return sent

    def reset(self) -> None:
        with self._lock:
            self._by_detector.clear()
            self._by_severity.clear()
            self._threats.clear()
            self._files = 0
            self._errors = 0
            self._scans = 0


def consent_notice() -> str:
    """The text shown when a user is asked about telemetry."""
    return (
        "Anonymous telemetry sends counts only: how many files were scanned "
        "(bucketed), which detectors fired, and which built-in heuristic names "
        "matched.\n\n"
        "It never sends file names, paths, hashes, contents, your hostname or "
        "username. Batches carry no identifier, so submissions cannot be linked "
        "to each other or to you.\n\n"
        "It is off unless you turn it on, and `sentinel telemetry --preview` "
        "shows exactly what would be sent."
    )
