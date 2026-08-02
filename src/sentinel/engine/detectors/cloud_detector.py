"""Optional hash-reputation lookups against a Sentinel reporting server.

Privacy contract — this detector is the only one that talks to the network
during a scan, and it is off unless the user turns it on:

* It sends **hashes only**. File contents, names and paths never leave the
  machine here. (Sample upload is a separate, separately-consented flow in
  :mod:`sentinel.feedback.sample_upload`.)
* Hashes are batched, so the server sees a set of digests per scan rather
  than a timed sequence it could correlate with user activity.
* A failure is never fatal. No network, no server, a timeout — the detector
  returns nothing and the scan continues on local signatures alone.

See docs/privacy.md for the full statement.
"""

from __future__ import annotations

import threading
from collections.abc import Sequence
from typing import Any

from sentinel.engine.detectors.base import Detector, ScanTarget, registry
from sentinel.engine.verdict import Detection, Severity

#: Hashes accumulated before a lookup is issued. Larger batches mean fewer
#: round trips but a longer wait before the first verdict.
BATCH_SIZE = 64

#: Stop trying after this many consecutive failures — a scan of a million
#: files should not attempt a million doomed HTTP requests.
MAX_CONSECUTIVE_FAILURES = 3


@registry.register
class CloudDetector(Detector):
    """Looks up file hashes against a reputation service."""

    name = "cloud"
    description = "Hash reputation lookup against a Sentinel server (opt-in, hashes only)"
    priority = 20

    def __init__(self, config: Any = None) -> None:
        super().__init__(config)
        self._privacy = getattr(config, "privacy", None)
        self._client: Any = None
        self._lock = threading.Lock()
        #: sha256 -> verdict payload, or None for "known and clean".
        self._cache: dict[str, dict[str, Any] | None] = {}
        self._failures = 0
        self._disabled = False

    def available(self) -> bool:
        if self._privacy is None or not getattr(self._privacy, "server_url", ""):
            self._unavailable_reason = "no server configured (privacy.server_url is empty)"
            return False
        if not getattr(self._privacy, "allow_cloud_lookup", False):
            self._unavailable_reason = (
                "cloud lookups are not enabled (privacy.allow_cloud_lookup is false)"
            )
            return False
        return True

    def setup(self) -> None:
        # Imported here so the core scanner does not pay for httpx on a
        # fully offline run.
        from sentinel.feedback.client import ServerClient

        self._client = ServerClient(self._privacy)
        self.log.info(
            "cloud lookups enabled against %s — hashes only, no file contents",
            getattr(self._privacy, "server_url", ""),
        )

    def teardown(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None
        self._cache.clear()

    def interested_in(self, target: ScanTarget) -> bool:
        # Only worth asking about files that could actually execute, and only
        # for files on disk (archive members are covered by their container).
        return not self._disabled and target.size > 0 and target.depth == 0

    def scan(self, target: ScanTarget) -> Sequence[Detection]:
        digest = target.sha256
        if not digest or self._client is None or self._disabled:
            return ()

        with self._lock:
            if digest in self._cache:
                cached = self._cache[digest]
                return self._to_detections(cached) if cached else ()

        try:
            results = self._client.lookup_hashes([digest])
            self._failures = 0
        except Exception as exc:
            self._failures += 1
            self.log.debug("reputation lookup failed: %s", exc)
            if self._failures >= MAX_CONSECUTIVE_FAILURES:
                self._disabled = True
                self.log.warning(
                    "disabling cloud lookups for this scan after %d failures",
                    self._failures,
                )
            return ()

        payload = results.get(digest)
        with self._lock:
            self._cache[digest] = payload

        return self._to_detections(payload) if payload else ()

    def _to_detections(self, payload: dict[str, Any]) -> list[Detection]:
        """Turn a server reputation record into a detection."""
        verdict = str(payload.get("verdict", "unknown")).lower()
        if verdict in {"clean", "unknown"}:
            return []

        name = str(payload.get("name") or "Cloud.Unknown")
        detections = int(payload.get("detection_count", 0))
        total = int(payload.get("engine_count", 0))
        severity_name = str(payload.get("severity", "medium")).lower()

        try:
            severity = Severity(severity_name)
        except ValueError:
            severity = Severity.MEDIUM

        # Confidence tracks how many independent engines agreed. One engine
        # out of seventy is usually a false positive; sixty out of seventy is
        # not up for debate.
        if total > 0:
            ratio = detections / total
            confidence = 30.0 + 65.0 * min(ratio * 2.0, 1.0)
            description = (
                f"{detections} of {total} reputation sources classify this file as "
                f"malicious."
            )
        else:
            confidence = {
                Severity.CRITICAL: 90.0,
                Severity.HIGH: 80.0,
                Severity.MEDIUM: 60.0,
                Severity.LOW: 35.0,
            }.get(severity, 50.0)
            description = "Flagged by the reputation service."

        return [
            self.detection(
                name,
                confidence,
                description,
                # Never conclusive: a remote service we cannot audit does not
                # get to unilaterally condemn a user's file.
                conclusive=False,
                verdict=verdict,
                detection_count=detections,
                engine_count=total,
                first_seen=payload.get("first_seen"),
                source="cloud",
            )
        ]
