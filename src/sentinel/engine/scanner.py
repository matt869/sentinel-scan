"""The scan orchestrator.

Ties the pieces together::

    FileWalker  ->  WorkerPool  ->  detectors  ->  aggregate  ->  Verdict
                                        |
                                    whitelist / cache

Responsibilities that live here rather than in the parts:

* Building and tearing down the detector set once per scan.
* Deciding which detectors see which file (the ``interested_in`` filter).
* Short-circuiting on a conclusive detection so a known sample does not pay
  for YARA and PE parsing.
* Consulting and populating the result cache.
* Emitting progress events and writing history to the database.
"""

from __future__ import annotations

import os
import threading
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from sentinel.core.config import Config, load_config
from sentinel.core.db import Database
from sentinel.core.events import EventBus, EventType
from sentinel.core.logger import get_logger
from sentinel.engine.detectors import registry
from sentinel.engine.detectors.archive_detector import ArchiveDetector
from sentinel.engine.detectors.base import Detector, ScanTarget
from sentinel.engine.quarantine import Quarantine
from sentinel.engine.queue import WorkerPool
from sentinel.engine.verdict import (
    Detection,
    ScanResult,
    Severity,
    Verdict,
    build_verdict,
)
from sentinel.engine.walker import FileEntry, FileWalker
from sentinel.engine.whitelist import Whitelist
from sentinel.signatures.loader import SignatureStore
from sentinel.utils.hashing import HashError, quick_fingerprint
from sentinel.version import __version__

log = get_logger(__name__)

#: Emit a progress event at most this often, so a fast scan does not spend
#: more time notifying listeners than scanning.
PROGRESS_INTERVAL = 0.25


class Scanner:
    """Scans files and directories for malware."""

    def __init__(
        self,
        config: Config | None = None,
        bus: EventBus | None = None,
        db: Database | None = None,
        detectors: Sequence[str] | None = None,
    ) -> None:
        """
        Args:
            config: Loaded configuration; defaults to :func:`load_config`.
            bus: Event bus for progress notifications. One is created if
                omitted, reachable as :attr:`bus`.
            db: Database handle. One is opened under the data directory if
                omitted.
            detectors: Restrict to these detector names. Defaults to the
                enabled set from the configuration.
        """
        self.config = config or load_config()
        self.config.paths.ensure()
        self.bus = bus or EventBus()
        self.db = db if db is not None else Database(self.config.paths.db_file)

        self._requested_detectors = (
            list(detectors)
            if detectors is not None
            else self.config.detectors.enabled_names()
        )
        self.detectors: list[Detector] = []
        self.whitelist = Whitelist(self.db)
        self.quarantine = Quarantine(self.config, self.db, self.bus)
        self.signatures = SignatureStore(self.config)

        self.cancel_event = threading.Event()
        self._counter_lock = threading.Lock()
        self._files_scanned = 0
        self._bytes_scanned = 0
        self._errors = 0
        self._last_progress = 0.0
        self._active = False

    # -- lifecycle -----------------------------------------------------

    def _build_detectors(self) -> list[Detector]:
        """Instantiate and set up the enabled detectors."""
        built = registry.build(self.config, self._requested_detectors)
        ready: list[Detector] = []

        for detector in built:
            try:
                detector.setup()
            except Exception as exc:
                log.warning("detector %s disabled: %s", detector.name, exc)
                continue
            ready.append(detector)

            # The archive detector needs a way back into the pipeline to
            # scan the members it extracts.
            if isinstance(detector, ArchiveDetector):
                detector.set_member_scanner(self._scan_member)

        if not ready:
            log.warning("no detectors are available; every file will look clean")
        else:
            log.debug("active detectors: %s", ", ".join(d.name for d in ready))
        return ready

    def _teardown_detectors(self) -> None:
        for detector in self.detectors:
            try:
                detector.teardown()
            except Exception:
                log.debug("teardown failed for %s", detector.name, exc_info=True)
        self.detectors = []

    # -- public API ----------------------------------------------------

    def scan_paths(
        self,
        paths: Sequence[str | os.PathLike[str]],
        quarantine_threats: bool = False,
        quarantine_threshold: Severity = Severity.HIGH,
        record_history: bool = True,
    ) -> ScanResult:
        """Scan every file under *paths* and return the result.

        Args:
            paths: Files or directories to scan.
            quarantine_threats: Move findings at or above
                *quarantine_threshold* into the vault.
            quarantine_threshold: Minimum severity for automatic quarantine.
                Defaults to HIGH — acting automatically on heuristic MEDIUM
                findings would move users' legitimate files.
            record_history: Write the scan and its findings to the database.
        """
        if self._active:
            raise RuntimeError("this Scanner is already running a scan")

        roots = [str(Path(p).expanduser()) for p in paths]
        self._reset()
        self._active = True
        started = time.time()
        monotonic_start = time.monotonic()

        scan_id = 0
        if record_history:
            scan_id = self.db.start_scan(roots, __version__)

        self.detectors = self._build_detectors()
        self.whitelist.reload()

        self.bus.emit(
            EventType.SCAN_STARTED,
            scan_id=scan_id,
            roots=roots,
            detectors=[d.name for d in self.detectors],
        )

        walker = FileWalker(self.config.scan, self.cancel_event)
        pool: WorkerPool[FileEntry, Verdict] = WorkerPool(
            self._scan_entry,
            workers=self.config.scan.resolved_threads(),
            cancel_event=self.cancel_event,
            on_error=self._on_worker_error,
        )

        verdicts: list[Verdict] = []
        try:
            for verdict in pool.process(walker.walk(roots)):
                self._record(verdict)
                if not verdict.is_clean:
                    verdicts.append(verdict)
                    self._emit_finding(verdict)
        finally:
            self._teardown_detectors()
            self._active = False

        result = ScanResult(
            scan_id=scan_id,
            roots=roots,
            verdicts=verdicts,
            files_scanned=self._files_scanned,
            files_skipped=walker.stats.files_skipped,
            bytes_scanned=self._bytes_scanned,
            errors=self._errors,
            duration=time.monotonic() - monotonic_start,
            cancelled=self.cancel_event.is_set(),
            started_at=started,
        )

        if quarantine_threats:
            self._quarantine_all(result, quarantine_threshold)

        if record_history:
            self._save(scan_id, result)

        self.bus.emit(
            EventType.SCAN_CANCELLED if result.cancelled else EventType.SCAN_FINISHED,
            scan_id=scan_id,
            files_scanned=result.files_scanned,
            threats=result.threat_count,
            suspicious=result.suspicious_count,
            duration=result.duration,
        )

        log.info(
            "scanned %d files (%.1f MB) in %.1fs — %d threats, %d suspicious",
            result.files_scanned, result.bytes_scanned / 1024 / 1024,
            result.duration, result.threat_count, result.suspicious_count,
        )
        return result

    def scan_file(self, path: str | os.PathLike[str]) -> Verdict:
        """Scan a single file with a temporary detector set.

        Convenience for one-off checks. For more than a handful of files use
        :meth:`scan_paths`, which builds the detectors once.
        """
        self.detectors = self._build_detectors()
        self.whitelist.reload()
        try:
            return self._scan_target(ScanTarget(path=Path(path)))
        finally:
            self._teardown_detectors()

    def cancel(self) -> None:
        """Stop the running scan as soon as in-flight files finish."""
        log.info("scan cancellation requested")
        self.cancel_event.set()

    def close(self) -> None:
        """Release the database handle."""
        self._teardown_detectors()
        self.db.close()

    def __enter__(self) -> Scanner:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    # -- per-file work -------------------------------------------------

    def _scan_entry(self, entry: FileEntry) -> Verdict:
        """Worker entry point: turn a walker result into a verdict."""
        target = ScanTarget(path=entry.path, size=entry.size)
        try:
            return self._scan_target(target)
        finally:
            target.release()

    def _scan_target(self, target: ScanTarget) -> Verdict:
        """Run the detector pipeline over one target."""
        started = time.monotonic()
        self.bus.emit(EventType.FILE_STARTED, path=str(target.path))

        # Whitelist by path first — it costs nothing and lets us skip hashing
        # an excluded file entirely.
        hit = self.whitelist.check(target.path)
        if hit is not None:
            return build_verdict(
                str(target.path), (), size=target.size, whitelisted=True,
                duration=time.monotonic() - started,
            )

        cached = self._cache_lookup(target)
        if cached is not None:
            return cached

        if target.read_error:
            return build_verdict(
                str(target.path), (), size=target.size,
                error=target.read_error, duration=time.monotonic() - started,
            )

        # Hash-based whitelist needs the digest, which the hash detector will
        # want anyway — computing it here means one pass, not two.
        digest = target.sha256
        hit = self.whitelist.check(target.path, digest)
        if hit is not None:
            return build_verdict(
                str(target.path), (), sha256=digest, size=target.size,
                whitelisted=True, duration=time.monotonic() - started,
            )

        detections = self._run_detectors(target)

        verdict = build_verdict(
            str(target.path),
            detections,
            sha256=digest,
            size=target.size,
            duration=time.monotonic() - started,
        )
        self._cache_store(target, verdict)
        return verdict

    def _run_detectors(self, target: ScanTarget) -> list[Detection]:
        """Run each interested detector, stopping on a conclusive hit."""
        detections: list[Detection] = []
        oversized = target.size > self.config.scan.max_file_size

        for detector in self.detectors:
            if self.cancel_event.is_set():
                break

            # Oversized files still get the hash detector — a known-bad 1 GB
            # file should not slip through — but not the content detectors.
            if oversized and detector.name != "hash":
                continue

            try:
                if not detector.interested_in(target):
                    continue
                found = detector.scan(target)
            except Exception as exc:
                # The contract says detectors do not raise. When one does,
                # note it and carry on rather than losing the whole file.
                log.warning(
                    "detector %s failed on %s: %s",
                    detector.name, target.display_path, exc,
                )
                log.debug("detector traceback", exc_info=True)
                continue

            if not found:
                continue

            detections.extend(found)

            if any(d.conclusive for d in found):
                log.debug(
                    "%s conclusively identified %s; skipping remaining detectors",
                    detector.name, target.display_path,
                )
                break

        return detections

    def _scan_member(self, target: ScanTarget) -> list[Detection]:
        """Pipeline entry point for archive members.

        Called by :class:`ArchiveDetector` from a worker thread. Excludes the
        archive detector itself — nesting is bounded by ``archive_depth``,
        which the detector checks — and skips the cache, since a temp path's
        fingerprint is meaningless.
        """
        detections: list[Detection] = []
        for detector in self.detectors:
            if self.cancel_event.is_set():
                break
            if detector.name == "archive":
                continue
            try:
                if not detector.interested_in(target):
                    continue
                found = detector.scan(target)
            except Exception as exc:
                log.debug("detector %s failed on member %s: %s",
                          detector.name, target.member_name, exc)
                continue
            detections.extend(found)
            if any(d.conclusive for d in found):
                break
        return detections

    # -- result cache --------------------------------------------------

    def _cache_lookup(self, target: ScanTarget) -> Verdict | None:
        """Return a cached verdict for an unchanged file, if we have one."""
        if target.depth > 0:
            return None
        try:
            fingerprint = quick_fingerprint(target.path)
        except HashError:
            return None

        row = self.db.cache_get(fingerprint, self.signatures.version)
        if row is None:
            return None

        severity = Severity(row["severity"])
        if severity is not Severity.CLEAN:
            # Never serve a *finding* from cache: the user needs the full
            # detection list, and a re-scan of a handful of bad files is
            # cheap. The cache exists to skip the millions of clean ones.
            return None

        return Verdict(
            path=str(target.path),
            sha256=row["sha256"],
            size=target.size,
            score=row["score"],
            severity=severity,
        )

    def _cache_store(self, target: ScanTarget, verdict: Verdict) -> None:
        if target.depth > 0 or verdict.error:
            return
        try:
            fingerprint = quick_fingerprint(target.path)
        except HashError:
            return
        try:
            self.db.cache_put(
                fingerprint, verdict.sha256, int(verdict.score),
                verdict.severity.value, verdict.name, self.signatures.version,
            )
        except Exception as exc:
            log.debug("cannot cache result for %s: %s", target.path, exc)

    # -- bookkeeping ---------------------------------------------------

    def _reset(self) -> None:
        self.cancel_event.clear()
        self._files_scanned = 0
        self._bytes_scanned = 0
        self._errors = 0
        self._last_progress = 0.0

    def _record(self, verdict: Verdict) -> None:
        """Update counters and emit throttled progress."""
        with self._counter_lock:
            self._files_scanned += 1
            self._bytes_scanned += verdict.size
            if verdict.error:
                self._errors += 1
            files = self._files_scanned
            total_bytes = self._bytes_scanned

        now = time.monotonic()
        if now - self._last_progress >= PROGRESS_INTERVAL:
            self._last_progress = now
            self.bus.emit(
                EventType.SCAN_PROGRESS,
                files_scanned=files,
                bytes_scanned=total_bytes,
                current=verdict.path,
            )

        if verdict.error:
            self.bus.emit(EventType.FILE_ERROR, path=verdict.path, error=verdict.error)
        else:
            self.bus.emit(EventType.FILE_SCANNED, path=verdict.path,
                          severity=verdict.severity.value)

    def _emit_finding(self, verdict: Verdict) -> None:
        event = (
            EventType.THREAT_FOUND if verdict.is_threat else EventType.SUSPICIOUS_FOUND
        )
        self.bus.emit(
            event,
            path=verdict.path,
            name=verdict.name,
            severity=verdict.severity.value,
            score=verdict.score,
            detectors=verdict.detector_names,
            summary=verdict.summary(),
        )

    def _on_worker_error(self, entry: FileEntry, exc: Exception) -> None:
        with self._counter_lock:
            self._errors += 1
        log.warning("could not scan %s: %s", entry.path, exc)
        self.bus.emit(EventType.FILE_ERROR, path=str(entry.path), error=str(exc))

    def _quarantine_all(self, result: ScanResult, threshold: Severity) -> None:
        """Move qualifying findings into the vault, updating their verdicts."""
        for verdict in result.threats:
            if verdict.severity < threshold:
                continue
            try:
                self.quarantine.quarantine(verdict)
                verdict.action = "quarantined"
            except Exception as exc:
                log.error("could not quarantine %s: %s", verdict.path, exc)
                verdict.action = "quarantine-failed"

    def _save(self, scan_id: int, result: ScanResult) -> None:
        """Persist the scan and its findings."""
        try:
            self.db.add_findings(
                scan_id,
                [
                    {
                        "path": v.path,
                        "sha256": v.sha256,
                        "size": v.size,
                        "severity": v.severity.value,
                        "score": int(v.score),
                        "name": v.name,
                        "detections": [d.to_dict() for d in v.detections],
                        "action": v.action,
                    }
                    for v in result.verdicts
                ],
            )
            self.db.finish_scan(
                scan_id,
                "cancelled" if result.cancelled else "completed",
                files_scanned=result.files_scanned,
                files_skipped=result.files_skipped,
                bytes_scanned=result.bytes_scanned,
                threats=result.threat_count,
                suspicious=result.suspicious_count,
                errors=result.errors,
            )
        except Exception as exc:
            # A failed history write must not invalidate the scan the user
            # just waited for.
            log.error("could not save scan history: %s", exc)

    # -- introspection -------------------------------------------------

    def detector_status(self) -> list[dict[str, Any]]:
        """Report every known detector and whether it can run.

        Used by ``sentinel detectors``. Builds throwaway instances, so it is
        safe to call outside a scan.
        """
        enabled = set(self._requested_detectors)
        rows: list[dict[str, Any]] = []

        for name in registry.names():
            cls = registry.get(name)
            assert cls is not None
            try:
                instance = cls(self.config)
                available = instance.available()
                reason = "" if available else instance.unavailable_reason
            except Exception as exc:
                available, reason = False, str(exc)

            rows.append(
                {
                    "name": name,
                    "description": cls.description,
                    "enabled": name in enabled,
                    "available": available,
                    "reason": reason,
                    "priority": cls.priority,
                }
            )
        return rows
