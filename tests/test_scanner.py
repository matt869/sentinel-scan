"""Tests for the scan engine: traversal, detection, scoring, caching."""

from __future__ import annotations

import threading
import zipfile
from pathlib import Path
from typing import ClassVar

import pytest

from sentinel.core.events import EventType
from sentinel.engine.verdict import (
    MAX_HEURISTIC_SCORE,
    Detection,
    Severity,
    Verdict,
    aggregate,
    build_verdict,
)
from sentinel.engine.walker import FileWalker
from sentinel.utils.entropy import shannon_entropy
from sentinel.utils.file_types import FileType, guess_type, has_double_extension
from sentinel.utils.hashing import hash_bytes, hash_file, hash_file_multi

# ----------------------------------------------------------------------
# severity ordering
# ----------------------------------------------------------------------

class TestSeverity:
    def test_ordering_is_by_rank_not_alphabetical(self) -> None:
        # Severity subclasses str, so a missing comparison operator silently
        # falls back to lexicographic ordering — under which "critical" is
        # less than "medium" and every threat check breaks.
        assert Severity.CRITICAL > Severity.MEDIUM
        assert Severity.CRITICAL >= Severity.MEDIUM
        assert Severity.LOW < Severity.HIGH
        assert Severity.LOW <= Severity.HIGH
        assert not Severity.LOW >= Severity.HIGH

    def test_max_picks_the_worst(self) -> None:
        assert max([Severity.LOW, Severity.CRITICAL, Severity.CLEAN]) is Severity.CRITICAL

    def test_sorting(self) -> None:
        ordered = sorted([Severity.HIGH, Severity.CLEAN, Severity.MEDIUM])
        assert ordered == [Severity.CLEAN, Severity.MEDIUM, Severity.HIGH]

    @pytest.mark.parametrize(
        ("score", "expected"),
        [
            (0, Severity.CLEAN), (29, Severity.CLEAN),
            (30, Severity.LOW), (49, Severity.LOW),
            (50, Severity.MEDIUM), (69, Severity.MEDIUM),
            (70, Severity.HIGH), (89, Severity.HIGH),
            (90, Severity.CRITICAL), (100, Severity.CRITICAL),
        ],
    )
    def test_from_score_bands(self, score: float, expected: Severity) -> None:
        assert Severity.from_score(score) is expected


# ----------------------------------------------------------------------
# score aggregation
# ----------------------------------------------------------------------

class TestAggregation:
    def _detection(self, confidence: float, conclusive: bool = False) -> Detection:
        return Detection("test", "Rule", confidence, conclusive=conclusive)

    def test_empty_is_zero(self) -> None:
        assert aggregate([]) == 0.0

    def test_single_detection_passes_through(self) -> None:
        assert aggregate([self._detection(60)]) == pytest.approx(60.0)

    def test_two_signals_combine_without_reaching_certainty(self) -> None:
        # Noisy-OR: 50% and 50% give 75%, not 100%.
        assert aggregate([self._detection(50), self._detection(50)]) == pytest.approx(75.0)

    def test_many_weak_signals_accumulate(self) -> None:
        score = aggregate([self._detection(20) for _ in range(5)])
        assert 65 < score < 70

    def test_weak_signals_never_reach_certainty(self) -> None:
        """100 is reserved for conclusive detections, whatever piles up."""
        score = aggregate([self._detection(30) for _ in range(50)])
        assert score < 100.0
        assert score == MAX_HEURISTIC_SCORE

    def test_heuristics_are_capped_below_a_hash_match(self) -> None:
        piled_up = aggregate([self._detection(80) for _ in range(10)])
        certain = aggregate([self._detection(95, conclusive=True)])
        assert piled_up < certain == 100.0

    def test_conclusive_short_circuits(self) -> None:
        detections = [self._detection(5), self._detection(95, conclusive=True)]
        assert aggregate(detections) == 100.0

    def test_confidence_out_of_range_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="confidence must be 0-100"):
            Detection("test", "Rule", 150)


class TestVerdict:
    def test_clean_when_no_detections(self) -> None:
        verdict = build_verdict("/tmp/file", [])
        assert verdict.is_clean and not verdict.is_threat
        assert verdict.summary() == "clean"

    def test_threat_at_medium_and_above(self) -> None:
        verdict = build_verdict("/tmp/file", [Detection("d", "Bad", 60)])
        assert verdict.is_threat
        assert verdict.severity is Severity.MEDIUM

    def test_whitelisted_is_never_a_threat(self) -> None:
        verdict = build_verdict(
            "/tmp/file", [Detection("d", "Bad", 99)], whitelisted=True
        )
        assert verdict.is_clean and not verdict.is_threat
        assert verdict.severity is Severity.CLEAN

    def test_top_detection_prefers_conclusive(self) -> None:
        verdict = build_verdict(
            "/tmp/f",
            [Detection("a", "Weak", 90), Detection("b", "Sure", 50, conclusive=True)],
        )
        assert verdict.top_detection is not None
        assert verdict.top_detection.name == "Sure"

    def test_detector_names_are_deduplicated_in_order(self) -> None:
        verdict = build_verdict(
            "/tmp/f",
            [
                Detection("script", "A", 10),
                Detection("yara", "B", 20),
                Detection("script", "C", 30),
            ],
        )
        assert verdict.detector_names == ["script", "yara"]

    def test_to_dict_is_json_safe(self) -> None:
        import json

        verdict = build_verdict(
            "/tmp/f", [Detection("d", "N", 50, metadata={"k": [1, 2]})], sha256="ab" * 32
        )
        json.dumps(verdict.to_dict())  # must not raise


# ----------------------------------------------------------------------
# utilities
# ----------------------------------------------------------------------

class TestHashing:
    def test_known_digest(self) -> None:
        assert hash_bytes(b"") == (
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )

    def test_file_matches_bytes(self, tmp_path: Path) -> None:
        path = tmp_path / "f.bin"
        payload = b"sentinel" * 1000
        path.write_bytes(payload)
        assert hash_file(path) == hash_bytes(payload)

    def test_multi_hash_single_pass(self, tmp_path: Path) -> None:
        path = tmp_path / "f.bin"
        path.write_bytes(b"abc")
        digests = hash_file_multi(path)
        assert digests["md5"] == "900150983cd24fb0d6963f7d28e17f72"
        assert digests["sha1"] == "a9993e364706816aba3e25717850c26c9cd0d89d"
        assert digests["sha256"].startswith("ba7816bf")

    def test_missing_file_raises_hash_error(self, tmp_path: Path) -> None:
        from sentinel.utils.hashing import HashError

        with pytest.raises(HashError):
            hash_file(tmp_path / "nope.bin")


class TestFileTypes:
    def test_pe_detected_from_magic(self, fake_pe: Path) -> None:
        info = guess_type(fake_pe)
        assert info.file_type is FileType.PE

    def test_masquerading_detected(self, fake_pe: Path) -> None:
        # A PE named .pdf has no legitimate explanation.
        assert guess_type(fake_pe).is_masquerading

    def test_extension_is_not_trusted(self, tmp_path: Path) -> None:
        path = tmp_path / "photo.png"
        path.write_bytes(b"MZ\x90\x00")
        info = guess_type(path)
        assert info.file_type is FileType.PE
        assert info.claimed_type is FileType.IMAGE

    @pytest.mark.parametrize(
        ("name", "expected"),
        [
            ("report.pdf.exe", ".pdf"),
            ("photo.jpg.scr", ".jpg"),
            ("archive.tar.gz", None),      # legitimate double extension
            ("script.min.js", None),       # legitimate
            ("plain.exe", None),
        ],
    )
    def test_double_extension(self, name: str, expected: str | None) -> None:
        assert has_double_extension(name) == expected


class TestEntropy:
    def test_empty_is_zero(self) -> None:
        assert shannon_entropy(b"") == 0.0

    def test_uniform_is_zero(self) -> None:
        assert shannon_entropy(b"\x00" * 1000) == 0.0

    def test_all_byte_values_is_maximal(self) -> None:
        assert shannon_entropy(bytes(range(256))) == pytest.approx(8.0)

    def test_text_is_lower_than_random(self) -> None:
        import os

        text = shannon_entropy(b"the quick brown fox " * 50)
        random = shannon_entropy(os.urandom(1000))
        assert text < random


# ----------------------------------------------------------------------
# walker
# ----------------------------------------------------------------------

class TestWalker:
    def test_finds_files_recursively(self, tmp_path: Path) -> None:
        (tmp_path / "a").mkdir()
        (tmp_path / "a" / "b").mkdir()
        (tmp_path / "top.txt").write_text("x")
        (tmp_path / "a" / "mid.txt").write_text("x")
        (tmp_path / "a" / "b" / "deep.txt").write_text("x")

        found = {e.path.name for e in FileWalker().walk([tmp_path])}
        assert found == {"top.txt", "mid.txt", "deep.txt"}

    def test_skips_empty_files(self, tmp_path: Path) -> None:
        (tmp_path / "empty.txt").write_text("")
        (tmp_path / "full.txt").write_text("content")
        found = [e.path.name for e in FileWalker().walk([tmp_path])]
        assert found == ["full.txt"]

    def test_single_file_root(self, clean_file: Path) -> None:
        found = list(FileWalker().walk([clean_file]))
        assert len(found) == 1 and found[0].path == clean_file

    def test_missing_path_is_skipped_not_fatal(self, tmp_path: Path) -> None:
        walker = FileWalker()
        assert list(walker.walk([tmp_path / "does-not-exist"])) == []
        assert walker.stats.files_skipped == 1

    def test_excluded_extensions(self, tmp_path: Path) -> None:
        (tmp_path / "disk.iso").write_text("x" * 100)
        (tmp_path / "doc.txt").write_text("x" * 100)

        class Settings:
            follow_symlinks = False
            max_file_size = 1024
            skip_network_drives = True
            exclude_paths: ClassVar[list[str]] = []
            exclude_extensions: ClassVar[list[str]] = [".iso"]

        found = [e.path.name for e in FileWalker(Settings()).walk([tmp_path])]
        assert found == ["doc.txt"]

    def test_cancellation_stops_traversal(self, tmp_path: Path) -> None:
        for i in range(200):
            (tmp_path / f"f{i}.txt").write_text("x")

        cancel = threading.Event()
        walker = FileWalker(cancel_event=cancel)
        collected = []
        for entry in walker.walk([tmp_path]):
            collected.append(entry)
            if len(collected) == 5:
                cancel.set()
        assert len(collected) < 200

    def test_stats_are_recorded(self, corpus: Path) -> None:
        walker = FileWalker()
        list(walker.walk([corpus]))
        assert walker.stats.files_found == 3
        assert walker.stats.bytes_found > 0
        assert walker.stats.directories >= 1


# ----------------------------------------------------------------------
# end-to-end scanning
# ----------------------------------------------------------------------

class TestScanner:
    def test_clean_file_produces_no_threat(self, scanner, clean_file: Path) -> None:
        verdict = scanner.scan_file(clean_file)
        assert verdict.is_clean
        assert not verdict.detections

    def test_powershell_dropper_is_flagged(self, scanner, powershell_dropper: Path) -> None:
        verdict = scanner.scan_file(powershell_dropper)
        assert verdict.is_threat
        assert verdict.severity >= Severity.HIGH
        assert "script" in verdict.detector_names

    def test_ransomware_script_is_critical(self, scanner, ransomware_script: Path) -> None:
        verdict = scanner.scan_file(ransomware_script)
        assert verdict.severity is Severity.CRITICAL
        # Both the shadow-copy deletion and the recovery disable should fire.
        names = {d.name for d in verdict.detections}
        assert any("shadow" in n.lower() or "Dropper" in n for n in names)

    def test_scan_directory_counts_and_exit_code(self, scanner, corpus: Path) -> None:
        result = scanner.scan_paths([corpus])
        assert result.files_scanned == 3
        assert result.threat_count >= 2
        assert result.exit_code() == 1
        assert result.worst_severity is Severity.CRITICAL

    def test_clean_directory_exits_zero(self, scanner, tmp_path: Path) -> None:
        directory = tmp_path / "clean"
        directory.mkdir()
        for i in range(5):
            (directory / f"note{i}.txt").write_text("nothing to see here\n" * 10)

        result = scanner.scan_paths([directory])
        assert result.threat_count == 0
        assert result.exit_code() == 0

    def test_hash_detector_is_conclusive(
        self, scanner, hash_signature_db, tmp_path: Path
    ) -> None:
        target = tmp_path / "sample.bin"
        target.write_bytes(b"a known bad payload" * 50)
        hash_signature_db(hash_file(target), "Trojan.Test.Known", "critical")

        verdict = scanner.scan_file(target)
        assert verdict.score == 100.0
        assert verdict.name == "Trojan.Test.Known"
        assert any(d.conclusive for d in verdict.detections)

    def test_events_are_emitted(self, scanner, recorder, corpus: Path) -> None:
        scanner.scan_paths([corpus])
        assert recorder.count(EventType.SCAN_STARTED) == 1
        assert recorder.count(EventType.SCAN_FINISHED) == 1
        assert recorder.count(EventType.THREAT_FOUND) >= 2

    def test_cancellation_marks_result(self, scanner, tmp_path: Path) -> None:
        directory = tmp_path / "many"
        directory.mkdir()
        for i in range(300):
            (directory / f"f{i}.txt").write_text("filler content " * 40)

        threading.Timer(0.01, scanner.cancel).start()
        result = scanner.scan_paths([directory])
        assert result.cancelled

    def test_history_is_persisted(self, scanner, db, corpus: Path) -> None:
        result = scanner.scan_paths([corpus])
        record = db.get_scan(result.scan_id)
        assert record is not None
        assert record.status == "completed"
        assert record.threats == result.threat_count
        assert len(db.findings_for_scan(result.scan_id)) == len(result.verdicts)

    def test_detector_failure_does_not_abort_the_scan(
        self, scanner, corpus: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A detector that raises is skipped; the rest of the scan proceeds."""
        scanner.detectors = scanner._build_detectors()
        assert scanner.detectors

        def explode(target):
            raise RuntimeError("detector is broken")

        monkeypatch.setattr(scanner.detectors[0], "scan", explode)
        result = scanner.scan_paths([corpus])
        assert result.files_scanned == 3

    def test_scan_result_json_excludes_clean_files(self, scanner, corpus: Path) -> None:
        result = scanner.scan_paths([corpus])
        payload = result.to_dict()
        # Only findings are serialised; a full-disk scan must not emit
        # millions of clean verdicts.
        paths = {t["path"] for t in payload["threats"]}
        assert not any(p.endswith("notes.txt") for p in paths)


class TestArchiveScanning:
    def test_path_traversal_is_flagged(self, scanner, traversal_zip: Path) -> None:
        verdict = scanner.scan_file(traversal_zip)
        names = {d.name for d in verdict.detections}
        assert "Heuristic.Archive.PathTraversal" in names

    def test_rtl_override_is_flagged(self, scanner, rtl_zip: Path) -> None:
        verdict = scanner.scan_file(rtl_zip)
        names = {d.name for d in verdict.detections}
        assert "Heuristic.Archive.RTLOverride" in names
        assert verdict.severity >= Severity.HIGH

    def test_members_are_scanned(
        self, scanner, hash_signature_db, tmp_path: Path
    ) -> None:
        """A known-bad file inside a zip is found via the member scanner."""
        payload = b"a known bad payload inside an archive" * 20
        hash_signature_db(hash_bytes(payload), "Trojan.Test.InZip", "critical")

        archive = tmp_path / "bundle.zip"
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("innocent.txt", "hello")
            zf.writestr("payload.bin", payload)

        verdict = scanner.scan_file(archive)
        assert verdict.is_threat
        assert any(d.name == "Trojan.Test.InZip" for d in verdict.detections)
        # The detection is attributed through the archive detector.
        assert any(d.detector.startswith("archive:") for d in verdict.detections)

    def test_nesting_depth_is_bounded(self, scanner, config, tmp_path: Path) -> None:
        config.scan.archive_depth = 1
        inner = tmp_path / "inner.zip"
        with zipfile.ZipFile(inner, "w") as zf:
            zf.writestr("deep.txt", "x")
        outer = tmp_path / "outer.zip"
        with zipfile.ZipFile(outer, "w") as zf:
            zf.write(inner, "inner.zip")

        # Must complete rather than recursing indefinitely.
        verdict = scanner.scan_file(outer)
        assert isinstance(verdict, Verdict)


class TestResultCache:
    def test_clean_result_is_cached_and_reused(
        self, scanner, db, clean_file: Path
    ) -> None:
        from sentinel.engine.detectors.base import ScanTarget

        scanner.detectors = scanner._build_detectors()
        try:
            first = scanner._scan_target(ScanTarget(path=clean_file))
            assert first.is_clean

            cached = scanner._cache_lookup(ScanTarget(path=clean_file))
            assert cached is not None
            assert cached.severity is Severity.CLEAN
        finally:
            scanner._teardown_detectors()

    def test_findings_are_never_served_from_cache(
        self, scanner, powershell_dropper: Path
    ) -> None:
        """A threat must be re-derived so the full detection list is present."""
        from sentinel.engine.detectors.base import ScanTarget

        scanner.detectors = scanner._build_detectors()
        try:
            scanner._scan_target(ScanTarget(path=powershell_dropper))
            assert scanner._cache_lookup(ScanTarget(path=powershell_dropper)) is None
        finally:
            scanner._teardown_detectors()
