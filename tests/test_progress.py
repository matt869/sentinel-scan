"""Tests for scan progress and the time estimate.

The estimate is what makes a forty-minute scan survivable, so the properties
tested here are the ones that decide whether a user trusts the number: it
never claims to know before it does, it never runs backwards, and it never
leaps upwards when the scan hits a slow patch.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from sentinel.core.events import EventType
from sentinel.engine.progress import (
    MAX_ETA_GROWTH,
    MIN_ELAPSED_FOR_ETA,
    Phase,
    ProgressTracker,
    format_eta,
)


class FakeClock:
    """A clock the test drives by hand, so nothing has to sleep."""

    def __init__(self, start: float = 1000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def tracker(clock: FakeClock) -> ProgressTracker:
    return ProgressTracker(clock=clock)


# ----------------------------------------------------------------------
# phases
# ----------------------------------------------------------------------

class TestPhases:
    def test_starts_enumerating_with_no_fraction(self, tracker: ProgressTracker) -> None:
        snapshot = tracker.snapshot()
        assert snapshot.phase is Phase.ENUMERATING
        # A percentage before the tree is counted would be a guess, and the
        # bar would jump backwards the moment a big directory turned up.
        assert snapshot.fraction is None
        assert snapshot.eta_seconds is None
        assert not snapshot.is_measurable

    def test_enumeration_reports_a_running_count(self, tracker: ProgressTracker) -> None:
        tracker.record_enumerated(1200, 4096, "C:/Users/x/file.txt")
        snapshot = tracker.snapshot()
        assert snapshot.files_total == 1200
        assert snapshot.current.endswith("file.txt")
        assert snapshot.fraction is None

    def test_scanning_phase_has_a_fraction(self, tracker: ProgressTracker) -> None:
        tracker.begin_scanning(files_total=10, bytes_total=1000)
        tracker.record_scanned(250)
        assert tracker.snapshot().fraction == pytest.approx(0.25)

    def test_zero_totals_mean_no_bar_rather_than_a_wrong_one(
        self, tracker: ProgressTracker
    ) -> None:
        # Enumeration skipped or cancelled. Better to show no bar than one
        # built on a number we do not have.
        tracker.begin_scanning(0, 0)
        tracker.record_scanned(500)
        snapshot = tracker.snapshot()
        assert snapshot.fraction is None
        assert snapshot.eta_seconds is None

    def test_finish_completes_the_bar(self, tracker: ProgressTracker) -> None:
        tracker.begin_scanning(10, 1000)
        tracker.record_scanned(400)
        tracker.finish()
        assert tracker.snapshot().fraction == 1.0


# ----------------------------------------------------------------------
# the fraction
# ----------------------------------------------------------------------

class TestFraction:
    def test_measures_bytes_not_files(self, tracker: ProgressTracker) -> None:
        # Two files: a 1 KB config and a 999 KB image. Finishing the config
        # is half the files but a thousandth of the work, and a bar that
        # jumps to 50% there is lying.
        tracker.begin_scanning(files_total=2, bytes_total=1_000_000)
        tracker.record_scanned(1_000)
        assert tracker.snapshot().fraction == pytest.approx(0.001)

    def test_clamped_at_one(self, tracker: ProgressTracker) -> None:
        # Enumeration and scanning see the tree moments apart, so the total
        # can be an undercount. The bar must not report 103%.
        tracker.begin_scanning(files_total=1, bytes_total=100)
        tracker.record_scanned(250)
        assert tracker.snapshot().fraction == 1.0


# ----------------------------------------------------------------------
# the estimate
# ----------------------------------------------------------------------

class TestEta:
    def _run(self, tracker: ProgressTracker, clock: FakeClock,
             chunk: int, seconds: float, times: int) -> None:
        for _ in range(times):
            clock.advance(seconds)
            tracker.record_scanned(chunk)

    def test_says_nothing_before_it_knows_something(
        self, tracker: ProgressTracker, clock: FakeClock
    ) -> None:
        tracker.begin_scanning(files_total=100, bytes_total=100_000)
        clock.advance(MIN_ELAPSED_FOR_ETA / 2)
        tracker.record_scanned(5_000)
        # Thread ramp-up and cache warming make any early rate wrong.
        assert tracker.snapshot().eta_seconds is None

    def test_estimates_from_the_observed_rate(
        self, tracker: ProgressTracker, clock: FakeClock
    ) -> None:
        tracker.begin_scanning(files_total=100, bytes_total=100_000)
        # 1000 bytes per second for 10 seconds: 90,000 bytes left, so ~90s.
        self._run(tracker, clock, chunk=1_000, seconds=1.0, times=10)
        eta = tracker.snapshot().eta_seconds
        assert eta is not None
        assert eta == pytest.approx(90.0, rel=0.15)

    def test_never_leaps_upwards(
        self, tracker: ProgressTracker, clock: FakeClock
    ) -> None:
        tracker.begin_scanning(files_total=100, bytes_total=1_000_000)
        self._run(tracker, clock, chunk=10_000, seconds=1.0, times=10)
        before = tracker.snapshot().eta_seconds
        assert before is not None

        # The scan hits a patch a hundred times slower. An estimate that
        # jumped from two minutes to three hours would destroy confidence in
        # every number the app shows.
        self._run(tracker, clock, chunk=100, seconds=1.0, times=5)
        after = tracker.snapshot().eta_seconds
        assert after is not None
        assert after <= before + 5 * MAX_ETA_GROWTH + 1.0

    def test_can_recover_when_the_scan_really_is_slower(
        self, tracker: ProgressTracker, clock: FakeClock
    ) -> None:
        # Rise-limiting must not mean the estimate is pinned at zero
        # forever — "almost done" that never ends is its own lie.
        tracker.begin_scanning(files_total=100, bytes_total=1_000_000)
        self._run(tracker, clock, chunk=10_000, seconds=1.0, times=10)
        fast = tracker.snapshot().eta_seconds
        assert fast is not None

        self._run(tracker, clock, chunk=100, seconds=1.0, times=200)
        slow = tracker.snapshot().eta_seconds
        assert slow is not None
        assert slow > fast

    def test_falls_freely_when_the_scan_speeds_up(
        self, tracker: ProgressTracker, clock: FakeClock
    ) -> None:
        tracker.begin_scanning(files_total=100, bytes_total=1_000_000)
        self._run(tracker, clock, chunk=1_000, seconds=1.0, times=10)
        slow = tracker.snapshot().eta_seconds
        assert slow is not None

        self._run(tracker, clock, chunk=50_000, seconds=1.0, times=10)
        fast = tracker.snapshot().eta_seconds
        assert fast is not None
        assert fast < slow

    def test_reaches_zero_at_the_end(
        self, tracker: ProgressTracker, clock: FakeClock
    ) -> None:
        tracker.begin_scanning(files_total=10, bytes_total=10_000)
        self._run(tracker, clock, chunk=1_000, seconds=1.0, times=10)
        assert tracker.snapshot().eta_seconds == pytest.approx(0.0, abs=1.0)


# ----------------------------------------------------------------------
# wording
# ----------------------------------------------------------------------

class TestFormatEta:
    @pytest.mark.parametrize(
        ("seconds", "expected"),
        [
            (None, "estimating…"),
            (3, "a few seconds"),
            (40, "under a minute"),
            (75, "about a minute"),
            (700, "about 12 minutes"),
            (3600, "about 1 hour"),
            (7200, "about 2 hours"),
            (9000, "about 2h 30m"),
        ],
    )
    def test_phrasing(self, seconds: float | None, expected: str) -> None:
        assert format_eta(seconds) == expected

    def test_never_shows_false_precision(self) -> None:
        # "11m 43s" is a promise you cannot keep, and being caught out on the
        # seconds costs more than the precision buys.
        assert format_eta(703) == format_eta(697)


# ----------------------------------------------------------------------
# engine integration
# ----------------------------------------------------------------------

class TestScannerIntegration:
    def test_enumeration_precedes_scanning(
        self, scanner, recorder, tmp_path: Path
    ) -> None:
        directory = tmp_path / "tree"
        directory.mkdir()
        for i in range(40):
            (directory / f"f{i}.txt").write_text("content " * 200)

        scanner.scan_paths([directory])

        types = [e.type for e in recorder]
        assert EventType.SCAN_ENUMERATING in types
        assert types.index(EventType.SCAN_ENUMERATING) < types.index(
            EventType.SCAN_PROGRESS
        )

    def test_progress_carries_totals_and_a_fraction(
        self, scanner, recorder, tmp_path: Path
    ) -> None:
        directory = tmp_path / "tree"
        directory.mkdir()
        for i in range(40):
            (directory / f"f{i}.txt").write_text("content " * 200)

        scanner.scan_paths([directory])

        events = recorder.of_type(EventType.SCAN_PROGRESS)
        assert events
        last = events[-1]
        assert last.get("files_total") == 40
        assert last.get("bytes_total") > 0
        assert 0.0 < last.get("fraction") <= 1.0

    def test_estimate_can_be_skipped(
        self, scanner, recorder, tmp_path: Path
    ) -> None:
        directory = tmp_path / "tree"
        directory.mkdir()
        (directory / "one.txt").write_text("hello")

        scanner.scan_paths([directory], estimate=False)

        assert recorder.count(EventType.SCAN_ENUMERATING) == 0
        for event in recorder.of_type(EventType.SCAN_PROGRESS):
            assert event.get("fraction") is None

    def test_enumeration_does_not_change_the_result(
        self, scanner, corpus: Path
    ) -> None:
        with_estimate = scanner.scan_paths([corpus])
        without = scanner.scan_paths([corpus], estimate=False)
        assert with_estimate.files_scanned == without.files_scanned
        assert with_estimate.threat_count == without.threat_count
