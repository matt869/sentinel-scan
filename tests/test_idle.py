"""The idle probe, the tracker, and the scheduler that sits on top of them."""

from __future__ import annotations

import threading

import pytest

from sentinel.daemon.scheduler import (
    CURSOR_KEY,
    CURSOR_MAX_AGE_SECONDS,
    INTERRUPTIONS_BEFORE_BACKOFF,
    INTERRUPTIONS_KEY,
    LAST_COMPLETED_KEY,
    SHORT_RUN_SECONDS,
    IdleScheduler,
    ScanCursor,
    ScanOutcome,
)
from sentinel.system import idle as idle_module
from sentinel.system.idle import IdleTracker, idle_seconds, user_is_away


class FakeDb:
    """The kv half of Database, which is all the scheduler touches."""

    def __init__(self, **initial: str) -> None:
        self.values: dict[str, str] = dict(initial)

    def get_setting(self, key: str, default: str | None = None) -> str | None:
        return self.values.get(key, default)

    def set_setting(self, key: str, value: str) -> None:
        self.values[key] = value


class FakeClock:
    def __init__(self, now: float = 1_000_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture(autouse=True)
def _clear_probe_cache() -> None:
    """The probe is cached process-wide; a test must not inherit another's."""
    idle_module.reset_probe()


# ----------------------------------------------------------------------
# the probe
# ----------------------------------------------------------------------

def test_idle_seconds_never_raises() -> None:
    """Whatever this platform is, asking must be safe."""
    value = idle_seconds()
    assert value is None or value >= 0.0


def test_a_platform_that_cannot_tell_reports_the_user_present(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(idle_module, "_build_probe", lambda: None)
    idle_module.reset_probe()
    assert idle_seconds() is None
    assert user_is_away(1.0) is False


def test_a_negative_reading_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    """A negative idle time is broken clock arithmetic, not a fast user.

    The Windows path subtracts two 32-bit tick counts, and getting the
    wraparound wrong produces exactly this for the 49.7 days after each
    rollover. Reporting it as a small number would let a full-disk scan start
    under someone sitting at the keyboard.
    """
    class Broken:
        name = "broken"

        def seconds(self) -> float:
            return -42.0

    monkeypatch.setattr(idle_module, "_build_probe", Broken)
    idle_module.reset_probe()
    assert idle_seconds() is None


def test_a_probe_that_raises_is_treated_as_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Exploding:
        name = "exploding"

        def seconds(self) -> float:
            raise OSError("the display went away")

    monkeypatch.setattr(idle_module, "_build_probe", Exploding)
    idle_module.reset_probe()
    assert idle_seconds() is None


@pytest.mark.skipif(idle_seconds() is None, reason="no idle probe on this platform")
def test_the_real_probe_returns_something_plausible() -> None:
    value = idle_seconds()
    assert value is not None
    # Under a test runner somebody has touched this machine within a week.
    assert 0.0 <= value < 7 * 24 * 3600


def test_the_windows_tick_wraparound_is_masked() -> None:
    """``GetTickCount`` rolls over every 49.7 days; the maths must roll with it.

    Subtracting in Python's unbounded integers gives a negative idle time for
    the 49.7 days after each wrap, which reads as "the user is here" and means
    a machine with long uptime never runs a background scan again.
    """
    last_input = 0xFFFFFF00      # just before the wrap
    now = 0x00000100             # just after it
    assert (now - last_input) & 0xFFFFFFFF == 512
    assert now - last_input < 0  # what the unmasked version would have said


# ----------------------------------------------------------------------
# the tracker
# ----------------------------------------------------------------------

def _tracker_reading(monkeypatch: pytest.MonkeyPatch, *values: float | None) -> IdleTracker:
    """A tracker whose probe returns *values* in order, then repeats the last."""
    queue = list(values)

    def fake() -> float | None:
        return queue.pop(0) if len(queue) > 1 else queue[0]

    monkeypatch.setattr(idle_module, "idle_seconds", fake)
    return IdleTracker(away_after=300.0)


def test_the_tracker_reports_going_away_and_coming_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tracker = _tracker_reading(monkeypatch, 10.0, 400.0, 500.0, 2.0, 5.0)

    assert tracker.poll() is False and not tracker.away   # present
    assert tracker.poll() is False and tracker.away       # went away
    assert tracker.poll() is False and tracker.away       # still away
    assert tracker.poll() is True and not tracker.away    # came back
    assert tracker.poll() is False                        # still here


def test_falling_idle_time_is_the_only_proof_of_input(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A drop means the counter was reset, which means somebody touched it.

    Without this, a poll loop comparing raw seconds cannot distinguish "idle
    for 4 seconds because they paused to think" from "idle time just reset".
    """
    tracker = _tracker_reading(monkeypatch, 900.0, 400.0)
    tracker.poll()
    assert tracker.away
    tracker.poll()
    assert not tracker.away, "idle time fell 500s; that is input, not a lull"


def test_losing_the_probe_mid_scan_counts_as_the_user_returning(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The X display went away, or the session changed. Fail towards backing off."""
    tracker = _tracker_reading(monkeypatch, 900.0, None)
    tracker.poll()
    assert tracker.away
    assert tracker.poll() is True
    assert not tracker.away


def test_the_return_time_is_recorded(monkeypatch: pytest.MonkeyPatch) -> None:
    tracker = _tracker_reading(monkeypatch, 900.0, 1.0)
    tracker.poll(now=100.0)
    assert tracker.returned_at is None
    tracker.poll(now=140.0)
    assert tracker.returned_at == 140.0


# ----------------------------------------------------------------------
# the cursor
# ----------------------------------------------------------------------

def test_a_cursor_survives_a_round_trip() -> None:
    cursor = ScanCursor(roots=("C:\\",), last_path="C:\\Users\\a.txt",
                        files_done=1234, started_at=99.0)
    restored = ScanCursor.from_json(cursor.to_json())
    assert restored == cursor


@pytest.mark.parametrize(
    "raw", ["", "not json", "{}", '{"roots": []}', '{"roots": ["C:"], "files_done": "x"}']
)
def test_an_unreadable_cursor_is_discarded_not_raised(raw: str) -> None:
    """A corrupt checkpoint costs one restarted scan; it must not stop scanning."""
    assert ScanCursor.from_json(raw) is None


def test_a_cursor_for_different_roots_does_not_match() -> None:
    cursor = ScanCursor(roots=("C:\\",))
    assert cursor.matches(["C:\\"])
    assert not cursor.matches(["C:\\", "D:\\"])


def test_an_old_cursor_is_stale() -> None:
    """Resuming into a tree that has been reorganised skips whatever moved."""
    cursor = ScanCursor(roots=("C:\\",), started_at=0.0)
    assert not cursor.is_stale(CURSOR_MAX_AGE_SECONDS - 1)
    assert cursor.is_stale(CURSOR_MAX_AGE_SECONDS + 1)


# ----------------------------------------------------------------------
# the scheduler
# ----------------------------------------------------------------------

def scheduler(
    run_scan: object, clock: FakeClock, db: FakeDb | None = None, **kwargs: object
) -> IdleScheduler:
    return IdleScheduler(
        run_scan,  # type: ignore[arg-type]
        roots=["C:\\"],
        db=db if db is not None else FakeDb(),
        clock=clock,
        **kwargs,  # type: ignore[arg-type]
    )


def test_a_machine_never_scanned_is_due(clock: FakeClock) -> None:
    assert scheduler(lambda *a: ScanOutcome(True), clock).due()


def test_the_interval_is_measured_from_completion(clock: FakeClock) -> None:
    db = FakeDb(**{LAST_COMPLETED_KEY: str(clock.now)})
    sched = scheduler(lambda *a: ScanOutcome(True), clock, db, interval_hours=20.0)

    assert not sched.due()
    clock.advance(19 * 3600)
    assert not sched.due()
    clock.advance(2 * 3600)
    assert sched.due()


def test_an_interrupted_attempt_does_not_count_as_a_scan(clock: FakeClock) -> None:
    """Otherwise a machine that is never idle for long reports itself scanned."""
    db = FakeDb()
    sched = scheduler(lambda *a: ScanOutcome(False, "C:\\x", 10), clock, db)
    sched._attempt()

    assert LAST_COMPLETED_KEY not in db.values
    assert sched.due()


def test_a_clock_that_moved_backwards_does_not_block_scanning(
    clock: FakeClock,
) -> None:
    """A dead CMOS battery must not mean 'never scan again until 2031'."""
    db = FakeDb(**{LAST_COMPLETED_KEY: str(clock.now + 10 * 365 * 24 * 3600)})
    assert scheduler(lambda *a: ScanOutcome(True), clock, db).due()


def test_completing_clears_the_cursor_and_the_strikes(clock: FakeClock) -> None:
    db = FakeDb(**{CURSOR_KEY: ScanCursor(roots=("C:\\",)).to_json(),
                   INTERRUPTIONS_KEY: "2"})
    sched = scheduler(lambda *a: ScanOutcome(True, "C:\\z", 500), clock, db)
    sched._attempt()

    assert db.values[CURSOR_KEY] == ""
    assert db.values[INTERRUPTIONS_KEY] == "0"
    assert float(db.values[LAST_COMPLETED_KEY]) == clock.now


def test_an_interrupted_attempt_checkpoints_where_it_got_to(
    clock: FakeClock,
) -> None:
    """The load-bearing one.

    Without a checkpoint, a scan that needs ninety minutes of unbroken
    idleness on a machine used every day rescans the first fifth of the disk
    forever and never looks at the rest.
    """
    db = FakeDb()
    sched = scheduler(lambda *a: ScanOutcome(False, "C:\\Users\\m", 8000), clock, db)
    sched._attempt()

    cursor = ScanCursor.from_json(db.values[CURSOR_KEY])
    assert cursor is not None
    assert cursor.last_path == "C:\\Users\\m"
    assert cursor.files_done == 8000


def test_the_next_attempt_resumes_from_the_checkpoint(clock: FakeClock) -> None:
    db = FakeDb(**{CURSOR_KEY: ScanCursor(
        roots=("C:\\",), last_path="C:\\Users\\m", files_done=8000,
        started_at=clock.now).to_json()})

    seen: list[ScanCursor | None] = []

    def run(roots: object, resume: ScanCursor | None, stop: object) -> ScanOutcome:
        seen.append(resume)
        return ScanOutcome(True)

    scheduler(run, clock, db)._attempt()
    assert seen[0] is not None
    assert seen[0].last_path == "C:\\Users\\m"


def test_a_stale_checkpoint_is_not_resumed(clock: FakeClock) -> None:
    db = FakeDb(**{CURSOR_KEY: ScanCursor(
        roots=("C:\\",), last_path="C:\\old",
        started_at=clock.now - CURSOR_MAX_AGE_SECONDS - 1).to_json()})

    seen: list[ScanCursor | None] = []

    def run(roots: object, resume: ScanCursor | None, stop: object) -> ScanOutcome:
        seen.append(resume)
        return ScanOutcome(True)

    scheduler(run, clock, db)._attempt()
    assert seen == [None]


def test_a_resumed_cursor_keeps_its_original_start(clock: FakeClock) -> None:
    """Otherwise a cursor resumed daily is immortal and never ages out."""
    origin = clock.now - 3 * 24 * 3600
    db = FakeDb(**{CURSOR_KEY: ScanCursor(
        roots=("C:\\",), last_path="C:\\a", started_at=origin).to_json()})

    sched = scheduler(lambda *a: ScanOutcome(False, "C:\\b", 20), clock, db)
    sched._attempt()

    cursor = ScanCursor.from_json(db.values[CURSOR_KEY])
    assert cursor is not None and cursor.started_at == origin


def test_a_crashing_scan_leaves_the_checkpoint_alone(clock: FakeClock) -> None:
    """A single unreadable file must not restart the whole disk from zero."""
    original = ScanCursor(roots=("C:\\",), last_path="C:\\good", files_done=99)
    db = FakeDb(**{CURSOR_KEY: original.to_json()})

    def explode(*args: object) -> ScanOutcome:
        raise RuntimeError("the walker fell over")

    sched = scheduler(explode, clock, db)
    sched._attempt()

    assert ScanCursor.from_json(db.values[CURSOR_KEY]) == original
    assert not sched.scanning


def test_repeated_short_interruptions_widen_the_idle_threshold(
    clock: FakeClock,
) -> None:
    """Someone who steps away for six minutes at a time must not be nagged.

    Retrying at the same threshold is how a program becomes the thing you
    disable.
    """
    db = FakeDb()
    sched = scheduler(lambda *a: ScanOutcome(False, "C:\\x", 5), clock, db,
                      away_after=300.0)
    assert sched.away_after == 300.0

    for _ in range(INTERRUPTIONS_BEFORE_BACKOFF):
        sched._attempt()
    assert sched.away_after > 300.0


def test_the_interruption_count_is_not_re_read_on_every_tick(
    clock: FakeClock,
) -> None:
    """It is read twice a second forever; that must not be a SQLite query."""
    class CountingDb(FakeDb):
        def __init__(self) -> None:
            super().__init__()
            self.reads = 0

        def get_setting(self, key: str, default: str | None = None) -> str | None:
            if key == INTERRUPTIONS_KEY:
                self.reads += 1
            return super().get_setting(key, default)

    db = CountingDb()
    sched = scheduler(lambda *a: ScanOutcome(True), clock, db)
    for _ in range(100):
        assert sched.away_after == 300.0
    assert db.reads <= 1, f"{db.reads} database reads for one cached number"


def test_the_cached_interruption_count_still_tracks_writes(
    clock: FakeClock,
) -> None:
    """A cache that goes stale would freeze the backoff at its first value."""
    db = FakeDb()
    sched = scheduler(lambda *a: ScanOutcome(False, "C:\\x", 5), clock, db)
    assert sched.away_after == 300.0

    for _ in range(INTERRUPTIONS_BEFORE_BACKOFF):
        sched._attempt()
    widened = sched.away_after
    assert widened > 300.0
    assert db.values[INTERRUPTIONS_KEY] == str(INTERRUPTIONS_BEFORE_BACKOFF)

    # A completion resets it, and the cache must follow that too.
    sched.run_scan = lambda *a: ScanOutcome(True)  # type: ignore[assignment]
    sched._attempt()
    assert sched.away_after == 300.0


def test_a_thread_that_will_not_start_does_not_wedge_the_scheduler(
    monkeypatch: pytest.MonkeyPatch, clock: FakeClock
) -> None:
    """Otherwise it never scans again, silently, with nothing in flight."""
    sched = scheduler(lambda *a: ScanOutcome(True), clock)

    def refuse(self: threading.Thread) -> None:
        raise RuntimeError("can't start new thread")

    monkeypatch.setattr(threading.Thread, "start", refuse)
    sched._start_attempt()

    assert not sched.scanning, "the running claim was never given back"
    monkeypatch.undo()
    sched._start_attempt()
    assert sched._scan_thread is not None
    sched._scan_thread.join(timeout=5.0)


def test_a_long_run_that_was_interrupted_is_not_held_against_the_threshold(
    clock: FakeClock,
) -> None:
    """That is the design working, not the threshold being wrong."""
    db = FakeDb(**{INTERRUPTIONS_KEY: "5"})

    def run(roots: object, resume: object, stop: object) -> ScanOutcome:
        clock.advance(SHORT_RUN_SECONDS + 60)
        return ScanOutcome(False, "C:\\deep", 400_000)

    scheduler(run, clock, db)._attempt()
    assert db.values[INTERRUPTIONS_KEY] == "0"


def test_the_user_coming_back_aborts_the_scan(
    monkeypatch: pytest.MonkeyPatch, clock: FakeClock
) -> None:
    """The whole point. It has to happen within one poll."""
    started = threading.Event()
    stopped = threading.Event()

    def run(roots: object, resume: object, stop: threading.Event) -> ScanOutcome:
        started.set()
        if stop.wait(5.0):
            stopped.set()
            return ScanOutcome(False, "C:\\partway", 12)
        return ScanOutcome(True)

    idle_values = iter([900.0] * 3)
    monkeypatch.setattr(
        idle_module, "idle_seconds", lambda: next(idle_values, 1.0)
    )

    db = FakeDb()
    sched = IdleScheduler(run, roots=["C:\\"], db=db, clock=clock,
                          away_after=300.0, poll_seconds=0.02)
    with sched:
        assert started.wait(3.0), "the scan never started while the machine was idle"
        assert stopped.wait(3.0), "the scan was not stopped when the user came back"

    assert db.values[CURSOR_KEY], "an aborted scan must leave a checkpoint"


def test_no_roots_means_nothing_starts(clock: FakeClock) -> None:
    sched = IdleScheduler(lambda *a: ScanOutcome(True), roots=[], db=FakeDb(),
                          clock=clock)
    assert not sched.should_start()


def test_a_missing_database_is_survivable(clock: FakeClock) -> None:
    """The scheduler is constructed before the database on some paths."""
    sched = IdleScheduler(lambda *a: ScanOutcome(True), roots=["C:\\"], db=None,
                          clock=clock)
    assert sched.due()
    sched._attempt()  # must not raise


def test_the_loop_survives_a_failing_tick(
    monkeypatch: pytest.MonkeyPatch, clock: FakeClock
) -> None:
    """A dead scheduler thread means a product that silently never scans again."""
    calls: list[int] = []
    ticked_twice = threading.Event()

    def boom() -> None:
        calls.append(1)
        if len(calls) >= 2:
            ticked_twice.set()
        raise RuntimeError("nope")

    sched = scheduler(lambda *a: ScanOutcome(True), clock, poll_seconds=0.01)
    monkeypatch.setattr(sched, "_tick", boom)

    # Waiting on the second tick rather than on a stopwatch. A fixed sleep
    # asserts something about how fast the CI runner is, which is not what
    # this test is about and is how a suite acquires a flake.
    with sched:
        survived = ticked_twice.wait(10.0)

    assert survived, "the loop stopped after the first failure"
