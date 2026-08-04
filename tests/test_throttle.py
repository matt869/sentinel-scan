"""The throttle governor.

Everything here runs against an injected :class:`Reading` and an injected
clock. The governor's job is a decision, and a decision can be tested exactly;
whether ``psutil`` reports the right CPU number is not this suite's problem
and cannot be made deterministic on a CI runner anyway.
"""

from __future__ import annotations

import dataclasses
import os
import threading

import pytest

from sentinel.daemon.throttle import (
    _DUTY,
    _RANK,
    MAX_PAUSE_SECONDS,
    Budget,
    Pace,
    Reading,
    ThrottleGovernor,
)


class FakeSensors:
    """Returns whatever the test last set."""

    def __init__(self, reading: Reading | None = None) -> None:
        self.reading = reading or Reading()
        self.reads = 0

    def read(self) -> Reading:
        self.reads += 1
        return self.reading


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


#: Captured before anything patches it, so the one test that exercises the
#: real thing can still reach it.
_REAL_SET_BACKGROUND_IO = ThrottleGovernor._set_background_io


@pytest.fixture(autouse=True)
def priority_calls(monkeypatch: pytest.MonkeyPatch) -> list[bool]:
    """Keep these tests out of the test runner's own scheduling priority.

    ``_set_background_io`` really does call ``SetPriorityClass``, and it
    applies to the whole process — which, here, is pytest. A test that
    dropped the runner into background I/O mode and never restored it would
    slow every test that ran after it, and that surfaces as an unrelated
    timeout hundreds of tests later. Recorded instead.
    """
    calls: list[bool] = []
    monkeypatch.setattr(
        ThrottleGovernor,
        "_set_background_io",
        lambda self, on: calls.append(on),
    )
    return calls


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


def governor(sensors: FakeSensors, clock: FakeClock, **kwargs: object) -> ThrottleGovernor:
    return ThrottleGovernor(sensors=sensors, clock=clock, **kwargs)  # type: ignore[arg-type]


# ----------------------------------------------------------------------
# the decision
# ----------------------------------------------------------------------

def test_full_speed_when_nobody_is_there(clock: FakeClock) -> None:
    sensors = FakeSensors(Reading(system_cpu=2.0, own_cpu=0.0, idle_seconds=600))
    assert governor(sensors, clock).decide(sensors.reading).pace is Pace.FULL


def test_half_speed_when_the_user_is_present_but_the_machine_is_quiet(
    clock: FakeClock,
) -> None:
    sensors = FakeSensors(Reading(system_cpu=5.0, own_cpu=0.0, idle_seconds=3))
    assert governor(sensors, clock).decide(sensors.reading).pace is Pace.HALF


def test_background_when_someone_else_is_using_the_machine(clock: FakeClock) -> None:
    sensors = FakeSensors(Reading(system_cpu=80.0, own_cpu=5.0, idle_seconds=3))
    assert governor(sensors, clock).decide(sensors.reading).pace is Pace.BACKGROUND


def test_unknown_idle_time_counts_as_present(clock: FakeClock) -> None:
    """The platform that cannot tell gets the careful answer, not the fast one."""
    sensors = FakeSensors(Reading(system_cpu=1.0, own_cpu=0.0, idle_seconds=None))
    assert governor(sensors, clock).decide(sensors.reading).pace is Pace.HALF


def test_our_own_cpu_does_not_count_as_the_machine_being_busy(
    clock: FakeClock,
) -> None:
    """The oscillation bug, pinned.

    A scan at full tilt puts the system-wide number well over the busy
    threshold on its own. If that counted, the governor would throttle in
    response to its own output, go quiet, see a calm machine, speed up, and
    flap forever.
    """
    reading = Reading(system_cpu=90.0, own_cpu=88.0, idle_seconds=3)
    assert reading.foreign_cpu == pytest.approx(2.0)
    assert governor(FakeSensors(reading), clock).decide(reading).pace is Pace.HALF


def test_foreign_cpu_never_goes_negative() -> None:
    """The two counters are sampled a moment apart and can disagree."""
    assert Reading(system_cpu=10.0, own_cpu=15.0).foreign_cpu == 0.0


def test_battery_outranks_an_empty_room(clock: FakeClock) -> None:
    """Being alone with the machine does not lift a battery's hard limit."""
    reading = Reading(system_cpu=1.0, own_cpu=0.0, idle_seconds=9999,
                      on_battery=True, battery_percent=80.0)
    assert governor(FakeSensors(reading), clock).decide(reading).pace is Pace.BACKGROUND


def test_a_nearly_flat_battery_stops_the_scan(clock: FakeClock) -> None:
    reading = Reading(idle_seconds=9999, on_battery=True, battery_percent=11.0)
    budget = governor(FakeSensors(reading), clock).decide(reading)
    assert budget.pace is Pace.PAUSED
    assert not budget.running


def test_battery_can_be_ignored_when_the_user_asks(clock: FakeClock) -> None:
    reading = Reading(system_cpu=1.0, own_cpu=0.0, idle_seconds=9999,
                      on_battery=True, battery_percent=50.0)
    gov = governor(FakeSensors(reading), clock, pause_on_battery=False)
    assert gov.decide(reading).pace is Pace.FULL


def test_manual_pause_beats_everything(clock: FakeClock) -> None:
    sensors = FakeSensors(Reading(system_cpu=0.0, own_cpu=0.0, idle_seconds=9999))
    gov = governor(sensors, clock)
    gov.pause()
    assert gov.budget(force=True).pace is Pace.PAUSED
    gov.resume()
    assert gov.budget(force=True).pace is not Pace.PAUSED


# ----------------------------------------------------------------------
# hysteresis
# ----------------------------------------------------------------------

def test_backing_off_is_immediate(clock: FakeClock) -> None:
    sensors = FakeSensors(Reading(system_cpu=1.0, own_cpu=0.0, idle_seconds=9999))
    gov = governor(sensors, clock)
    assert gov.budget(force=True).pace is Pace.FULL

    sensors.reading = Reading(system_cpu=90.0, own_cpu=1.0, idle_seconds=0)
    assert gov.budget(force=True).pace is Pace.BACKGROUND


def test_recovering_waits_for_sustained_calm(clock: FakeClock) -> None:
    sensors = FakeSensors(Reading(system_cpu=90.0, own_cpu=1.0, idle_seconds=0))
    gov = governor(sensors, clock, recovery_seconds=30.0)
    assert gov.budget(force=True).pace is Pace.BACKGROUND

    # The machine goes quiet, but not for long enough yet.
    sensors.reading = Reading(system_cpu=1.0, own_cpu=0.0, idle_seconds=9999)
    assert gov.budget(force=True).pace is Pace.BACKGROUND
    clock.advance(29.0)
    assert gov.budget(force=True).pace is Pace.BACKGROUND

    clock.advance(2.0)
    assert gov.budget(force=True).pace is Pace.FULL


def test_a_flicker_of_calm_does_not_speed_the_scan_up(clock: FakeClock) -> None:
    """One quiet sample in the middle of real work must not lurch the pace."""
    busy = Reading(system_cpu=90.0, own_cpu=1.0, idle_seconds=0)
    calm = Reading(system_cpu=1.0, own_cpu=0.0, idle_seconds=9999)

    sensors = FakeSensors(busy)
    gov = governor(sensors, clock, recovery_seconds=30.0)
    gov.budget(force=True)

    for _ in range(10):
        sensors.reading = calm
        clock.advance(5.0)
        gov.budget(force=True)
        sensors.reading = busy
        clock.advance(5.0)
        assert gov.budget(force=True).pace is Pace.BACKGROUND


def test_pace_ranking_is_explicit_not_lexicographic() -> None:
    """The Severity trap: Pace subclasses str, so ``<`` would be alphabetical.

    Under string ordering "half" < "full" is False, which would invert the
    hysteresis for exactly one of the four values — the subtlest possible
    version of this bug.
    """
    assert _RANK[Pace.PAUSED] < _RANK[Pace.BACKGROUND] < _RANK[Pace.HALF] < _RANK[Pace.FULL]
    assert (Pace.HALF < Pace.FULL) is False  # what the default would have given


# ----------------------------------------------------------------------
# pacing
# ----------------------------------------------------------------------

def test_full_speed_never_sleeps(clock: FakeClock) -> None:
    sensors = FakeSensors(Reading(system_cpu=1.0, own_cpu=0.0, idle_seconds=9999))
    gov = governor(sensors, clock)
    gov.budget(force=True)
    assert gov.wait_turn(0.5) == 0.0


def test_the_pause_is_proportional_to_the_work(monkeypatch: pytest.MonkeyPatch,
                                               clock: FakeClock) -> None:
    """One duty cycle has to be right for a 2 KB config and a 400 MB installer.

    A fixed pause between files would throttle a directory of small files
    into uselessness and barely touch a directory of large ones.
    """
    slept: list[float] = []
    monkeypatch.setattr(
        threading.Event, "wait", lambda self, timeout=None: slept.append(timeout or 0.0)
    )

    sensors = FakeSensors(Reading(system_cpu=5.0, own_cpu=0.0, idle_seconds=3))
    gov = governor(sensors, clock)
    assert gov.budget(force=True).pace is Pace.HALF  # 50% duty

    gov.wait_turn(0.1)
    gov.wait_turn(1.0)
    # 50% duty means pausing for as long as the work took.
    assert slept == [pytest.approx(0.1), pytest.approx(1.0)]


def test_one_expensive_file_cannot_stall_the_pipeline(
    monkeypatch: pytest.MonkeyPatch, clock: FakeClock
) -> None:
    """The duty cycle is a target, not a guarantee, and this is where it gives.

    At 15% duty a file that took 40 seconds would earn a 226-second pause. A
    scan that appears to have hung is a scan the user kills.
    """
    slept: list[float] = []
    monkeypatch.setattr(
        threading.Event, "wait", lambda self, timeout=None: slept.append(timeout or 0.0)
    )

    sensors = FakeSensors(Reading(system_cpu=95.0, own_cpu=1.0, idle_seconds=0))
    gov = governor(sensors, clock)
    assert gov.budget(force=True).pace is Pace.BACKGROUND

    gov.wait_turn(40.0)
    assert slept == [MAX_PAUSE_SECONDS]


def test_a_parked_worker_is_released_when_the_pause_lifts(clock: FakeClock) -> None:
    """A paused scan must not need a scan restart to come back."""
    sensors = FakeSensors(Reading(system_cpu=1.0, own_cpu=0.0, idle_seconds=9999))
    gov = governor(sensors, clock, sample_interval=0.01)
    gov.pause()
    assert not gov.budget(force=True).running

    released = threading.Event()

    def worker() -> None:
        gov.wait_turn(0.1)
        released.set()

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    assert not released.wait(0.1), "the worker left a pause it was never released from"

    gov.resume()
    assert released.wait(2.0), "the worker stayed parked after the pause lifted"
    thread.join(timeout=1.0)


def test_sampling_is_rate_limited(clock: FakeClock) -> None:
    """The GUI polls this for the flyout; it must not re-read the machine each time."""
    sensors = FakeSensors(Reading(system_cpu=1.0, own_cpu=0.0, idle_seconds=9999))
    gov = governor(sensors, clock, sample_interval=2.0)

    gov.budget()
    for _ in range(20):
        gov.budget()
    assert sensors.reads == 1

    clock.advance(3.0)
    gov.budget()
    assert sensors.reads == 2


def test_a_broken_sensor_keeps_the_last_budget(clock: FakeClock) -> None:
    """A governor that raises would take the scan down with it."""
    sensors = FakeSensors(Reading(system_cpu=1.0, own_cpu=0.0, idle_seconds=9999))
    gov = governor(sensors, clock)
    gov.budget(force=True)

    def explode() -> Reading:
        raise RuntimeError("psutil fell over")

    sensors.read = explode  # type: ignore[method-assign]
    clock.advance(10.0)
    assert gov.budget().pace is Pace.FULL


# ----------------------------------------------------------------------
# what the user is told
# ----------------------------------------------------------------------

def test_every_budget_carries_a_reason(clock: FakeClock) -> None:
    """The flyout shows this line, so 'why is it slow' is never unanswered."""
    readings = [
        Reading(system_cpu=1.0, own_cpu=0.0, idle_seconds=9999),
        Reading(system_cpu=1.0, own_cpu=0.0, idle_seconds=1),
        Reading(system_cpu=95.0, own_cpu=1.0, idle_seconds=1),
        Reading(idle_seconds=9999, on_battery=True, battery_percent=5.0),
    ]
    for reading in readings:
        budget = governor(FakeSensors(reading), clock).decide(reading)
        assert budget.reason
        assert budget.describe()


def test_duty_cycles_are_ordered_with_the_paces() -> None:
    ordered = sorted(_RANK, key=lambda pace: _RANK[pace])
    duties = [_DUTY[pace] for pace in ordered]
    assert duties == sorted(duties)
    assert _DUTY[Pace.PAUSED] == 0.0
    assert _DUTY[Pace.FULL] == 1.0


# ----------------------------------------------------------------------
# background I/O priority
# ----------------------------------------------------------------------

def test_background_io_follows_the_pace_not_the_scan(
    priority_calls: list[bool], clock: FakeClock
) -> None:
    """Yielding I/O while nobody is there just makes the scan longer."""
    sensors = FakeSensors(Reading(system_cpu=1.0, own_cpu=0.0, idle_seconds=9999))
    gov = governor(sensors, clock, recovery_seconds=0.0)
    gov.budget(force=True)

    sensors.reading = Reading(system_cpu=95.0, own_cpu=1.0, idle_seconds=0)
    gov.budget(force=True)
    assert priority_calls[-1] is True, "throttled, so our reads should queue behind"

    sensors.reading = Reading(system_cpu=1.0, own_cpu=0.0, idle_seconds=9999)
    # Two samples, even at zero recovery: the first observes the calm and
    # starts the clock on it, the second finds it has held. A single quiet
    # reading is never enough to climb.
    gov.budget(force=True)
    clock.advance(60.0)
    gov.budget(force=True)
    assert priority_calls[-1] is False, "nobody to yield to, so take the disk"


@pytest.mark.skipif(os.name != "nt", reason="Windows process background mode")
def test_the_real_background_mode_can_be_entered_and_left() -> None:
    """The ctypes call itself, on the only platform that has it.

    Restored in a finally: leaving the test runner in background mode would
    slow everything after it.
    """
    gov = ThrottleGovernor(sensors=FakeSensors(), clock=FakeClock())
    try:
        _REAL_SET_BACKGROUND_IO(gov, True)
        assert gov._background_io is True
        # Asking twice must be a no-op, not an error: Windows returns
        # ERROR_PROCESS_MODE_ALREADY_BACKGROUND for the second call.
        _REAL_SET_BACKGROUND_IO(gov, True)
        assert gov._background_io is True
    finally:
        _REAL_SET_BACKGROUND_IO(gov, False)
    assert gov._background_io is False


def test_budget_is_immutable() -> None:
    """Workers read this concurrently; nothing may edit one in place."""
    budget = Budget(Pace.FULL, 1.0, "because")
    with pytest.raises(dataclasses.FrozenInstanceError):
        budget.pace = Pace.PAUSED  # type: ignore[misc]
