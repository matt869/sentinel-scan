"""How much of this machine the scan is allowed to take, right now.

The product promise is that Sentinel stays out of the way. On the hardware
this is built for — 4 GB and a spinning disk — that promise is not kept by
being efficient. A scan that reads every file on a rotating platter will
saturate that disk however tight the code is, and the user will feel it in
every window they open. It is kept by *not running at full speed while
somebody is using the computer*.

So the engine asks this module between files: how long should I wait? The
answer is a duty cycle — the fraction of wall-clock time the scan may spend
working — and the governor derives it from what the machine is doing.

Three decisions here are load-bearing.

**Sleeping between files is not enough on its own; on Windows we also drop
into background I/O priority.** A sleep gives the disk back only in the gaps.
While one of our reads is actually queued it competes with the user's reads
on equal terms, and the read that makes them wait is the one already in
flight. ``PROCESS_MODE_BACKGROUND_BEGIN`` puts our I/O behind theirs in the
scheduler, which is the part a sleep cannot do. Neither mechanism replaces
the other: priority alone still lets us use the whole disk when nobody else
wants it, which is exactly the case where a duty cycle is what saves the
user's afternoon.

**Our own CPU use is subtracted before deciding the machine is busy.** The
obvious implementation reads system-wide CPU, sees 60%, and backs off —
except that 55 of those points are us. Then we are idle, so the load drops,
so we speed up, so the load rises, so we back off. That oscillation is not a
tuning problem to be smoothed away; it is a feedback loop caused by measuring
our own output as if it were someone else's input.

**Backing off is immediate, recovering is slow.** They are not symmetric
because the costs are not. Being slow to back off is felt directly, as a
computer that stutters when you sit down at it. Being slow to recover costs
only scan throughput at a moment when nobody is watching. Anything that
recovers as fast as it backs off will flap across the threshold and produce a
stutter every few seconds, which is worse than simply running slowly.
"""

from __future__ import annotations

import os
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum

from sentinel.core.logger import get_logger
from sentinel.system import idle as idle_probe

log = get_logger(__name__)

try:
    import psutil

    PSUTIL_AVAILABLE = True
except ImportError:  # pragma: no cover - depends on the environment
    psutil = None  # type: ignore[assignment]
    PSUTIL_AVAILABLE = False


class Pace(str, Enum):
    """How hard the scan may work."""

    FULL = "full"
    HALF = "half"
    BACKGROUND = "background"
    PAUSED = "paused"


#: Explicit ordering, least to most generous. :class:`Pace` subclasses ``str``,
#: so any comparison left to the default is lexicographic — under which
#: ``"background" < "full"`` is true by luck and ``"half" < "full"`` is false,
#: and the hysteresis below silently inverts for one of the four values. The
#: same trap as ``Severity`` in :mod:`sentinel.engine.verdict`, which defines
#: all four comparison operators for the same reason.
_RANK: dict[Pace, int] = {
    Pace.PAUSED: 0,
    Pace.BACKGROUND: 1,
    Pace.HALF: 2,
    Pace.FULL: 3,
}

#: Share of wall clock the scan may spend working, per pace.
_DUTY: dict[Pace, float] = {
    Pace.PAUSED: 0.0,
    Pace.BACKGROUND: 0.15,
    Pace.HALF: 0.5,
    Pace.FULL: 1.0,
}

#: Machine-wide CPU use, excluding our own, above which someone else clearly
#: wants this computer.
BUSY_CPU_PERCENT = 35.0

#: No input for this long and we assume nobody is at the keyboard.
DEFAULT_AWAY_AFTER = 300.0

#: How long the machine must stay calm before the pace is allowed to rise.
DEFAULT_RECOVERY_SECONDS = 30.0

#: Minimum gap between samples. Below this the readings are noise — psutil
#: needs a real interval to diff against — and above it the governor stops
#: noticing a user who has just sat down.
SAMPLE_INTERVAL = 2.0

#: Longest single pause between files. The duty cycle is a target, not a
#: guarantee: a file that takes twenty seconds to scan cannot be paced to 15%
#: without stalling the pipeline for two minutes, and a scan that appears to
#: have hung is a scan the user kills. Files that expensive are rare enough
#: that capping here costs little and protects the common case.
MAX_PAUSE_SECONDS = 10.0

#: Below this charge, stop entirely rather than merely slowing down. A scan
#: is never worth being the reason a laptop died before it was plugged in.
CRITICAL_BATTERY_PERCENT = 20.0


@dataclass(frozen=True, slots=True)
class Budget:
    """What the scan may do, and why — the reason is shown to the user."""

    pace: Pace
    duty_cycle: float
    reason: str

    @property
    def running(self) -> bool:
        return self.duty_cycle > 0.0

    def describe(self) -> str:
        """The line shown in the flyout, beside the resource line."""
        if self.pace is Pace.PAUSED:
            return f"Paused — {self.reason}"
        if self.pace is Pace.FULL:
            return f"Scanning at full speed — {self.reason}"
        return f"Scanning slowly — {self.reason}"


@dataclass(frozen=True, slots=True)
class Reading:
    """One sample of the world. Separated out so tests can supply their own."""

    #: Machine-wide CPU use as a percentage of all cores, us included.
    system_cpu: float | None = None
    #: This process's CPU use, as a percentage of all cores.
    own_cpu: float | None = None
    #: Seconds since the last input, or None if this platform cannot say.
    idle_seconds: float | None = None
    #: True on battery, False on mains, None if there is no battery.
    on_battery: bool | None = None
    battery_percent: float | None = None

    @property
    def foreign_cpu(self) -> float | None:
        """System CPU with our own contribution removed.

        This is the number that answers "does somebody else want this
        machine?", and it is the only one the busy check may use.
        """
        if self.system_cpu is None:
            return None
        if self.own_cpu is None:
            return self.system_cpu
        return max(0.0, self.system_cpu - self.own_cpu)


class _Sensors:
    """Reads the machine. One instance per governor."""

    def __init__(self) -> None:
        self._cores = os.cpu_count() or 1
        self._process = None
        if PSUTIL_AVAILABLE:
            try:
                self._process = psutil.Process()
                # Both counters return 0.0 on their first call — they have no
                # previous sample to diff against. Priming them here moves
                # that zero to construction time, so it is spent before any
                # scan is running rather than on the governor's first real
                # decision. A budget() called immediately after construction
                # still sees a short interval and so a low number; that lands
                # on HALF, which is the careful answer, and the sample two
                # seconds later is real.
                self._process.cpu_percent(None)
                psutil.cpu_percent(None)
            except Exception as exc:  # pragma: no cover - platform dependent
                log.debug("cannot read this process: %s", exc)
                self._process = None

    def read(self) -> Reading:
        return Reading(
            system_cpu=self._system_cpu(),
            own_cpu=self._own_cpu(),
            idle_seconds=idle_probe.idle_seconds(),
            on_battery=self._on_battery(),
            battery_percent=self._battery_percent(),
        )

    def _system_cpu(self) -> float | None:
        if not PSUTIL_AVAILABLE:
            return None
        try:
            return float(psutil.cpu_percent(None))
        except Exception:
            return None

    def _own_cpu(self) -> float | None:
        """Our CPU use as a share of the *whole machine*.

        ``Process.cpu_percent`` is a share of one core, so 100.0 on an
        eight-core box means one saturated core. Comparing that directly
        against ``psutil.cpu_percent``, which is a share of all eight, would
        overstate our contribution eightfold and subtract the user's work out
        of the busy check along with our own.
        """
        if self._process is None:
            return None
        try:
            return float(self._process.cpu_percent(None)) / self._cores
        except Exception:
            return None

    def _on_battery(self) -> bool | None:
        if not PSUTIL_AVAILABLE:
            return None
        try:
            battery = psutil.sensors_battery()
        except Exception:
            return None
        return None if battery is None else not battery.power_plugged

    def _battery_percent(self) -> float | None:
        if not PSUTIL_AVAILABLE:
            return None
        try:
            battery = psutil.sensors_battery()
        except Exception:
            return None
        return None if battery is None else float(battery.percent)


class ThrottleGovernor:
    """Decides the pace, and paces the workers that ask it to.

    Thread-safe: the scan calls :meth:`wait_turn` from every worker while the
    GUI reads :meth:`budget` for the flyout.
    """

    def __init__(
        self,
        *,
        away_after: float = DEFAULT_AWAY_AFTER,
        busy_cpu: float = BUSY_CPU_PERCENT,
        recovery_seconds: float = DEFAULT_RECOVERY_SECONDS,
        sample_interval: float = SAMPLE_INTERVAL,
        pause_on_battery: bool = True,
        sensors: _Sensors | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.away_after = away_after
        self.busy_cpu = busy_cpu
        self.recovery_seconds = recovery_seconds
        self.sample_interval = sample_interval
        self.pause_on_battery = pause_on_battery

        self._sensors = sensors if sensors is not None else _Sensors()
        self._clock = clock or time.monotonic
        self._lock = threading.RLock()
        #: Set whenever the pace changes, so a worker parked in a long pause
        #: wakes as soon as the user leaves rather than serving out a sleep
        #: chosen under conditions that no longer hold.
        self._wake = threading.Event()

        self._budget = Budget(Pace.FULL, 1.0, "no measurement yet")
        self._sampled_at: float | None = None
        self._calm_since: float | None = None
        self._manual_pause = False
        self._background_io = False

    # -- public API ----------------------------------------------------

    def budget(self, *, force: bool = False, settle: bool = True) -> Budget:
        """The current budget, re-sampling at most every *sample_interval*.

        *settle* is False only for a change the user made themselves. Somebody
        who has just clicked Resume is not a machine-load reading to be
        smoothed; making them wait out the recovery delay for a decision they
        took explicitly reads as a button that does not work.
        """
        with self._lock:
            now = self._clock()
            if (
                not force
                and self._sampled_at is not None
                and now - self._sampled_at < self.sample_interval
            ):
                return self._budget

            self._sampled_at = now
            try:
                reading = self._sensors.read()
            except Exception as exc:  # pragma: no cover - sensor bug
                log.debug("cannot sample the machine: %s", exc)
                return self._budget

            candidate = self.decide(reading)
            settled = self._settle(candidate, now) if settle else candidate
            if not settle:
                self._calm_since = None
            self._install(settled)
            return settled

    def wait_turn(self, work_seconds: float) -> float:
        """Pause after a unit of work. Returns the seconds actually slept.

        Called by a scan worker once per file with the time that file took.
        Deriving the pause from the measured cost is what makes one duty
        cycle correct for both a 2 KB config and a 400 MB installer: pausing
        a fixed amount between files would throttle a directory of small
        files into uselessness while barely touching a directory of large
        ones.
        """
        budget = self.budget()

        if budget.duty_cycle >= 1.0:
            return 0.0

        if budget.duty_cycle <= 0.0:
            return self._park()

        target = work_seconds * (1.0 / budget.duty_cycle - 1.0)
        return self._sleep(min(target, MAX_PAUSE_SECONDS))

    def pause(self) -> None:
        """Stop the scan working at all, until :meth:`resume`."""
        with self._lock:
            self._manual_pause = True
        self.budget(force=True)

    def resume(self) -> None:
        with self._lock:
            self._manual_pause = False
            self._calm_since = None
        self.budget(force=True, settle=False)

    @property
    def paused(self) -> bool:
        with self._lock:
            return self._manual_pause

    def close(self) -> None:
        """Hand back background I/O priority and release parked workers."""
        self._set_background_io(False)
        self._wake.set()

    def __enter__(self) -> ThrottleGovernor:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    # -- the decision --------------------------------------------------

    def decide(self, reading: Reading) -> Budget:
        """Map a :class:`Reading` onto a :class:`Budget`. Pure, so it tests.

        Order matters: the checks run cheapest-and-most-absolute first, and
        each one that fires ends the decision. Battery outranks user presence
        because a laptop on battery has a hard limit that being alone in the
        room does not lift.
        """
        if self._manual_pause:
            return Budget(Pace.PAUSED, 0.0, "you paused it")

        if reading.on_battery and self.pause_on_battery:
            percent = reading.battery_percent
            if percent is not None and percent <= CRITICAL_BATTERY_PERCENT:
                return Budget(
                    Pace.PAUSED, 0.0,
                    f"running on battery ({percent:.0f}%)",
                )
            return Budget(
                Pace.BACKGROUND, _DUTY[Pace.BACKGROUND], "running on battery"
            )

        # Unknown idle time counts as present. Starting a full-disk scan
        # under someone who is working is the one mistake that gets the
        # product uninstalled, so the platform that cannot tell gets the
        # careful answer rather than the fast one.
        away = (
            reading.idle_seconds is not None
            and reading.idle_seconds >= self.away_after
        )
        if away:
            return Budget(Pace.FULL, _DUTY[Pace.FULL], "nobody is using this computer")

        foreign = reading.foreign_cpu
        if foreign is not None and foreign >= self.busy_cpu:
            return Budget(
                Pace.BACKGROUND, _DUTY[Pace.BACKGROUND],
                "you're using this computer for something else",
            )

        return Budget(Pace.HALF, _DUTY[Pace.HALF], "you're using this computer")

    def _settle(self, candidate: Budget, now: float) -> Budget:
        """Apply hysteresis: drop immediately, climb only after calm.

        A candidate at or below the current pace is adopted at once. A more
        generous one has to hold for ``recovery_seconds`` first, so a user
        who pauses between keystrokes does not make the scan lurch back to
        full speed and then off again a second later.
        """
        current = self._budget
        if _RANK[candidate.pace] <= _RANK[current.pace]:
            self._calm_since = None
            return candidate

        if self._calm_since is None:
            self._calm_since = now
            return current

        if now - self._calm_since >= self.recovery_seconds:
            self._calm_since = None
            return candidate
        return current

    def _install(self, budget: Budget) -> None:
        if budget == self._budget:
            return
        previous = self._budget
        self._budget = budget
        log.debug(
            "pace %s -> %s (%s)", previous.pace.value, budget.pace.value, budget.reason
        )
        # Background I/O priority tracks the pace rather than being switched
        # on for the whole scan: while nobody is at the machine there is no
        # one to yield to, and yielding anyway just makes the scan longer.
        self._set_background_io(_RANK[budget.pace] <= _RANK[Pace.BACKGROUND])
        self._wake.set()

    # -- sleeping ------------------------------------------------------

    def _sleep(self, seconds: float) -> float:
        """Sleep, but wake early if the pace changes underneath us."""
        if seconds <= 0:
            return 0.0
        started = self._clock()
        self._wake.clear()
        self._wake.wait(seconds)
        return self._clock() - started

    def _park(self) -> float:
        """Wait out a pause, rechecking periodically.

        Bounded rather than waiting on the event alone: the condition that
        caused the pause — a battery, a busy machine — changes without
        anything calling us, so a parked worker has to come back and look.
        """
        started = self._clock()
        while True:
            self._wake.clear()
            self._wake.wait(self.sample_interval)
            if self.budget(force=True).running:
                return self._clock() - started

    # -- Windows background I/O ----------------------------------------

    def _set_background_io(self, on: bool) -> None:
        """Enter or leave Windows' background processing mode.

        This lowers I/O *and* memory priority for the whole process, which is
        the point: it is the only lever that makes our reads queue behind the
        user's. It is a no-op everywhere else — Linux has ``ionice``, which
        needs a syscall per thread and privileges we do not have unelevated,
        and macOS has no equivalent a normal process may set for itself.
        """
        if os.name != "nt" or on == self._background_io:
            return

        try:
            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.GetCurrentProcess.restype = wintypes.HANDLE
            kernel32.SetPriorityClass.argtypes = [wintypes.HANDLE, wintypes.DWORD]

            #: PROCESS_MODE_BACKGROUND_BEGIN / _END
            mode = 0x00100000 if on else 0x00200000
            if not kernel32.SetPriorityClass(kernel32.GetCurrentProcess(), mode):
                error = ctypes.get_last_error()
                # 402 ERROR_PROCESS_MODE_ALREADY_BACKGROUND
                # 403 ERROR_PROCESS_MODE_NOT_BACKGROUND
                # Both mean the process is already in the state being asked
                # for, which is success as far as the caller is concerned.
                if error not in (402, 403):
                    log.debug("cannot change background mode: error %d", error)
                    return
            self._background_io = on
        except Exception as exc:  # pragma: no cover - platform dependent
            log.debug("cannot change background mode: %s", exc)
