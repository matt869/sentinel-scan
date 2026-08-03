"""Scan progress and the time estimate.

A scan on a spinning disk takes tens of minutes. Forty minutes with no idea
how long is left reads as *frozen*, and people kill it — so the estimate is
not decoration, it is what makes a slow scan survivable.

Two phases, because for the first stretch we genuinely do not know the size
of the job:

**Enumerating.** Walking the tree to find out how many files there are and
how many bytes they hold. No percentage is possible yet, and inventing one
would mean the bar jumps backwards the moment a big directory turns up. This
phase reports a live count instead.

**Scanning.** The totals are known, so the fraction and the estimate are
real.

Three things the estimate does deliberately:

*It measures bytes, not files.* File counts swing wildly — a directory of
2 KB configs and one holding a 4 GB disk image are the same "one file" to a
counter, and an ETA built on that lurches every time the mix changes. Bytes
track the actual work.

*It only rises slowly.* An estimate that jumps from five minutes to twenty
because the scan hit a slow patch destroys confidence in every number the
app shows. This one falls freely but climbs at a bounded rate, so a rough
patch stretches the estimate rather than making it leap.

*It says nothing until it knows something.* The first seconds of a scan are
thread ramp-up and cache warming, and any rate computed from them is wrong.
Until there is enough evidence the estimate is ``None`` and the front end
says "estimating", which is honest and costs nothing.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum

#: Rate is averaged over this many seconds of history. Long enough to ride
#: out one slow file, short enough to notice a genuinely slower region.
RATE_WINDOW = 30.0

#: No estimate before this much of the scan has happened. Both conditions
#: must hold: a fast scan of a huge tree still needs a few seconds of
#: evidence, and a slow scan of a small one needs a meaningful fraction.
MIN_ELAPSED_FOR_ETA = 3.0
MIN_FRACTION_FOR_ETA = 0.01

#: How fast the reported estimate may grow, in seconds per second of wall
#: clock. Below 1.0 the number still visibly counts down while it stretches,
#: so the user never sees the remaining time run away from them.
MAX_ETA_GROWTH = 0.5


class Phase(str, Enum):
    """Which half of the scan is running."""

    ENUMERATING = "enumerating"
    SCANNING = "scanning"
    FINISHED = "finished"


@dataclass(frozen=True, slots=True)
class ProgressSnapshot:
    """An immutable view of where a scan has got to.

    Attributes:
        phase: What the scan is doing now.
        files_done: Files scanned so far.
        files_total: Files found by enumeration; 0 when not yet known.
        bytes_done: Bytes scanned so far.
        bytes_total: Bytes found by enumeration; 0 when not yet known.
        current: Path being worked on, for the scrolling display line.
        elapsed: Seconds since the scan started.
        fraction: Completion in 0-1, or None when the total is unknown.
        eta_seconds: Estimated seconds remaining, or None when not yet
            confident enough to say.
    """

    phase: Phase
    files_done: int = 0
    files_total: int = 0
    bytes_done: int = 0
    bytes_total: int = 0
    current: str = ""
    elapsed: float = 0.0
    fraction: float | None = None
    eta_seconds: float | None = None

    @property
    def is_measurable(self) -> bool:
        """Whether a real progress bar can be drawn."""
        return self.fraction is not None

    def as_payload(self) -> dict[str, object]:
        """Flatten for an event payload."""
        return {
            "phase": self.phase.value,
            "files_scanned": self.files_done,
            "files_total": self.files_total,
            "bytes_scanned": self.bytes_done,
            "bytes_total": self.bytes_total,
            "current": self.current,
            "elapsed": round(self.elapsed, 2),
            "fraction": None if self.fraction is None else round(self.fraction, 4),
            "eta_seconds": None if self.eta_seconds is None else round(self.eta_seconds, 1),
        }


class ProgressTracker:
    """Tracks scan progress and produces the estimate.

    Safe to update from worker threads; every method takes the lock.
    """

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        # Injectable clock so the tests can drive time forwards without
        # sleeping. Anything callable returning seconds will do.
        self._clock = clock
        self._lock = threading.Lock()

        self.phase = Phase.ENUMERATING
        self.files_total = 0
        self.bytes_total = 0
        self._files_done = 0
        self._bytes_done = 0
        self._current = ""

        self._started = self._now()
        self._scan_started: float | None = None
        #: (timestamp, bytes_done) samples inside the rate window.
        self._samples: deque[tuple[float, int]] = deque()
        self._last_eta: float | None = None
        self._last_eta_at: float = 0.0

    def _now(self) -> float:
        return float(self._clock())

    # -- phases --------------------------------------------------------

    def begin_scanning(self, files_total: int = 0, bytes_total: int = 0) -> None:
        """Enter the scanning phase with the totals enumeration produced.

        Zero totals are allowed and simply mean no estimate: enumeration may
        have been skipped or cancelled, and a scan with no bar is far better
        than a bar built on a number we do not have.
        """
        with self._lock:
            self.phase = Phase.SCANNING
            self.files_total = max(0, files_total)
            self.bytes_total = max(0, bytes_total)
            self._scan_started = self._now()
            self._samples.clear()
            self._samples.append((self._scan_started, 0))
            self._last_eta = None

    def finish(self) -> None:
        with self._lock:
            self.phase = Phase.FINISHED

    # -- updates -------------------------------------------------------

    def record_enumerated(self, files: int, total_bytes: int, current: str = "") -> None:
        """Update the live count during enumeration."""
        with self._lock:
            self.files_total = files
            self.bytes_total = total_bytes
            self._current = current

    def record_scanned(self, size: int, current: str = "") -> None:
        """Record one finished file."""
        with self._lock:
            self._files_done += 1
            self._bytes_done += max(0, size)
            if current:
                self._current = current
            self._sample(self._now(), self._bytes_done)

    def _sample(self, now: float, done: int) -> None:
        """Append a rate sample and drop everything outside the window."""
        self._samples.append((now, done))
        cutoff = now - RATE_WINDOW
        # Keep one sample older than the cutoff so the window spans the full
        # duration rather than starting at the first surviving sample.
        while len(self._samples) > 2 and self._samples[1][0] < cutoff:
            self._samples.popleft()

    # -- reading -------------------------------------------------------

    def snapshot(self) -> ProgressSnapshot:
        """Current state, including a freshly computed estimate."""
        with self._lock:
            now = self._now()
            fraction = self._fraction()
            return ProgressSnapshot(
                phase=self.phase,
                files_done=self._files_done,
                files_total=self.files_total,
                bytes_done=self._bytes_done,
                bytes_total=self.bytes_total,
                current=self._current,
                elapsed=now - self._started,
                fraction=fraction,
                eta_seconds=self._eta(now, fraction),
            )

    def _fraction(self) -> float | None:
        """Completion in 0-1, by bytes, or None when it cannot be known."""
        if self.phase is Phase.FINISHED:
            return 1.0
        if self.phase is not Phase.SCANNING or self.bytes_total <= 0:
            return None
        # Enumeration and scanning see the tree at slightly different moments,
        # so the total can be an undercount. Clamp rather than let the bar
        # report 103%.
        return min(self._bytes_done / self.bytes_total, 1.0)

    def _eta(self, now: float, fraction: float | None) -> float | None:
        """Seconds remaining, smoothed and rise-limited, or None."""
        if self.phase is not Phase.SCANNING or fraction is None:
            return None
        if self._scan_started is None:
            return None

        elapsed = now - self._scan_started
        if elapsed < MIN_ELAPSED_FOR_ETA or fraction < MIN_FRACTION_FOR_ETA:
            return None

        rate = self._rate(now)
        if rate <= 0:
            return self._last_eta

        remaining_bytes = max(self.bytes_total - self._bytes_done, 0)
        raw = remaining_bytes / rate

        capped = raw
        if self._last_eta is not None:
            # Falling is free; rising is rationed. Allowance is measured
            # against wall clock so a long gap between reads can still let
            # the estimate recover a realistic value.
            since = max(now - self._last_eta_at, 0.0)
            ceiling = self._last_eta + since * MAX_ETA_GROWTH
            capped = min(raw, ceiling)

        self._last_eta = capped
        self._last_eta_at = now
        return capped

    def _rate(self, now: float) -> float:
        """Bytes per second over the rate window."""
        if len(self._samples) < 2:
            return 0.0
        start_time, start_bytes = self._samples[0]
        span = now - start_time
        if span <= 0:
            return 0.0
        return (self._bytes_done - start_bytes) / span


def format_eta(seconds: float | None) -> str:
    """Render an estimate the way a person would say it.

    Deliberately vague. "about 12 minutes" is a promise you can keep;
    "11m 43s" is a promise you cannot, and being caught out on the seconds
    costs more trust than the precision ever bought.

    >>> format_eta(None)
    'estimating…'
    >>> format_eta(8)
    'a few seconds'
    >>> format_eta(700)
    'about 12 minutes'
    """
    if seconds is None:
        return "estimating…"
    if seconds < 15:
        return "a few seconds"
    if seconds < 90:
        return "under a minute" if seconds < 60 else "about a minute"

    minutes = round(seconds / 60.0)
    if minutes < 60:
        return f"about {minutes} minutes"

    hours, remainder = divmod(minutes, 60)
    if remainder < 8:
        return f"about {hours} hour{'s' if hours > 1 else ''}"
    if remainder > 52:
        return f"about {hours + 1} hours"
    return f"about {hours}h {remainder}m"
