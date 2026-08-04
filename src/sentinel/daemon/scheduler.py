"""Deciding when a background scan runs, and making sure one ever finishes.

The scan this schedules is the full-disk one: tens of minutes on the hardware
this product targets, and on a spinning disk sometimes an hour and a half. It
has to happen, because a scanner that only runs when the user remembers to
click it is a scanner that runs twice. And it must never be the reason
somebody's computer is slow.

Those two facts produce every decision below.

**Not a fixed hour.** The obvious design is a nightly scan at 3 a.m. It fails
on exactly the machines this is for: the desktop that gets switched off at the
wall, and the laptop that is shut in a bag. A schedule anchored to a clock
runs on machines that are awake at that clock, which is a description of
servers, not of the people here. So the trigger is *idleness*, and the clock
only enforces a minimum gap.

**Interrupted is the normal case, not the error case.** On a machine used
every day, a scan that needs ninety minutes of idleness in one unbroken block
may never get it. If an interrupted scan restarts from the beginning, the
first fifth of the disk is scanned over and over and the last four fifths are
never looked at — and every one of those attempts costs the user real time.
So progress is checkpointed and the next attempt resumes. The unit of
completion is the whole disk, eventually, not any single sitting.

**Backing off when the user keeps coming back.** Somebody who steps away for
six minutes at a time will, under a fixed five-minute threshold, be
interrupted by a starting scan over and over. Retrying at the same threshold
is how a program becomes the thing you disable. After repeated short
interruptions the required idle time goes up, so the software adapts to the
person rather than the person to the software.
"""

from __future__ import annotations

import contextlib
import json
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from sentinel.core.logger import get_logger
from sentinel.system.idle import IdleTracker

log = get_logger(__name__)

#: kv keys. The cursor is in the database rather than in memory because its
#: whole purpose is to survive something — a reboot, a crash, a user who
#: closed the app.
CURSOR_KEY = "idle.cursor"
LAST_COMPLETED_KEY = "idle.last_completed"
INTERRUPTIONS_KEY = "idle.interruptions"

#: No input for this long before a scan may start.
DEFAULT_AWAY_AFTER = 300.0

#: Minimum gap between completed scans. Deliberately under 24 hours: at
#: exactly 24 the window drifts later by however long the scan took plus
#: however long it waited for idleness, so a machine used on a daily rhythm
#: walks its scan out of the quiet hours and then starts skipping days. At 20
#: it re-anchors to whenever the machine is actually free.
DEFAULT_INTERVAL_HOURS = 20.0

#: How often the loop looks at the world. This is what bounds how long the
#: user waits after touching the mouse before the scan gets out of the way,
#: so it is a responsiveness number, not a housekeeping one.
DEFAULT_POLL_SECONDS = 2.0

#: A checkpoint older than this describes a filesystem that has moved on.
#: Resuming into the middle of a tree that has been reorganised skips
#: whatever moved above the cursor, so past this age we start again.
CURSOR_MAX_AGE_SECONDS = 7 * 24 * 3600

#: An attempt cut short sooner than this counts as the user being disturbed
#: rather than as ordinary progress.
SHORT_RUN_SECONDS = 120.0

#: Consecutive short runs before the idle threshold is widened.
INTERRUPTIONS_BEFORE_BACKOFF = 3

#: Multiplier and ceiling applied when backing off.
BACKOFF_FACTOR = 2.0
MAX_AWAY_AFTER = 3600.0


@dataclass(frozen=True, slots=True)
class ScanCursor:
    """Where the last attempt got to, and what it was scanning."""

    roots: tuple[str, ...]
    #: Path most recently finished. The next attempt skips everything that
    #: sorts at or before this within the same roots.
    last_path: str = ""
    files_done: int = 0
    #: When the *series* of attempts began, not the last one. Age is measured
    #: from here because that is what tells us the tree has moved on.
    started_at: float = field(default_factory=time.time)

    def to_json(self) -> str:
        return json.dumps(
            {
                "roots": list(self.roots),
                "last_path": self.last_path,
                "files_done": self.files_done,
                "started_at": self.started_at,
            }
        )

    @classmethod
    def from_json(cls, raw: str) -> ScanCursor | None:
        """Parse a stored cursor, or None if it is unusable.

        Never raises. A corrupt checkpoint must cost at most one restarted
        scan; it must not stop scanning from happening.
        """
        try:
            data = json.loads(raw)
            roots = tuple(str(r) for r in data["roots"])
            if not roots:
                return None
            return cls(
                roots=roots,
                last_path=str(data.get("last_path", "")),
                files_done=int(data.get("files_done", 0)),
                started_at=float(data.get("started_at", 0.0)),
            )
        except Exception as exc:
            log.debug("discarding an unreadable scan cursor: %s", exc)
            return None

    def matches(self, roots: Sequence[str]) -> bool:
        """Whether this cursor describes the roots we are about to scan."""
        return self.roots == tuple(roots)

    def is_stale(self, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        return now - self.started_at > CURSOR_MAX_AGE_SECONDS


@dataclass(frozen=True, slots=True)
class ScanOutcome:
    """What an attempt achieved."""

    completed: bool
    last_path: str = ""
    files_done: int = 0


#: ``(roots, resume_from, stop) -> outcome``. The callback must return
#: promptly once *stop* is set, and report where it got to either way.
RunScan = Callable[[Sequence[str], ScanCursor | None, threading.Event], ScanOutcome]


class IdleScheduler:
    """Runs *run_scan* when nobody is using the machine, and resumes it."""

    def __init__(
        self,
        run_scan: RunScan,
        roots: Sequence[str],
        *,
        db: object | None = None,
        away_after: float = DEFAULT_AWAY_AFTER,
        interval_hours: float = DEFAULT_INTERVAL_HOURS,
        poll_seconds: float = DEFAULT_POLL_SECONDS,
        clock: Callable[[], float] | None = None,
        tracker: IdleTracker | None = None,
    ) -> None:
        self.run_scan = run_scan
        self.roots = tuple(roots)
        self.db = db
        self.base_away_after = away_after
        self.interval_seconds = interval_hours * 3600.0
        self.poll_seconds = poll_seconds

        self._clock = clock or time.time
        self._tracker = tracker or IdleTracker(away_after=away_after)
        self._stop = threading.Event()
        #: Set for the duration of one attempt, and cleared when it ends.
        #: Distinct from ``_stop``, which ends the scheduler itself.
        self._abort = threading.Event()
        self._thread: threading.Thread | None = None
        self._scan_thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._running = False

    # -- lifecycle -----------------------------------------------------

    def start(self) -> None:
        """Begin watching. Returns immediately."""
        if self._thread is not None:
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop, name="sentinel-idle", daemon=True
        )
        self._thread.start()
        log.debug(
            "idle scheduler watching %d root(s), idle threshold %.0fs",
            len(self.roots), self.away_after,
        )

    def stop(self, timeout: float = 10.0) -> None:
        """Stop watching and abort any attempt in flight."""
        self._stop.set()
        self._abort.set()
        for attribute in ("_thread", "_scan_thread"):
            thread = getattr(self, attribute)
            setattr(self, attribute, None)
            if thread is not None:
                thread.join(timeout=timeout)

    def __enter__(self) -> IdleScheduler:
        self.start()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.stop()

    @property
    def scanning(self) -> bool:
        with self._lock:
            return self._running

    # -- policy --------------------------------------------------------

    @property
    def away_after(self) -> float:
        """Required idle time, widened if this user keeps being interrupted."""
        strikes = self._interruptions()
        if strikes < INTERRUPTIONS_BEFORE_BACKOFF:
            return self.base_away_after
        extra = strikes - INTERRUPTIONS_BEFORE_BACKOFF + 1
        return min(self.base_away_after * BACKOFF_FACTOR * extra, MAX_AWAY_AFTER)

    def due(self, now: float | None = None) -> bool:
        """Whether enough time has passed since the last *completed* scan.

        Measured from completion, not from the last attempt: attempts that
        were interrupted did not scan the disk, and treating them as if they
        had is how a machine that is never idle for long ends up reporting
        itself scanned without ever having been.
        """
        now = self._clock() if now is None else now
        last = self._get_float(LAST_COMPLETED_KEY)
        if last is None:
            return True
        # A timestamp in the future means the clock moved backwards — a
        # correction, a timezone fix, a dead CMOS battery. Treat it as
        # unknown rather than refusing to scan until the date catches up,
        # which on a machine with a flat battery is never.
        if last > now:
            log.debug("last-completed timestamp is in the future; ignoring it")
            return True
        return now - last >= self.interval_seconds

    def should_start(self, now: float | None = None) -> bool:
        """Every condition for starting an attempt, in one place."""
        if self._stop.is_set() or self.scanning:
            return False
        if not self.roots:
            return False
        if not self.due(now):
            return False
        return self._tracker.away

    # -- the loop ------------------------------------------------------

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self._tick()
            except Exception:
                # A scheduler thread that dies leaves a product that silently
                # never scans again, and nothing about the UI would show it.
                log.exception("idle scheduler tick failed")
            self._stop.wait(self.poll_seconds)

    def _tick(self) -> None:
        self._tracker.away_after = self.away_after
        came_back = self._tracker.poll()

        if came_back and self.scanning:
            log.info("the user came back; stopping the background scan")
            self._abort.set()
            return

        if self.should_start():
            self._start_attempt()

    def _start_attempt(self) -> None:
        """Launch an attempt on its own thread.

        Not run inline. The loop's other job is noticing that the user has
        come back, and a scan runs for tens of minutes — calling it from the
        tick would block the very watcher whose reaction time is the whole
        point of polling every two seconds. The scan would then run to
        completion under someone who had sat back down.
        """
        with self._lock:
            if self._running:
                return
            # Claimed before the thread starts, so the next tick — which may
            # arrive before the thread has been scheduled — does not start a
            # second scan over the top of this one.
            self._running = True

        self._abort.clear()
        self._scan_thread = threading.Thread(
            target=self._attempt, name="sentinel-idle-scan", daemon=True
        )
        self._scan_thread.start()

    def _attempt(self) -> None:
        """Run one attempt to completion, interruption, or failure."""
        resume = self._load_cursor()
        started = self._clock()

        with self._lock:
            self._running = True

        try:
            outcome = self.run_scan(self.roots, resume, self._abort)
        except Exception:
            log.exception("the background scan failed")
            # The cursor is deliberately left alone. A scan that crashed at
            # an unknown point has not invalidated what the previous one
            # established, and discarding the checkpoint here would restart
            # from zero every time a single unreadable file crashed a run.
            return
        finally:
            with self._lock:
                self._running = False
            self._abort.clear()

        self._record(outcome, resume, elapsed=self._clock() - started)

    def _record(
        self, outcome: ScanOutcome, resume: ScanCursor | None, *, elapsed: float
    ) -> None:
        if outcome.completed:
            self._set(LAST_COMPLETED_KEY, str(self._clock()))
            self._set(CURSOR_KEY, "")
            self._set(INTERRUPTIONS_KEY, "0")
            log.info(
                "background scan finished: %d files in %.0fs",
                outcome.files_done, elapsed,
            )
            return

        cursor = ScanCursor(
            roots=self.roots,
            last_path=outcome.last_path,
            files_done=outcome.files_done,
            # Carry the original start forward so the checkpoint ages out of
            # its own accord. Resetting it here would make a cursor that is
            # resumed daily immortal, and it would be describing a filesystem
            # from a fortnight ago.
            started_at=resume.started_at if resume else self._clock(),
        )
        self._set(CURSOR_KEY, cursor.to_json())

        if elapsed < SHORT_RUN_SECONDS:
            strikes = self._interruptions() + 1
            self._set(INTERRUPTIONS_KEY, str(strikes))
            log.debug(
                "background scan interrupted after %.0fs (%d in a row)",
                elapsed, strikes,
            )
        else:
            # A long run that was interrupted is the design working, not the
            # threshold being wrong, so it does not count against it.
            self._set(INTERRUPTIONS_KEY, "0")
            log.info(
                "background scan paused after %.0fs at %s",
                elapsed, outcome.last_path or "the start",
            )

    def _load_cursor(self) -> ScanCursor | None:
        raw = self._get(CURSOR_KEY)
        if not raw:
            return None
        cursor = ScanCursor.from_json(raw)
        if cursor is None:
            return None
        if not cursor.matches(self.roots):
            log.debug("the stored cursor is for different roots; starting over")
            return None
        if cursor.is_stale(self._clock()):
            log.info("the stored scan checkpoint is too old to trust; starting over")
            return None
        return cursor

    # -- storage -------------------------------------------------------

    def _interruptions(self) -> int:
        raw = self._get(INTERRUPTIONS_KEY)
        try:
            return max(0, int(raw)) if raw else 0
        except ValueError:
            return 0

    def _get_float(self, key: str) -> float | None:
        raw = self._get(key)
        if not raw:
            return None
        try:
            return float(raw)
        except ValueError:
            return None

    def _get(self, key: str) -> str | None:
        getter = getattr(self.db, "get_setting", None)
        if getter is None:
            return None
        with contextlib.suppress(Exception):
            return getter(key)
        return None

    def _set(self, key: str, value: str) -> None:
        setter = getattr(self.db, "set_setting", None)
        if setter is None:
            return
        with contextlib.suppress(Exception):
            setter(key, value)
