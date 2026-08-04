"""Background operation: when Sentinel works, and how hard.

Two questions, deliberately in two modules, because they have different
answers and different failure modes.

* :mod:`sentinel.daemon.throttle` — *how hard may we work right now?* Sampled
  continuously, applies to any scan, and its job is to stay under the
  threshold at which a person notices.
* :mod:`sentinel.daemon.scheduler` — *should a scan be running at all?*
  Consulted occasionally, owns the resumable cursor, and its job is to get a
  full scan finished on a machine that is in use every day.

Neither imports the other. The scheduler decides to start something; the
governor paces whatever is running.
"""

from __future__ import annotations

from sentinel.daemon.scheduler import IdleScheduler, ScanCursor
from sentinel.daemon.throttle import Budget, Pace, ThrottleGovernor

__all__ = [
    "Budget",
    "IdleScheduler",
    "Pace",
    "ScanCursor",
    "ThrottleGovernor",
]
