#!/usr/bin/env python3
"""Soak the background daemon and report anything that grows.

The daemon is the part of this application that runs for weeks without being
restarted, so it is the part where a small leak becomes a real one. A test
that runs for five seconds cannot see that; a slope only shows up over time.

Time is *compressed* rather than waited out. A leak is per-tick, not per
second — the scheduler leaks or does not leak once per poll, whatever the
poll interval — so the loops are driven far faster than they run in
production and the ticks are counted. A few minutes of wall clock then covers
more than a day of operation, and the numbers are reported in the units that
matter: real hours at the real 2-second poll.

Two modes, because the daemon has two very different lives:

``--idle`` (the default)
    What it does almost all of the time: tick, decide not to scan, sample the
    machine, decide nothing changed. This is the eight-hour idle soak.

``--churn``
    The rare-but-repeated path: governor lifecycles with workers parking and
    being released, and scheduler attempts each on a fresh thread. This is
    where a thread or a database connection would be left behind.

Usage::

    python scripts/soak_daemon.py                    # ~8 idle hours, 4 min
    python scripts/soak_daemon.py --seconds 900      # ~32 idle hours
    python scripts/soak_daemon.py --churn --cycles 300
"""

from __future__ import annotations

import argparse
import gc
import os
import shutil
import sqlite3
import sys
import tempfile
import threading
import time

#: The scheduler's real poll interval. Ticks are reported as hours at this
#: rate, because "15,000 ticks" means nothing and "8.7 hours" does.
REAL_POLL_SECONDS = 2.0

#: Ticks in an eight-hour idle stretch, at the real poll interval.
TICKS_PER_EIGHT_HOURS = int(8 * 3600 / REAL_POLL_SECONDS)


def _prepare_data_dir() -> str:
    root = os.path.join(tempfile.gettempdir(), "sentinel-soak")
    shutil.rmtree(root, ignore_errors=True)
    os.environ["SENTINEL_DATA_DIR"] = root
    return root


def _rss_mb() -> float:
    gc.collect()
    import psutil

    return psutil.Process().memory_info().rss / 1024**2


def _open_connections() -> int:
    gc.collect()
    return sum(1 for o in gc.get_objects() if isinstance(o, sqlite3.Connection))


# ----------------------------------------------------------------------
# idle
# ----------------------------------------------------------------------

def soak_idle(seconds: float) -> bool:
    """Tick the scheduler and sample the governor, changing nothing."""
    from sentinel.core.config import load_config
    from sentinel.core.db import Database
    from sentinel.daemon import IdleScheduler
    from sentinel.daemon.throttle import Reading, ThrottleGovernor
    from sentinel.system import idle as idle_probe

    config = load_config()
    config.paths.ensure()
    db = Database(config.paths.db_file)

    # The steady state: nobody at the machine, and a scan not due for hours.
    idle_probe.idle_seconds = lambda: 9999.0
    db.set_setting("idle.last_completed", str(time.time()))

    ticks = {"n": 0}

    def counted(original):
        def poll(now=None):
            ticks["n"] += 1
            return original(now)
        return poll

    def never_runs(roots, resume, stopping):
        raise AssertionError("a scan started during an idle soak")

    sched = IdleScheduler(never_runs, roots=["/nonexistent"], db=db,
                          away_after=300.0, poll_seconds=0.0005)
    sched._tracker.poll = counted(sched._tracker.poll)  # type: ignore[method-assign]

    reading = Reading(system_cpu=3.0, own_cpu=1.0, idle_seconds=9999)

    class Steady:
        reads = 0

        def read(self):
            Steady.reads += 1
            return reading

    governor = ThrottleGovernor(sensors=Steady(), sample_interval=0.0005)
    governor._set_background_io = lambda on: None  # type: ignore[assignment]

    start_rss, start_threads = _rss_mb(), threading.active_count()
    print(f"start   rss {start_rss:6.2f} MB   threads {start_threads}")

    stop = threading.Event()

    def sample_governor() -> None:
        while not stop.is_set():
            governor.budget()
            time.sleep(0.0005)

    sampler = threading.Thread(target=sample_governor, daemon=True)
    sched.start()
    sampler.start()

    marks: list[tuple[int, float]] = []
    began = time.monotonic()
    while time.monotonic() - began < seconds:
        time.sleep(seconds / 8)
        rss = _rss_mb()
        marks.append((ticks["n"], rss))
        hours = ticks["n"] * REAL_POLL_SECONDS / 3600
        print(f"  ticks {ticks['n']:>9,}  ({hours:>6.1f} real hours)"
              f"   rss {rss:6.2f} MB   threads {threading.active_count()}")

    stop.set()
    sampler.join(timeout=5)
    sched.stop(timeout=10)
    governor.close()

    end_rss, end_threads = _rss_mb(), threading.active_count()
    total = ticks["n"]

    print("\n" + "=" * 68)
    print(f"  scheduler ticks    {total:>11,}  = "
          f"{total * REAL_POLL_SECONDS / 3600:.1f} hours at the real poll")
    print(f"  governor samples   {Steady.reads:>11,}")
    print(f"  rss                {start_rss:>11.2f} -> {end_rss:.2f} MB "
          f"({end_rss - start_rss:+.2f})")
    print(f"  threads            {start_threads:>11} -> {end_threads}")

    # The second half only. The first half includes allocator warm-up, which
    # is not a leak and would otherwise be reported as one.
    half = len(marks) // 2
    ok = True
    if len(marks) > 2 and marks[-1][0] > marks[half][0]:
        rate = (marks[-1][1] - marks[half][1]) / (marks[-1][0] - marks[half][0])
        per_soak = rate * TICKS_PER_EIGHT_HOURS
        print(f"  steady-state rate  {per_soak:>11.3f} MB per 8 idle hours")
        ok = per_soak < 5.0
    ok = ok and end_threads <= start_threads + 1
    print("=" * 68)
    db.close()
    return ok


# ----------------------------------------------------------------------
# churn
# ----------------------------------------------------------------------

def soak_churn(cycles: int) -> bool:
    """Build and tear down governors and scan attempts, over and over."""
    from sentinel.core.config import load_config
    from sentinel.core.db import Database
    from sentinel.core.events import EventBus
    from sentinel.daemon import IdleScheduler, ScanOutcome, ThrottleGovernor
    from sentinel.daemon.throttle import Reading
    from sentinel.engine.scanner import Scanner
    from sentinel.system import idle as idle_probe

    config = load_config()
    config.paths.ensure()

    tree = os.path.join(tempfile.gettempdir(), "sentinel-soak-tree")
    shutil.rmtree(tree, ignore_errors=True)
    os.makedirs(tree)
    for i in range(30):
        with open(os.path.join(tree, f"f{i}.dat"), "wb") as fh:
            fh.write(b"soak" + os.urandom(6000))

    conditions = [
        Reading(system_cpu=1.0, own_cpu=0.0, idle_seconds=9999),
        Reading(system_cpu=5.0, own_cpu=0.0, idle_seconds=2),
        Reading(system_cpu=95.0, own_cpu=1.0, idle_seconds=2),
        Reading(idle_seconds=9999, on_battery=True, battery_percent=5.0),
    ]

    class Churn:
        def __init__(self) -> None:
            self.i = 0

        def read(self):
            self.i += 1
            return conditions[self.i % len(conditions)]

    before = (_rss_mb(), threading.active_count(), _open_connections())
    print(f"start   rss {before[0]:6.2f} MB   threads {before[1]}   "
          f"sqlite connections {before[2]}")

    for _ in range(cycles):
        governor = ThrottleGovernor(sensors=Churn(), sample_interval=0.001,
                                    recovery_seconds=0.0)
        governor._set_background_io = lambda on: None  # type: ignore[assignment]
        stop = threading.Event()

        def work(g=governor, s=stop) -> None:
            while not s.is_set():
                g.wait_turn(0.001)

        workers = [threading.Thread(target=work, daemon=True) for _ in range(4)]
        for worker in workers:
            worker.start()
        for _ in range(4):
            governor.budget(force=True)
        governor.pause()
        governor.resume()
        stop.set()
        governor.close()
        for worker in workers:
            worker.join(timeout=5)
            if worker.is_alive():
                print("  FAIL: a worker was never released from a pause")
                return False

    db = Database(config.paths.db_file)
    scanner = Scanner(config, bus=EventBus(), db=db, detectors=["hash", "script"])
    idle_probe.idle_seconds = lambda: 9999.0
    run = {"n": 0}

    def run_scan(roots, resume, stopping):
        run["n"] += 1
        scanner.cancel_event.clear()
        result = scanner.scan_paths(list(roots), record_history=False,
                                    estimate=False)
        # Alternate, so both the checkpoint and the completion path run.
        return ScanOutcome(completed=run["n"] % 2 == 0,
                           last_path=os.path.join(roots[0], "f1.dat"),
                           files_done=result.files_scanned)

    for _ in range(cycles):
        sched = IdleScheduler(run_scan, roots=[tree], db=db,
                              away_after=1.0, poll_seconds=0.01)
        sched._start_attempt()
        sched._scan_thread.join(timeout=60)
        if sched._scan_thread.is_alive():
            print("  FAIL: a scan thread never finished")
            return False
        sched.stop(timeout=5)

    scanner.close()
    db.close()
    after = (_rss_mb(), threading.active_count(), _open_connections())

    print("\n" + "=" * 68)
    print(f"  governor lifecycles {cycles:>9,} x 4 workers")
    print(f"  scan attempts       {run['n']:>9,}, each on a fresh thread")
    print(f"  rss                 {before[0]:>9.2f} -> {after[0]:.2f} MB "
          f"({after[0] - before[0]:+.2f})")
    print(f"  threads             {before[1]:>9} -> {after[1]}")
    print(f"  sqlite connections  {before[2]:>9} -> {after[2]}")
    print("=" * 68)

    return after[1] <= before[1] + 1 and after[2] <= before[2] + 2


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--idle", action="store_true",
                      help="soak the polling loops (default)")
    mode.add_argument("--churn", action="store_true",
                      help="soak governor and scan-attempt lifecycles")
    parser.add_argument("--seconds", type=float, default=240.0,
                        help="wall clock for --idle (default: 240)")
    parser.add_argument("--cycles", type=int, default=150,
                        help="lifecycles for --churn (default: 150)")
    args = parser.parse_args()

    try:
        import psutil  # noqa: F401
    except ImportError:
        print("psutil is required: pip install 'sentinel-scan[system]'")
        return 2

    _prepare_data_dir()
    ok = soak_churn(args.cycles) if args.churn else soak_idle(args.seconds)
    print("\nSOAK CLEAN" if ok else "\nSOMETHING GREW")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
