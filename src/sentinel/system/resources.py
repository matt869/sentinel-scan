"""What Sentinel is costing this machine, right now.

This exists to be displayed permanently, in the flyout, where the user can
always see it. That is unusual and it is deliberate.

The people this is built for are on four gigabytes of RAM and a spinning
disk, and many of them have been burned before by security software that ate
their computer. They have no way to check whether this one is doing the same,
short of opening Task Manager and knowing what to look for. Showing the
number unprompted — and never rounding it in our own favour — is the cheapest
trust the product can buy, and no competitor does it.

Which means the number has to be honest even when it is embarrassing. There
is deliberately no smoothing that hides a spike, no "<1%" floor, and no
reporting of the current thread instead of the process. If a scan is costing
25% of a core, it says 25%.
"""

from __future__ import annotations

import os
import threading
from typing import Any

from sentinel.core.logger import get_logger

log = get_logger(__name__)

try:
    import psutil

    PSUTIL_AVAILABLE = True
except ImportError:  # pragma: no cover - depends on the environment
    psutil = None  # type: ignore[assignment]
    PSUTIL_AVAILABLE = False


class ResourceMeter:
    """Samples this process's own CPU and memory use.

    Not thread-safe by accident — it takes a lock — because the flyout reads
    it on the GUI thread while a scan is running elsewhere.
    """

    def __init__(self, pid: int | None = None) -> None:
        self._lock = threading.Lock()
        self._process: Any = None
        self._cores = os.cpu_count() or 1

        if not PSUTIL_AVAILABLE:
            log.debug("psutil is not installed; resource use will not be shown")
            return

        try:
            self._process = psutil.Process(pid) if pid else psutil.Process()
            # The first call to cpu_percent always returns 0.0 — it has no
            # previous sample to diff against. Prime it here so the first
            # reading the user sees is real rather than a reassuring lie.
            self._process.cpu_percent(None)
        except Exception as exc:  # pragma: no cover - platform dependent
            log.debug("cannot read this process: %s", exc)
            self._process = None

    @property
    def available(self) -> bool:
        return self._process is not None

    def cpu_percent(self) -> float | None:
        """CPU use since the previous call, as a share of *one* core.

        Expressed per-core rather than per-machine on purpose. "25%" meaning
        a quarter of one core is what the eco-mode budget is written in, and
        what somebody watching Task Manager on a two-core laptop will see.
        """
        with self._lock:
            if self._process is None:
                return None
            try:
                return float(self._process.cpu_percent(None))
            except Exception as exc:
                log.debug("cannot sample CPU: %s", exc)
                return None

    def memory_bytes(self) -> int | None:
        """Resident set size: memory actually occupying RAM."""
        with self._lock:
            if self._process is None:
                return None
            try:
                return int(self._process.memory_info().rss)
            except Exception as exc:
                log.debug("cannot sample memory: %s", exc)
                return None

    def sample(self) -> tuple[float | None, int | None]:
        """Both figures at once, for a caller updating one label."""
        return self.cpu_percent(), self.memory_bytes()

    def describe(self) -> str:
        """The line shown in the flyout.

        CPU keeps one decimal place. The point of the line is that 0.4% is
        shown as 0.4%, not rounded up to a whole percent and not hidden
        behind "<1%" — both of which are the shapes a product uses when it
        would rather you did not look. A genuine 0.0% prints as 0.0%.
        """
        cpu, memory = self.sample()
        if cpu is None and memory is None:
            return "Resource use unavailable"

        parts = []
        if cpu is not None:
            parts.append(f"{cpu:.1f}% CPU")
        if memory is not None:
            parts.append(f"{round(memory / (1024 * 1024))} MB")
        return " · ".join(parts)


#: One meter for the whole process. Constructing several is harmless but each
#: keeps its own CPU baseline, so their readings disagree confusingly.
_default: ResourceMeter | None = None


def default_meter() -> ResourceMeter:
    global _default
    if _default is None:
        _default = ResourceMeter()
    return _default
