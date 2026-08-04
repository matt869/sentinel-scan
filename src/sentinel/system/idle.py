"""How long since the user last touched this machine.

One number, asked of the operating system, with no policy attached. What
counts as "long enough to start scanning" belongs to
:mod:`sentinel.daemon.scheduler`; what to do about a user who has come back
belongs to :mod:`sentinel.daemon.throttle`. This module only answers the
question.

Idle is defined as **time since the last keyboard or mouse input**, not as
low CPU. The two come apart in the case that matters most: a machine
compiling something overnight with nobody in the room is busy but idle, and a
machine sitting at 2% CPU with someone reading a page on it is quiet but very
much in use. We are trying not to be noticed by a person, so the person is
what we measure.

Every probe returns ``None`` rather than guessing when it cannot tell, and
callers treat ``None`` as *the user is present*. Being wrong that way costs a
scan that does not start; being wrong the other way starts a full-disk scan
under someone who is working, which is the single behaviour that gets
security software uninstalled.
"""

from __future__ import annotations

import os
import sys
import time

from sentinel.core.logger import get_logger

log = get_logger(__name__)

#: Cached across calls: the scheduler polls this every couple of seconds for
#: the life of the process, and re-resolving an X11 display or re-spawning
#: ``ioreg`` at that rate is not free.
_probe: _Probe | None = None


class _Probe:
    """Base for the per-platform implementations."""

    name = "none"

    def seconds(self) -> float | None:
        raise NotImplementedError


# ----------------------------------------------------------------------
# Windows
# ----------------------------------------------------------------------

class _WindowsProbe(_Probe):
    """``GetLastInputInfo``, which is the whole answer on Windows.

    Two details are load-bearing and both are easy to get wrong.

    **The tick counter wraps.** ``dwTime`` is a ``DWORD`` in ``GetTickCount``
    space, and ``GetTickCount`` rolls over to zero every 49.7 days of uptime.
    Subtracting in Python's unbounded integers gives a *negative* idle time
    for the 49.7 days after each wrap — which reads as "the user is here" and
    silently means a machine with long uptime never runs an idle scan again.
    Masking the difference back to 32 bits is what makes the arithmetic
    match the counter it came from. ``GetTickCount64`` does not help here:
    the value being subtracted is 32-bit, so the difference has to be too.

    **It is per-session.** The call reports input for the session the calling
    process is in. A process in session 0 — a Windows service — sees the
    input of a desktop nobody is sitting at, which is always none, which
    means always idle. Sentinel's background work runs in the user's own
    session for exactly this reason. If this is ever reached from a service,
    the number it returns is not about the user and must not be trusted.
    """

    name = "GetLastInputInfo"

    def __init__(self) -> None:
        import ctypes
        from ctypes import wintypes

        class LASTINPUTINFO(ctypes.Structure):
            _fields_ = [("cbSize", wintypes.UINT), ("dwTime", wintypes.DWORD)]

        self._ctypes = ctypes
        self._struct = LASTINPUTINFO
        self._user32 = ctypes.WinDLL("user32", use_last_error=True)
        self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self._user32.GetLastInputInfo.argtypes = [ctypes.POINTER(LASTINPUTINFO)]
        self._user32.GetLastInputInfo.restype = wintypes.BOOL
        self._kernel32.GetTickCount.restype = wintypes.DWORD

    def seconds(self) -> float | None:
        info = self._struct()
        info.cbSize = self._ctypes.sizeof(self._struct)
        if not self._user32.GetLastInputInfo(self._ctypes.byref(info)):
            return None

        now = self._kernel32.GetTickCount()
        elapsed_ms = (now - info.dwTime) & 0xFFFFFFFF
        return elapsed_ms / 1000.0


# ----------------------------------------------------------------------
# Linux
# ----------------------------------------------------------------------

class _XScreenSaverProbe(_Probe):
    """``XScreenSaverQueryInfo``, the only portable answer under X11.

    Wayland deliberately does not expose this — a client being able to ask
    "is the user at the keyboard?" is the input-sniffing surface Wayland
    exists to close — and the X11 compatibility layer answers 0 forever
    rather than failing. A frozen 0 is the dangerous shape, because it reads
    as *the user is here* only by accident, so the Wayland check happens
    before the library is even loaded.
    """

    name = "XScreenSaver"

    def __init__(self) -> None:
        import ctypes

        if os.environ.get("WAYLAND_DISPLAY"):
            raise RuntimeError("Wayland does not expose an idle time")
        if not os.environ.get("DISPLAY"):
            raise RuntimeError("no X11 display")

        class XScreenSaverInfo(ctypes.Structure):
            _fields_ = [
                ("window", ctypes.c_ulong),
                ("state", ctypes.c_int),
                ("kind", ctypes.c_int),
                ("since", ctypes.c_ulong),
                ("idle", ctypes.c_ulong),
                ("event_mask", ctypes.c_ulong),
            ]

        self._ctypes = ctypes
        self._xlib = ctypes.CDLL("libX11.so.6")
        self._xss = ctypes.CDLL("libXss.so.1")

        self._xlib.XOpenDisplay.restype = ctypes.c_void_p
        self._xlib.XDefaultRootWindow.argtypes = [ctypes.c_void_p]
        self._xlib.XDefaultRootWindow.restype = ctypes.c_ulong
        self._xss.XScreenSaverAllocInfo.restype = ctypes.POINTER(XScreenSaverInfo)
        self._xss.XScreenSaverQueryInfo.argtypes = [
            ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(XScreenSaverInfo)
        ]

        self._display = self._xlib.XOpenDisplay(None)
        if not self._display:
            raise RuntimeError("cannot open the X display")
        self._root = self._xlib.XDefaultRootWindow(self._display)
        self._info = self._xss.XScreenSaverAllocInfo()
        if not self._info:
            raise RuntimeError("XScreenSaverAllocInfo failed")

    def seconds(self) -> float | None:
        if not self._xss.XScreenSaverQueryInfo(self._display, self._root, self._info):
            return None
        return self._info.contents.idle / 1000.0


# ----------------------------------------------------------------------
# macOS
# ----------------------------------------------------------------------

class _MacProbe(_Probe):
    """``HIDIdleTime`` out of the I/O registry, in nanoseconds.

    Shelling out to ``ioreg`` rather than binding IOKit: the binding needs
    pyobjc, which is a heavy dependency to add for one integer, and this is
    read every couple of seconds rather than every couple of milliseconds.
    """

    name = "ioreg HIDIdleTime"

    def __init__(self) -> None:
        if not os.path.exists("/usr/sbin/ioreg"):
            raise RuntimeError("ioreg is not available")

    def seconds(self) -> float | None:
        import subprocess

        try:
            completed = subprocess.run(
                ["/usr/sbin/ioreg", "-c", "IOHIDSystem", "-d", "4", "-r"],
                capture_output=True, text=True, timeout=5, check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            log.debug("ioreg failed: %s", exc)
            return None

        for line in completed.stdout.splitlines():
            if "HIDIdleTime" not in line:
                continue
            _, _, value = line.partition("=")
            try:
                return int(value.strip()) / 1_000_000_000.0
            except ValueError:
                return None
        return None


# ----------------------------------------------------------------------
# selection
# ----------------------------------------------------------------------

def _build_probe() -> _Probe | None:
    """Pick the probe for this platform, or None if there is not one."""
    candidates: tuple[type[_Probe], ...]
    if os.name == "nt":
        candidates = (_WindowsProbe,)
    elif sys.platform == "darwin":
        candidates = (_MacProbe,)
    elif sys.platform.startswith("linux"):
        candidates = (_XScreenSaverProbe,)
    else:
        candidates = ()

    for candidate in candidates:
        try:
            probe = candidate()
        except Exception as exc:
            log.debug("idle probe %s unavailable: %s", candidate.name, exc)
            continue
        log.debug("idle detection via %s", probe.name)
        return probe
    return None


def idle_seconds() -> float | None:
    """Seconds since the last keyboard or mouse input.

    Returns ``None`` when this platform cannot say, which callers must treat
    as *the user is present*. Never raises.
    """
    global _probe
    if _probe is None:
        _probe = _build_probe()
        if _probe is None:
            return None

    try:
        value = _probe.seconds()
    except Exception as exc:  # pragma: no cover - platform dependent
        log.debug("idle probe failed: %s", exc)
        return None

    # A negative reading means the clock arithmetic went wrong somewhere
    # below us. Report "cannot tell" rather than a number that would let a
    # scan start under a user who is sitting right there.
    if value is None or value < 0:
        return None
    return value


def user_is_away(threshold_seconds: float) -> bool:
    """Whether nobody has touched this machine for *threshold_seconds*.

    False when the platform cannot tell.
    """
    value = idle_seconds()
    return value is not None and value >= threshold_seconds


def detection_method() -> str:
    """How idle time is being measured here, for the log and for support."""
    global _probe
    if _probe is None:
        _probe = _build_probe()
    return _probe.name if _probe is not None else "unavailable"


def reset_probe() -> None:
    """Drop the cached probe. For tests, and for a display that went away."""
    global _probe
    _probe = None


class IdleTracker:
    """Turns the raw number into edges: went away, came back.

    The scheduler wants to know *when the user returned*, and a poll loop
    comparing raw seconds cannot tell the difference between "idle for 4
    seconds because they paused to think" and "idle time just reset because
    they touched the mouse". This tracks the previous reading so a drop in
    idle time is recognised as input rather than read as a smaller number.
    """

    def __init__(self, away_after: float = 300.0) -> None:
        self.away_after = away_after
        self._last_seen: float | None = None
        self._away = False
        self._returned_at: float | None = None

    @property
    def away(self) -> bool:
        return self._away

    @property
    def returned_at(self) -> float | None:
        """Monotonic time of the most recent return, or None."""
        return self._returned_at

    def poll(self, now: float | None = None) -> bool:
        """Sample once. Returns True if the user *just came back*."""
        now = time.monotonic() if now is None else now
        value = idle_seconds()
        previous, self._last_seen = self._last_seen, value

        # Unknown counts as present, and as a return if we thought they were
        # away: losing the probe mid-scan (the X display went away, the
        # session changed) must fail towards backing off.
        if value is None:
            came_back = self._away
            self._away = False
            if came_back:
                self._returned_at = now
            return came_back

        # Idle time falling is the only positive evidence of input there is.
        # Anything else is inference from a threshold.
        touched = previous is not None and value < previous

        was_away = self._away
        self._away = value >= self.away_after and not touched
        came_back = was_away and not self._away
        if came_back:
            self._returned_at = now
        return came_back
