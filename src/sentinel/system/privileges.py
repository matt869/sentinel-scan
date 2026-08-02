"""Privilege detection and guidance.

Sentinel deliberately does **not** try to elevate itself. A scanner that
silently relaunches as root is a scanner users cannot reason about, and
UAC/sudo prompts triggered by a background process are exactly the pattern
malware imitates. Instead we detect the current level, tell the user plainly
what is out of reach, and let them decide.
"""

from __future__ import annotations

import ctypes
import os
import sys
from dataclasses import dataclass

from sentinel.core.logger import get_logger

log = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class PrivilegeInfo:
    """What the current process is allowed to do."""

    elevated: bool
    user: str
    platform: str
    #: Human-readable note about what elevation would add.
    note: str = ""

    @property
    def label(self) -> str:
        if self.elevated:
            return "administrator" if self.platform == "windows" else "root"
        return "standard user"


def is_elevated() -> bool:
    """True if running as Administrator (Windows) or root (POSIX)."""
    if os.name == "nt":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception as exc:  # pragma: no cover - non-standard Windows
            log.debug("cannot determine elevation: %s", exc)
            return False
    try:
        return os.geteuid() == 0
    except AttributeError:  # pragma: no cover - no geteuid
        return False


def current_user() -> str:
    """Best-effort username, without raising on a headless service account."""
    for variable in ("USER", "USERNAME", "LOGNAME"):
        value = os.environ.get(variable)
        if value:
            return value
    try:
        import getpass

        return getpass.getuser()
    except Exception:
        return "unknown"


def platform_name() -> str:
    """``windows``, ``macos``, ``linux`` or the raw ``sys.platform``."""
    if sys.platform.startswith("win"):
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    if sys.platform.startswith("linux"):
        return "linux"
    return sys.platform


def privilege_info() -> PrivilegeInfo:
    """Describe the current privilege level and what it costs."""
    elevated = is_elevated()
    platform = platform_name()

    if elevated:
        note = "Full access: all user profiles and system directories are scannable."
    elif platform == "windows":
        note = (
            "Running as a standard user. Other users' profiles, "
            "C:\\Windows\\System32\\config and some ProgramData paths will be "
            "skipped as unreadable. Autorun inspection covers HKCU only. "
            "Run from an elevated prompt for a full system scan."
        )
    else:
        note = (
            "Running unprivileged. Other users' home directories, /root and some "
            "system paths will be skipped as unreadable. Re-run with sudo for a "
            "full system scan."
        )

    return PrivilegeInfo(
        elevated=elevated, user=current_user(), platform=platform, note=note
    )


def elevation_command() -> str:
    """The command a user would run to get an elevated scan."""
    if os.name == "nt":
        return 'Start-Process powershell -Verb RunAs -ArgumentList "sentinel scan ..."'
    return "sudo sentinel scan ..."


def can_read(path: str | os.PathLike[str]) -> bool:
    """Whether the current process can open *path* for reading."""
    return os.access(path, os.R_OK)


def requires_elevation(path: str | os.PathLike[str]) -> bool:
    """True when *path* exists but is unreadable at the current level."""
    return os.path.exists(path) and not can_read(path)


def warn_if_unprivileged(operation: str = "scan") -> PrivilegeInfo:
    """Log a one-line notice when running without elevation.

    Returns the :class:`PrivilegeInfo` so callers can show it in the UI.
    """
    info = privilege_info()
    if not info.elevated:
        log.info("%s running as %s — %s", operation, info.label, info.note)
    return info
