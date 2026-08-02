"""Autostart ("autorun") enumeration.

Persistence is the step that turns a one-off execution into a lasting
compromise, and almost every technique for it is visible from user space:
a registry Run key, a LaunchAgent plist, a systemd unit, a cron line.

This module provides the common vocabulary and dispatches to the
platform-specific collector. Entries are *reported*, never removed — the
same list contains the user's password manager and a keylogger, and only the
user can tell them apart.

The paths themselves are handed to the scanner, so an autorun pointing at a
malicious binary is caught by the ordinary detector pipeline.
"""

from __future__ import annotations

import os
import shlex
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sentinel.core.logger import get_logger

log = get_logger(__name__)

#: Locations that are writable by a normal user and therefore attractive for
#: persistence that does not need elevation.
USER_WRITABLE_MARKERS = (
    "\\appdata\\", "\\temp\\", "\\downloads\\", "\\users\\public\\",
    "/tmp/", "/var/tmp/", "/dev/shm/",
)

#: Interpreters invoked from an autostart entry. Not damning — plenty of
#: legitimate software launches a script — but worth surfacing.
SCRIPT_HOSTS = (
    "powershell", "pwsh", "cmd.exe", "wscript", "cscript", "mshta",
    "rundll32", "regsvr32", "python", "perl", "ruby", "node", "bash", "sh",
)


@dataclass(slots=True)
class AutorunEntry:
    """One thing configured to start automatically."""

    #: Where it was found, e.g. ``HKCU\\...\\Run`` or ``~/.config/autostart``.
    location: str
    #: The entry's own name or key.
    name: str
    #: The raw command line as configured.
    command: str
    #: Best-effort path to the executable, extracted from *command*.
    target: str = ""
    #: user | system
    scope: str = "user"
    enabled: bool = True
    #: Notes about why this entry might warrant attention.
    flags: list[str] = field(default_factory=list)

    @property
    def exists(self) -> bool:
        """Whether :attr:`target` resolves to a real file."""
        return bool(self.target) and os.path.isfile(self.target)

    @property
    def is_flagged(self) -> bool:
        return bool(self.flags)

    def to_dict(self) -> dict[str, Any]:
        return {
            "location": self.location,
            "name": self.name,
            "command": self.command,
            "target": self.target,
            "scope": self.scope,
            "enabled": self.enabled,
            "exists": self.exists,
            "flags": self.flags,
        }

    def __str__(self) -> str:
        return f"{self.location}\\{self.name} -> {self.command}"


def collect(include_system: bool = True) -> list[AutorunEntry]:
    """Enumerate autostart entries for the current platform.

    Args:
        include_system: Include machine-wide locations as well as the current
            user's. System locations usually need elevation to read; entries
            that cannot be read are skipped rather than raising.
    """
    # Imported lazily so a Linux build never touches the winreg module and
    # vice versa.
    try:
        if sys.platform.startswith("win"):
            from sentinel.system import platform_win as backend
        elif sys.platform == "darwin":
            from sentinel.system import platform_mac as backend
        elif sys.platform.startswith("linux"):
            from sentinel.system import platform_linux as backend
        else:
            log.info("autorun enumeration is not implemented for %s", sys.platform)
            return []
    except ImportError as exc:  # pragma: no cover - defensive
        log.warning("cannot load platform backend: %s", exc)
        return []

    try:
        entries = backend.collect_autoruns(include_system=include_system)
    except Exception as exc:
        log.error("autorun enumeration failed: %s", exc)
        log.debug("traceback", exc_info=True)
        return []

    for entry in entries:
        entry.flags = analyse(entry)
    return entries


def analyse(entry: AutorunEntry) -> list[str]:
    """Return reasons *entry* is worth a closer look."""
    flags: list[str] = []
    target_lower = entry.target.lower().replace("/", os.sep).replace("\\", os.sep)
    command_lower = entry.command.lower()

    if entry.target and not entry.exists:
        flags.append(
            "Points at a file that no longer exists. Usually leftover from "
            "uninstalled software; occasionally a sign something was removed "
            "while its persistence stayed behind."
        )

    normalised = entry.target.lower().replace("/", "\\")
    if any(marker.replace("/", "\\") in normalised for marker in USER_WRITABLE_MARKERS):
        flags.append(
            f"Runs from a user-writable directory ({Path(entry.target).parent}). "
            f"Legitimate installers put programs in Program Files or /usr; malware "
            f"prefers locations it can write without elevation."
        )

    for host in SCRIPT_HOSTS:
        if host in command_lower:
            flags.append(f"Launches a script interpreter ({host}) at startup.")
            break

    for marker in ("-enc", "-encodedcommand", "frombase64string", "downloadstring",
                   "-windowstyle hidden", "iex "):
        if marker in command_lower:
            flags.append(
                f"Command line contains '{marker.strip()}', which is used to hide "
                f"what actually runs."
            )
            break

    # An unquoted path with spaces lets an attacker plant C:\Program.exe and
    # have Windows run it instead (unquoted service path hijack).
    if os.name == "nt" and entry.command and not entry.command.startswith('"'):
        head = entry.command.split(" -")[0].split(" /")[0]
        if " " in head.strip() and head.strip().lower().endswith(".exe"):
            flags.append(
                "The executable path contains spaces but is not quoted, which "
                "allows a path-interception attack."
            )

    _ = target_lower  # kept for clarity in future checks
    return flags


def extract_target(command: str) -> str:
    """Pull the executable path out of a command line.

    Handles the quoted case, the ``rundll32 foo.dll,Entry`` case, and the
    unquoted-path-with-spaces case that Windows itself gets wrong.
    """
    command = command.strip()
    if not command:
        return ""

    if command.startswith('"'):
        end = command.find('"', 1)
        if end > 0:
            return command[1:end]

    if os.name == "nt":
        # Try progressively longer prefixes until one names a real file.
        parts = command.split(" ")
        for index in range(1, len(parts) + 1):
            candidate = " ".join(parts[:index]).strip().rstrip(",")
            if os.path.isfile(candidate):
                return candidate
            if candidate.lower().endswith((".exe", ".dll", ".bat", ".cmd", ".vbs")):
                return candidate
        return parts[0]

    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()
    return tokens[0] if tokens else ""


def flagged(entries: list[AutorunEntry] | None = None) -> list[AutorunEntry]:
    """Only the entries with at least one flag."""
    return [e for e in (entries if entries is not None else collect()) if e.is_flagged]


def targets_for_scan(entries: list[AutorunEntry] | None = None) -> list[str]:
    """Existing files referenced by autorun entries, for a targeted scan.

    Scanning these is the highest value-per-second check available: it is a
    few dozen files, and it covers everything configured to run on boot.
    """
    seen: dict[str, None] = {}
    for entry in entries if entries is not None else collect():
        if entry.exists:
            seen.setdefault(os.path.abspath(entry.target), None)
    return list(seen)
