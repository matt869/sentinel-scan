"""macOS-specific system inspection.

The persistence surface is mostly launchd: property lists under
``LaunchAgents`` (per-user, run at login) and ``LaunchDaemons`` (system-wide,
run at boot). Third-party kernel/system extensions and login items round it
out.

Plists come in XML and binary flavours; :mod:`plistlib` reads both, so there
is no need to shell out to ``defaults``.
"""

from __future__ import annotations

import plistlib
from pathlib import Path

from sentinel.core.logger import get_logger
from sentinel.system.autoruns import AutorunEntry, extract_target

log = get_logger(__name__)

#: (directory, label, scope)
_LAUNCH_DIRS: tuple[tuple[str, str, str], ...] = (
    ("~/Library/LaunchAgents", "LaunchAgent (user)", "user"),
    ("/Library/LaunchAgents", "LaunchAgent (system)", "system"),
    ("/Library/LaunchDaemons", "LaunchDaemon", "system"),
    ("/System/Library/LaunchAgents", "LaunchAgent (Apple)", "system"),
    ("/System/Library/LaunchDaemons", "LaunchDaemon (Apple)", "system"),
)

#: Apple's own entries are numerous and uninteresting; skipping them keeps
#: the report to the handful of things a user actually installed.
_APPLE_PREFIXES = ("com.apple.", "com.openssh.")

_STARTUP_DIRS: tuple[tuple[str, str, str], ...] = (
    ("/Library/StartupItems", "StartupItem", "system"),
    ("~/Library/Application Support/com.apple.backgroundtaskmanagementagent",
     "Background task agent", "user"),
)


def collect_autoruns(include_system: bool = True) -> list[AutorunEntry]:
    """Enumerate macOS autostart entries."""
    entries: list[AutorunEntry] = []
    entries.extend(_collect_launchd(include_system))
    entries.extend(_collect_startup_items(include_system))
    return entries


def _collect_launchd(include_system: bool) -> list[AutorunEntry]:
    entries: list[AutorunEntry] = []

    for raw_dir, label, scope in _LAUNCH_DIRS:
        if scope == "system" and not include_system:
            continue
        directory = Path(raw_dir).expanduser()
        if not directory.is_dir():
            continue

        try:
            children = sorted(directory.iterdir())
        except OSError as exc:
            log.debug("cannot list %s: %s", directory, exc)
            continue

        for path in children:
            if path.suffix != ".plist" or not path.is_file():
                continue

            plist = _read_plist(path)
            if plist is None:
                continue

            label_value = str(plist.get("Label", path.stem))
            if label_value.startswith(_APPLE_PREFIXES) and "Apple" in label:
                continue

            command, target = _command_from_plist(plist)
            if not command:
                continue

            entry = AutorunEntry(
                location=label,
                name=label_value,
                command=command,
                target=target,
                scope=scope,
                enabled=not plist.get("Disabled", False),
            )

            # RunAtLoad plus KeepAlive means "start at login and restart if
            # killed" — the shape of something that does not want to stop.
            if plist.get("RunAtLoad") and plist.get("KeepAlive"):
                entry.flags.append(
                    "Configured to start at login and restart automatically if "
                    "terminated."
                )
            interval = plist.get("StartInterval")
            if isinstance(interval, int) and 0 < interval <= 60:
                entry.flags.append(
                    f"Re-runs every {interval} seconds, which is unusually frequent."
                )

            entries.append(entry)

    return entries


def _command_from_plist(plist: dict) -> tuple[str, str]:
    """Extract the command and executable from a launchd plist."""
    program = plist.get("Program")
    if isinstance(program, str) and program:
        return program, program

    arguments = plist.get("ProgramArguments")
    if isinstance(arguments, list) and arguments:
        parts = [str(a) for a in arguments]
        command = " ".join(parts)
        return command, parts[0]

    return "", ""


def _collect_startup_items(include_system: bool) -> list[AutorunEntry]:
    entries: list[AutorunEntry] = []

    for raw_dir, label, scope in _STARTUP_DIRS:
        if scope == "system" and not include_system:
            continue
        directory = Path(raw_dir).expanduser()
        if not directory.is_dir():
            continue
        try:
            children = sorted(directory.iterdir())
        except OSError:
            continue
        for path in children:
            if path.name.startswith("."):
                continue
            entries.append(
                AutorunEntry(
                    location=label,
                    name=path.name,
                    command=str(path),
                    target=extract_target(str(path)),
                    scope=scope,
                )
            )

    return entries


def _read_plist(path: Path) -> dict | None:
    """Read an XML or binary plist, returning None on any problem."""
    try:
        with open(path, "rb") as fh:
            data = plistlib.load(fh)
    except (OSError, plistlib.InvalidFileException, ValueError) as exc:
        log.debug("cannot parse %s: %s", path, exc)
        return None
    return data if isinstance(data, dict) else None


def gatekeeper_status() -> dict[str, object]:
    """Whether Gatekeeper is enabled.

    Read-only. Uses ``spctl`` because there is no stable file to read; a
    missing binary or non-zero exit simply yields "unknown".
    """
    import shutil
    import subprocess

    spctl = shutil.which("spctl")
    if not spctl:
        return {"available": False}

    try:
        result = subprocess.run(
            [spctl, "--status"], capture_output=True, text=True, timeout=5, check=False
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {"available": False, "error": str(exc)}

    output = (result.stdout or "").strip().lower()
    return {
        "available": True,
        "enabled": "assessments enabled" in output,
        "raw": output,
    }


def high_value_scan_paths() -> list[str]:
    """Directories worth a quick scan on macOS."""
    home = Path.home()
    candidates = [
        home / "Downloads", home / "Desktop", home / "Documents",
        home / "Library" / "LaunchAgents",
        Path("/Library/LaunchAgents"), Path("/Library/LaunchDaemons"),
        Path("/tmp"), Path("/var/tmp"),
    ]
    return [str(p) for p in candidates if p.is_dir()]
