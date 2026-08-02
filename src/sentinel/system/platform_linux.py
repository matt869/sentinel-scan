"""Linux-specific system inspection.

Persistence on Linux is spread across systemd units, cron, XDG autostart
desktop files, and shell startup files. All of them are plain text, so this
module is mostly careful parsing.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from sentinel.core.logger import get_logger
from sentinel.system.autoruns import AutorunEntry, extract_target

log = get_logger(__name__)

#: (directory, label, scope)
_SYSTEMD_DIRS: tuple[tuple[str, str, str], ...] = (
    ("~/.config/systemd/user", "systemd (user)", "user"),
    ("/etc/systemd/system", "systemd (system)", "system"),
    ("/usr/lib/systemd/system", "systemd (vendor)", "system"),
    ("/lib/systemd/system", "systemd (vendor)", "system"),
)

_AUTOSTART_DIRS: tuple[tuple[str, str, str], ...] = (
    ("~/.config/autostart", "XDG autostart (user)", "user"),
    ("/etc/xdg/autostart", "XDG autostart (system)", "system"),
)

_CRON_FILES: tuple[tuple[str, str, str], ...] = (
    ("/etc/crontab", "crontab (system)", "system"),
)

_CRON_DIRS: tuple[tuple[str, str, str], ...] = (
    ("/etc/cron.d", "cron.d", "system"),
    ("/etc/cron.hourly", "cron.hourly", "system"),
    ("/etc/cron.daily", "cron.daily", "system"),
    ("/etc/cron.weekly", "cron.weekly", "system"),
    ("/etc/cron.monthly", "cron.monthly", "system"),
)

#: Shell startup files. A malicious line appended here runs on every login.
_SHELL_RC_FILES = (
    "~/.bashrc", "~/.bash_profile", "~/.profile", "~/.zshrc", "~/.zprofile",
    "~/.config/fish/config.fish",
)

_EXEC_START = re.compile(r"^\s*ExecStart\s*=\s*(.+)$", re.MULTILINE)
_DESKTOP_EXEC = re.compile(r"^\s*Exec\s*=\s*(.+)$", re.MULTILINE)
_DESKTOP_HIDDEN = re.compile(r"^\s*Hidden\s*=\s*true\s*$", re.MULTILINE | re.IGNORECASE)
_CRON_LINE = re.compile(r"^\s*(?:@\w+|[\d*/,\-]+(?:\s+[\d*/,\-]+){4})\s+(.+)$")


def collect_autoruns(include_system: bool = True) -> list[AutorunEntry]:
    """Enumerate Linux autostart entries."""
    entries: list[AutorunEntry] = []
    entries.extend(_collect_systemd(include_system))
    entries.extend(_collect_xdg_autostart(include_system))
    entries.extend(_collect_cron(include_system))
    entries.extend(_collect_shell_rc())
    return entries


def _collect_systemd(include_system: bool) -> list[AutorunEntry]:
    entries: list[AutorunEntry] = []

    for raw_dir, label, scope in _SYSTEMD_DIRS:
        if scope == "system" and not include_system:
            continue
        directory = Path(raw_dir).expanduser()
        if not directory.is_dir():
            continue

        for path in _iter_files(directory, suffixes=(".service", ".timer")):
            text = _read(path)
            if text is None:
                continue
            match = _EXEC_START.search(text)
            if not match:
                continue
            command = match.group(1).strip()
            entries.append(
                AutorunEntry(
                    location=label,
                    name=path.name,
                    command=command,
                    # systemd prefixes have meaning (-, @, +, !) but are not
                    # part of the path.
                    target=extract_target(command.lstrip("-@+!:")),
                    scope=scope,
                    enabled="Install]" in text or scope == "user",
                )
            )

    return entries


def _collect_xdg_autostart(include_system: bool) -> list[AutorunEntry]:
    entries: list[AutorunEntry] = []

    for raw_dir, label, scope in _AUTOSTART_DIRS:
        if scope == "system" and not include_system:
            continue
        directory = Path(raw_dir).expanduser()
        if not directory.is_dir():
            continue

        for path in _iter_files(directory, suffixes=(".desktop",)):
            text = _read(path)
            if text is None:
                continue
            match = _DESKTOP_EXEC.search(text)
            if not match:
                continue
            command = match.group(1).strip()
            entries.append(
                AutorunEntry(
                    location=label,
                    name=path.stem,
                    command=command,
                    target=extract_target(command),
                    scope=scope,
                    enabled=not _DESKTOP_HIDDEN.search(text),
                )
            )

    return entries


def _collect_cron(include_system: bool) -> list[AutorunEntry]:
    entries: list[AutorunEntry] = []

    # The current user's crontab, read without shelling out to `crontab -l`.
    user = os.environ.get("USER") or os.environ.get("LOGNAME") or ""
    if user:
        for base in ("/var/spool/cron/crontabs", "/var/spool/cron"):
            path = Path(base) / user
            if path.is_file():
                entries.extend(_parse_crontab(path, "crontab (user)", "user"))
                break

    if not include_system:
        return entries

    for raw_path, label, scope in _CRON_FILES:
        path = Path(raw_path)
        if path.is_file():
            entries.extend(_parse_crontab(path, label, scope))

    for raw_dir, label, scope in _CRON_DIRS:
        directory = Path(raw_dir)
        if not directory.is_dir():
            continue
        for path in _iter_files(directory):
            if directory.name == "cron.d":
                entries.extend(_parse_crontab(path, label, scope))
            else:
                # cron.daily etc. hold executable scripts, not crontab lines.
                entries.append(
                    AutorunEntry(
                        location=label,
                        name=path.name,
                        command=str(path),
                        target=str(path),
                        scope=scope,
                    )
                )

    return entries


def _parse_crontab(path: Path, label: str, scope: str) -> list[AutorunEntry]:
    text = _read(path)
    if text is None:
        return []

    entries: list[AutorunEntry] = []
    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" in stripped.split()[0]:
            continue
        match = _CRON_LINE.match(stripped)
        if not match:
            continue
        command = match.group(1).strip()
        # System crontabs have a user field between schedule and command.
        if scope == "system" and label != "crontab (user)":
            parts = command.split(None, 1)
            if len(parts) == 2 and not parts[0].startswith("/"):
                command = parts[1]
        entries.append(
            AutorunEntry(
                location=label,
                name=f"{path.name}:{number}",
                command=command,
                target=extract_target(command),
                scope=scope,
            )
        )
    return entries


def _collect_shell_rc() -> list[AutorunEntry]:
    """Flag shell rc files that pull in something from a writable location."""
    entries: list[AutorunEntry] = []
    suspicious = re.compile(
        r"^\s*(?:source|\.)\s+(\S+)|^\s*(curl|wget)\s+\S+\s*\|\s*(?:ba)?sh",
        re.MULTILINE,
    )

    for raw_path in _SHELL_RC_FILES:
        path = Path(raw_path).expanduser()
        if not path.is_file():
            continue
        text = _read(path)
        if text is None:
            continue

        for match in suspicious.finditer(text):
            sourced = match.group(1)
            if sourced:
                resolved = Path(sourced.replace("$HOME", str(Path.home()))).expanduser()
                # Sourcing a file from the home directory is completely
                # normal; only flag writable-by-anyone locations.
                if not any(
                    str(resolved).startswith(prefix)
                    for prefix in ("/tmp/", "/var/tmp/", "/dev/shm/")
                ):
                    continue
            entries.append(
                AutorunEntry(
                    location=f"shell rc ({path.name})",
                    name=path.name,
                    command=match.group(0).strip(),
                    target=str(sourced or ""),
                    scope="user",
                )
            )

    return entries


def _iter_files(directory: Path, suffixes: tuple[str, ...] = ()) -> list[Path]:
    try:
        children = sorted(directory.iterdir())
    except OSError as exc:
        log.debug("cannot list %s: %s", directory, exc)
        return []
    return [
        p for p in children
        if p.is_file() and (not suffixes or p.suffix in suffixes)
    ]


def _read(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        log.debug("cannot read %s: %s", path, exc)
        return None


def high_value_scan_paths() -> list[str]:
    """Directories worth a quick scan on Linux."""
    home = Path.home()
    candidates = [
        home / "Downloads", home / "Desktop", home / "Documents",
        home / ".local" / "bin", home / ".config" / "autostart",
        Path("/tmp"), Path("/var/tmp"), Path("/dev/shm"),
    ]
    return [str(p) for p in candidates if p.is_dir()]
