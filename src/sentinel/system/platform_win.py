"""Windows-specific system inspection.

Covers the persistence locations that matter in practice: the Run/RunOnce
registry keys, the Startup folders, Winlogon shell hooks, and services.

Everything degrades gracefully. Reading HKLM needs elevation; when it is not
available the machine-wide entries are skipped and the user-level ones are
still returned, with a note rather than an exception.
"""

from __future__ import annotations

import os
from pathlib import Path

from sentinel.core.logger import get_logger
from sentinel.system.autoruns import AutorunEntry, extract_target

log = get_logger(__name__)

try:
    import winreg

    _WINREG_AVAILABLE = True
except ImportError:  # pragma: no cover - non-Windows
    winreg = None  # type: ignore[assignment]
    _WINREG_AVAILABLE = False


#: (hive, subkey, label, scope). Order matters only for display.
_RUN_KEYS: tuple[tuple[str, str, str, str], ...] = (
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU\\Run", "user"),
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
     "HKCU\\RunOnce", "user"),
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
     "HKCU\\ShellFolders", "user"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM\\Run", "system"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
     "HKLM\\RunOnce", "system"),
    ("HKLM", r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
     "HKLM\\Run (32-bit)", "system"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\RunServices",
     "HKLM\\RunServices", "system"),
)

#: Winlogon values that should hold exactly one known-good binary. Anything
#: appended after a comma here runs at every logon and is a classic hook.
_WINLOGON_KEY = r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
_WINLOGON_VALUES = {
    "Shell": "explorer.exe",
    "Userinit": "userinit.exe",
}


def _hive(name: str) -> int:
    return {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}[name]


def collect_autoruns(include_system: bool = True) -> list[AutorunEntry]:
    """Enumerate Windows autostart entries."""
    if not _WINREG_AVAILABLE:
        log.debug("winreg unavailable; not on Windows")
        return []

    entries: list[AutorunEntry] = []
    entries.extend(_collect_run_keys(include_system))
    entries.extend(_collect_startup_folders(include_system))
    entries.extend(_collect_winlogon())
    return entries


def _collect_run_keys(include_system: bool) -> list[AutorunEntry]:
    entries: list[AutorunEntry] = []

    for hive_name, subkey, label, scope in _RUN_KEYS:
        if scope == "system" and not include_system:
            continue
        if "ShellFolders" in label:
            continue  # handled by _collect_startup_folders

        try:
            key = winreg.OpenKey(_hive(hive_name), subkey)
        except FileNotFoundError:
            continue
        except PermissionError:
            log.debug("%s requires elevation; skipped", label)
            continue
        except OSError as exc:
            log.debug("cannot open %s: %s", label, exc)
            continue

        with key:
            index = 0
            while True:
                try:
                    name, value, _kind = winreg.EnumValue(key, index)
                except OSError:
                    break
                index += 1

                command = str(value).strip()
                if not command:
                    continue
                entries.append(
                    AutorunEntry(
                        location=label,
                        name=name,
                        command=command,
                        target=extract_target(command),
                        scope=scope,
                    )
                )

    return entries


def _collect_startup_folders(include_system: bool) -> list[AutorunEntry]:
    """Shortcuts dropped in a Startup folder."""
    entries: list[AutorunEntry] = []

    candidates: list[tuple[Path, str, str]] = []
    appdata = os.environ.get("APPDATA")
    if appdata:
        candidates.append(
            (
                Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs"
                / "Startup",
                "Startup folder (user)",
                "user",
            )
        )
    program_data = os.environ.get("PROGRAMDATA")
    if program_data and include_system:
        candidates.append(
            (
                Path(program_data) / "Microsoft" / "Windows" / "Start Menu" / "Programs"
                / "Startup",
                "Startup folder (all users)",
                "system",
            )
        )

    for directory, label, scope in candidates:
        if not directory.is_dir():
            continue
        try:
            children = list(directory.iterdir())
        except OSError as exc:
            log.debug("cannot list %s: %s", directory, exc)
            continue

        for path in children:
            if path.name.lower() == "desktop.ini" or path.is_dir():
                continue
            entries.append(
                AutorunEntry(
                    location=label,
                    name=path.name,
                    command=str(path),
                    # A .lnk points elsewhere, but resolving shortcuts needs
                    # COM. Scanning the shortcut file itself is still useful.
                    target=str(path),
                    scope=scope,
                )
            )

    return entries


def _collect_winlogon() -> list[AutorunEntry]:
    """Winlogon Shell/Userinit hooks."""
    entries: list[AutorunEntry] = []

    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _WINLOGON_KEY)
    except (FileNotFoundError, PermissionError, OSError):
        return entries

    with key:
        for value_name, expected in _WINLOGON_VALUES.items():
            try:
                value, _kind = winreg.QueryValueEx(key, value_name)
            except OSError:
                continue

            command = str(value).strip()
            if not command:
                continue

            # The stock values are "explorer.exe" and "userinit.exe,". Extra
            # comma-separated entries are appended hooks.
            parts = [p.strip() for p in command.split(",") if p.strip()]
            unexpected = [p for p in parts if Path(p).name.lower() != expected]

            entry = AutorunEntry(
                location=f"HKLM\\Winlogon\\{value_name}",
                name=value_name,
                command=command,
                target=extract_target(parts[0] if parts else command),
                scope="system",
            )
            if unexpected:
                entry.flags.append(
                    f"Winlogon {value_name} normally runs only {expected}. It also "
                    f"launches: {', '.join(unexpected)}. This runs at every logon."
                )
            entries.append(entry)

    return entries


def list_services() -> list[dict[str, str]]:
    """Installed Windows services, when psutil is available."""
    try:
        import psutil
    except ImportError:
        log.info("service listing needs psutil")
        return []

    out: list[dict[str, str]] = []
    try:
        for service in psutil.win_service_iter():
            try:
                info = service.as_dict()
            except Exception:
                continue
            out.append(
                {
                    "name": info.get("name", ""),
                    "display_name": info.get("display_name", ""),
                    "status": info.get("status", ""),
                    "start_type": info.get("start_type", ""),
                    "binpath": info.get("binpath", ""),
                    "username": info.get("username", ""),
                }
            )
    except Exception as exc:
        log.debug("service enumeration failed: %s", exc)
    return out


def defender_status() -> dict[str, object]:
    """Whether Windows Defender real-time protection is on.

    Malware commonly disables it, so a scanner noticing it is off is useful.
    Read-only: this never changes the setting.
    """
    if not _WINREG_AVAILABLE:
        return {"available": False}

    result: dict[str, object] = {"available": True}
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection",
        ) as key:
            value, _ = winreg.QueryValueEx(key, "DisableRealtimeMonitoring")
            result["realtime_disabled"] = bool(value)
    except FileNotFoundError:
        result["realtime_disabled"] = False
    except (PermissionError, OSError) as exc:
        result["error"] = str(exc)

    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows Defender"
        ) as key:
            value, _ = winreg.QueryValueEx(key, "DisableAntiSpyware")
            result["policy_disabled"] = bool(value)
    except FileNotFoundError:
        result["policy_disabled"] = False
    except (PermissionError, OSError):
        pass

    return result


def high_value_scan_paths() -> list[str]:
    """Directories worth a quick scan on Windows."""
    paths: list[str] = []
    for variable in ("USERPROFILE", "APPDATA", "LOCALAPPDATA", "TEMP", "ProgramData"):
        value = os.environ.get(variable)
        if not value:
            continue
        base = Path(value)
        if variable == "USERPROFILE":
            paths.extend(
                str(base / name) for name in ("Downloads", "Desktop", "Documents")
            )
        else:
            paths.append(str(base))
    return [p for p in paths if os.path.isdir(p)]
