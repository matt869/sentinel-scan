"""Running-process inspection.

This is a *reporting* surface, not a blocking one. Sentinel does not hook
syscalls, inject into processes or kill things automatically — that requires
a kernel driver, and getting it wrong bluescreens the machine. What it does
is enumerate what is running, flag shapes worth a human look, and let the
user act.

The heuristics here deliberately favour precision. "svchost.exe running from
the Downloads folder" is worth an alert; "a process using a lot of CPU" is
not, and treating it as one trains users to ignore the tool.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sentinel.core.logger import get_logger

log = get_logger(__name__)

try:
    import psutil

    _PSUTIL_AVAILABLE = True
except ImportError:  # pragma: no cover - depends on the environment
    psutil = None  # type: ignore[assignment]
    _PSUTIL_AVAILABLE = False


#: Windows system binaries that must live in System32/SysWOW64. A process
#: with one of these names running from anywhere else is a classic
#: masquerading technique (MITRE ATT&CK T1036.005).
PROTECTED_WINDOWS_NAMES = frozenset(
    {
        "svchost.exe", "lsass.exe", "csrss.exe", "smss.exe", "services.exe",
        "winlogon.exe", "wininit.exe", "spoolsv.exe", "taskhost.exe",
        "taskhostw.exe", "dwm.exe", "explorer.exe", "conhost.exe",
        "rundll32.exe", "dllhost.exe", "sihost.exe", "ctfmon.exe",
    }
)

#: Directories those binaries are legitimately found in, lowercased.
LEGITIMATE_SYSTEM_DIRS = (
    "c:\\windows\\system32",
    "c:\\windows\\syswow64",
    "c:\\windows",
    "c:\\windows\\winsxs",
)

#: Directories a system-named process has no business running from.
SUSPICIOUS_PARENT_DIRS = (
    "\\appdata\\local\\temp",
    "\\appdata\\roaming",
    "\\downloads",
    "\\temp",
    "\\tmp",
    "\\users\\public",
    "\\programdata",
    "\\recycle",
)


@dataclass(slots=True)
class ProcessInfo:
    """A snapshot of one running process."""

    pid: int
    name: str
    exe: str = ""
    cmdline: str = ""
    username: str = ""
    ppid: int = 0
    parent_name: str = ""
    create_time: float = 0.0
    memory_bytes: int = 0
    #: Notes explaining why this process was flagged.
    flags: list[str] = field(default_factory=list)

    @property
    def is_flagged(self) -> bool:
        return bool(self.flags)

    @property
    def directory(self) -> str:
        return str(Path(self.exe).parent) if self.exe else ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "pid": self.pid,
            "name": self.name,
            "exe": self.exe,
            "cmdline": self.cmdline[:500],
            "username": self.username,
            "ppid": self.ppid,
            "parent_name": self.parent_name,
            "memory_bytes": self.memory_bytes,
            "flags": self.flags,
        }


def available() -> bool:
    """Whether process enumeration is possible in this install."""
    return _PSUTIL_AVAILABLE


def iter_processes() -> Iterator[ProcessInfo]:
    """Yield every process the current user can see.

    Processes that vanish mid-enumeration or that we lack rights to inspect
    are skipped silently — both are completely routine.
    """
    if not _PSUTIL_AVAILABLE:
        log.info("process listing needs psutil (pip install 'sentinel-scan[system]')")
        return

    attributes = [
        "pid", "name", "exe", "cmdline", "username", "ppid",
        "create_time", "memory_info",
    ]

    for proc in psutil.process_iter(attributes, ad_value=None):
        try:
            info = proc.info
            memory = info.get("memory_info")
            cmdline = info.get("cmdline") or []
            yield ProcessInfo(
                pid=info["pid"],
                name=info.get("name") or "",
                exe=info.get("exe") or "",
                cmdline=" ".join(cmdline),
                username=info.get("username") or "",
                ppid=info.get("ppid") or 0,
                create_time=info.get("create_time") or 0.0,
                memory_bytes=getattr(memory, "rss", 0) if memory else 0,
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
        except Exception as exc:  # pragma: no cover - platform quirks
            log.debug("skipping a process: %s", exc)
            continue


def list_processes(flagged_only: bool = False) -> list[ProcessInfo]:
    """Snapshot every process, annotated with any suspicion flags."""
    processes = list(iter_processes())
    by_pid = {p.pid: p for p in processes}

    for process in processes:
        parent = by_pid.get(process.ppid)
        process.parent_name = parent.name if parent else ""
        process.flags = _analyse(process, parent)

    if flagged_only:
        return [p for p in processes if p.is_flagged]
    return processes


def _analyse(process: ProcessInfo, parent: ProcessInfo | None) -> list[str]:
    """Return the reasons this process looks worth a second look."""
    flags: list[str] = []
    name = process.name.lower()
    exe = (process.exe or "").lower().replace("/", "\\")

    if (
        os.name == "nt"
        and name in PROTECTED_WINDOWS_NAMES
        and exe
        and not any(exe.startswith(d) for d in LEGITIMATE_SYSTEM_DIRS)
    ):
        flags.append(
            f"'{process.name}' is a Windows system process but is running from "
            f"{process.directory}, not System32. This is a common way to hide "
            f"malware in plain sight."
        )

    # Only interesting for things that look like system tooling; plenty of
    # legitimate apps run from AppData (Slack, VS Code, browsers).
    if (
        exe
        and name in PROTECTED_WINDOWS_NAMES
        and any(marker in exe for marker in SUSPICIOUS_PARENT_DIRS)
    ):
        flags.append(f"Running from a temporary or user-writable location: {exe}")

    # A process with no executable path that is not a kernel thread.
    if not process.exe and process.pid > 4 and os.name == "nt":
        flags.append(
            "No executable path is readable for this process. That is normal for "
            "protected system processes, and also what a process hollowed by "
            "injection looks like."
        )

    cmdline = process.cmdline.lower()
    if "powershell" in name or "pwsh" in name:
        for marker, note in (
            ("-enc", "PowerShell running a base64-encoded command"),
            ("-encodedcommand", "PowerShell running a base64-encoded command"),
            ("bypass", "PowerShell running with the execution policy bypassed"),
            ("-windowstyle hidden", "PowerShell running with a hidden window"),
            ("downloadstring", "PowerShell downloading and running remote code"),
        ):
            if marker in cmdline:
                flags.append(note)
                break

    if parent is not None:
        parent_name = parent.name.lower()
        # Office spawning a shell is the single highest-signal indicator of a
        # malicious document on Windows.
        office = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
                  "msaccess.exe", "onenote.exe"}
        shells = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe",
                  "cscript.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe"}
        if parent_name in office and name in shells:
            flags.append(
                f"Spawned by {parent.name}. Office applications launching a script "
                f"host is the signature of a malicious document."
            )

    return flags


def find_by_path(path: str | os.PathLike[str]) -> list[ProcessInfo]:
    """Processes currently running the executable at *path*.

    Used before quarantining: moving a file that is running fails on Windows
    and is pointless everywhere else.
    """
    target = str(Path(path).resolve()).lower()
    return [
        p for p in iter_processes()
        if p.exe and str(Path(p.exe)).lower() == target
    ]


def is_running(path: str | os.PathLike[str]) -> bool:
    """True if the executable at *path* has a live process."""
    return bool(find_by_path(path))


def terminate(pid: int, force: bool = False, timeout: float = 5.0) -> bool:
    """Ask a process to exit. Returns True if it is gone afterwards.

    Always asks politely first: a SIGKILL to the wrong pid can lose a user's
    unsaved work, and malware rarely resists termination anyway.
    """
    if not _PSUTIL_AVAILABLE:
        raise RuntimeError("terminating processes requires psutil")

    try:
        proc = psutil.Process(pid)
        proc.terminate()
        try:
            proc.wait(timeout=timeout)
            return True
        except psutil.TimeoutExpired:
            if not force:
                log.warning("pid %d did not exit; pass force=True to kill it", pid)
                return False
            proc.kill()
            proc.wait(timeout=timeout)
            return True
    except psutil.NoSuchProcess:
        return True
    except psutil.AccessDenied:
        log.error("not permitted to terminate pid %d — try running elevated", pid)
        return False
    except Exception as exc:
        log.error("could not terminate pid %d: %s", pid, exc)
        return False


def executables_for_scan() -> list[str]:
    """Distinct on-disk executables backing running processes.

    A fast "scan what is actually running" pass — far quicker than a full
    disk scan and covers the code that matters most right now.
    """
    seen: dict[str, None] = {}
    for process in iter_processes():
        if process.exe and os.path.isfile(process.exe):
            seen.setdefault(process.exe, None)
    return list(seen)
