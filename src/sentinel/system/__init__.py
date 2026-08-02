"""OS inspection: privileges, processes, drives, autoruns, hosts file.

Everything here is read-only reporting. Nothing in this package modifies the
system — no registry writes, no killing processes without an explicit call,
no editing the hosts file. See docs/architecture.md for the reasoning.
"""

from __future__ import annotations

import sys
from typing import Any

from sentinel.system.autoruns import AutorunEntry
from sentinel.system.autoruns import collect as collect_autoruns
from sentinel.system.drives import Drive, list_drives, scannable_roots
from sentinel.system.hosts_file import HostsReport, read_hosts
from sentinel.system.privileges import PrivilegeInfo, is_elevated, privilege_info
from sentinel.system.processes import ProcessInfo, list_processes

__all__ = [
    "AutorunEntry",
    "Drive",
    "HostsReport",
    "PrivilegeInfo",
    "ProcessInfo",
    "collect_autoruns",
    "high_value_scan_paths",
    "is_elevated",
    "list_drives",
    "list_processes",
    "privilege_info",
    "read_hosts",
    "scannable_roots",
    "system_report",
]


def _backend() -> Any:
    """The platform module for the current OS, or None."""
    try:
        if sys.platform.startswith("win"):
            from sentinel.system import platform_win

            return platform_win
        if sys.platform == "darwin":
            from sentinel.system import platform_mac

            return platform_mac
        if sys.platform.startswith("linux"):
            from sentinel.system import platform_linux

            return platform_linux
    except ImportError:
        pass
    return None


def high_value_scan_paths() -> list[str]:
    """Directories a quick scan should cover on this platform.

    Downloads, temp directories and autostart locations — where things
    arrive and where they persist.
    """
    backend = _backend()
    if backend is None:
        return []
    return list(backend.high_value_scan_paths())


def system_report(include_system: bool = True) -> dict[str, Any]:
    """Gather everything ``sentinel system`` displays."""
    privileges = privilege_info()
    autoruns = collect_autoruns(include_system=include_system)
    hosts = read_hosts()
    processes = list_processes(flagged_only=True)

    return {
        "privileges": {
            "elevated": privileges.elevated,
            "user": privileges.user,
            "platform": privileges.platform,
            "label": privileges.label,
            "note": privileges.note,
        },
        "drives": [
            {
                "path": d.path, "label": d.label, "kind": d.kind,
                "filesystem": d.filesystem, "total": d.total, "free": d.free,
            }
            for d in list_drives()
        ],
        "autoruns": {
            "total": len(autoruns),
            "flagged": [e.to_dict() for e in autoruns if e.is_flagged],
        },
        "processes": {
            "flagged": [p.to_dict() for p in processes],
        },
        "hosts": {
            "path": hosts.path,
            "readable": hosts.readable,
            "error": hosts.error,
            "custom_entries": hosts.custom_entry_count,
            "findings": [
                {"severity": f.severity, "message": f.message,
                 "line": f.entry.line_number, "raw": f.entry.raw}
                for f in hosts.findings
            ],
        },
    }
