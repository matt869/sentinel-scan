"""Enumerating mounted volumes.

Used to build the "scan a drive" list in the GUI, and to let the walker skip
network and removable media when configured to. Falls back to a
platform-specific path when :mod:`psutil` is unavailable, so the drive list
still works on a minimal install.
"""

from __future__ import annotations

import os
import shutil
import string
from dataclasses import dataclass
from pathlib import Path

from sentinel.core.logger import get_logger

log = get_logger(__name__)

try:
    import psutil

    _PSUTIL_AVAILABLE = True
except ImportError:  # pragma: no cover - depends on the environment
    psutil = None  # type: ignore[assignment]
    _PSUTIL_AVAILABLE = False


#: Filesystem types that are kernel state, not storage. Scanning them is
#: pointless and sometimes hangs.
PSEUDO_FILESYSTEMS = frozenset(
    {
        "proc", "sysfs", "devtmpfs", "devpts", "tmpfs", "cgroup", "cgroup2",
        "securityfs", "pstore", "bpf", "debugfs", "tracefs", "configfs",
        "fusectl", "hugetlbfs", "mqueue", "autofs", "binfmt_misc", "squashfs",
        "overlay", "ramfs", "nsfs",
    }
)

#: Filesystem types served over a network. Scanning these is slow and often
#: not the user's data to scan.
NETWORK_FILESYSTEMS = frozenset(
    {"nfs", "nfs4", "cifs", "smbfs", "smb2", "afpfs", "sshfs", "webdav", "ftpfs"}
)


@dataclass(frozen=True, slots=True)
class Drive:
    """A mounted volume."""

    path: str
    label: str
    filesystem: str
    total: int
    free: int
    kind: str  # fixed | removable | network | optical | pseudo | unknown

    @property
    def used(self) -> int:
        return max(self.total - self.free, 0)

    @property
    def is_scannable(self) -> bool:
        return self.kind not in {"pseudo", "optical"} and self.total > 0

    @property
    def usage_percent(self) -> float:
        return (self.used / self.total * 100) if self.total else 0.0

    def __str__(self) -> str:
        return f"{self.path} ({self.label or self.kind}, {self.filesystem})"


def list_drives(include_pseudo: bool = False) -> list[Drive]:
    """Return every mounted volume.

    Args:
        include_pseudo: Include ``/proc``-style pseudo filesystems.
    """
    drives = _list_psutil() if _PSUTIL_AVAILABLE else _list_fallback()
    if not include_pseudo:
        drives = [d for d in drives if d.kind != "pseudo"]
    return sorted(drives, key=lambda d: d.path)


def _list_psutil() -> list[Drive]:
    out: list[Drive] = []
    try:
        partitions = psutil.disk_partitions(all=True)
    except Exception as exc:
        log.debug("psutil.disk_partitions failed: %s", exc)
        return _list_fallback()

    for partition in partitions:
        filesystem = (partition.fstype or "").lower()
        kind = _classify(partition.mountpoint, filesystem, partition.opts or "")

        total = free = 0
        if kind not in {"pseudo", "optical"}:
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                total, free = usage.total, usage.free
            except (OSError, PermissionError):
                # An empty optical drive or an unreadable mount.
                pass

        out.append(
            Drive(
                path=partition.mountpoint,
                label=_label_for(partition.mountpoint),
                filesystem=filesystem or "unknown",
                total=total,
                free=free,
                kind=kind,
            )
        )
    return out


def _list_fallback() -> list[Drive]:
    """Enumerate without psutil."""
    if os.name == "nt":
        return _list_windows_letters()
    return _list_posix_mounts()


def _list_windows_letters() -> list[Drive]:
    """Probe A: through Z: for volumes that respond."""
    out: list[Drive] = []
    for letter in string.ascii_uppercase:
        root = f"{letter}:\\"
        if not os.path.exists(root):
            continue
        total = free = 0
        try:
            usage = shutil.disk_usage(root)
            total, free = usage.total, usage.free
        except OSError:
            continue
        out.append(
            Drive(
                path=root,
                label=_label_for(root),
                filesystem="unknown",
                total=total,
                free=free,
                kind=_windows_drive_kind(root),
            )
        )
    return out


def _list_posix_mounts() -> list[Drive]:
    """Parse /proc/mounts, falling back to just ``/``."""
    out: list[Drive] = []
    try:
        with open("/proc/mounts", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) < 3:
                    continue
                mountpoint, filesystem = parts[1], parts[2].lower()
                kind = _classify(mountpoint, filesystem, "")
                total = free = 0
                if kind != "pseudo":
                    try:
                        usage = shutil.disk_usage(mountpoint)
                        total, free = usage.total, usage.free
                    except OSError:
                        continue
                out.append(
                    Drive(
                        path=mountpoint,
                        label=Path(mountpoint).name or mountpoint,
                        filesystem=filesystem,
                        total=total,
                        free=free,
                        kind=kind,
                    )
                )
    except OSError:
        try:
            usage = shutil.disk_usage("/")
            out.append(Drive("/", "root", "unknown", usage.total, usage.free, "fixed"))
        except OSError:
            pass
    return out


def _classify(mountpoint: str, filesystem: str, options: str) -> str:
    """Bucket a mount into fixed/removable/network/optical/pseudo."""
    if filesystem in PSEUDO_FILESYSTEMS:
        return "pseudo"
    if filesystem in NETWORK_FILESYSTEMS or mountpoint.startswith("\\\\"):
        return "network"
    if filesystem in {"iso9660", "udf", "cdfs"}:
        return "optical"
    if "removable" in options.lower():
        return "removable"

    if os.name == "nt" and len(mountpoint) >= 2 and mountpoint[1] == ":":
        return _windows_drive_kind(mountpoint)

    # Common removable mount roots on Linux and macOS.
    for prefix in ("/media/", "/mnt/", "/run/media/", "/Volumes/"):
        if mountpoint.startswith(prefix):
            return "removable"

    return "fixed"


def _windows_drive_kind(root: str) -> str:
    """Ask Windows what kind of drive this is."""
    try:
        import ctypes

        drive_type = ctypes.windll.kernel32.GetDriveTypeW(ctypes.c_wchar_p(root))
    except Exception:
        return "unknown"

    return {
        2: "removable",
        3: "fixed",
        4: "network",
        5: "optical",
        6: "fixed",  # RAM disk
    }.get(drive_type, "unknown")


def _label_for(mountpoint: str) -> str:
    """Volume label, or the mount point's own name."""
    if os.name == "nt":
        try:
            import ctypes

            buffer = ctypes.create_unicode_buffer(261)
            ctypes.windll.kernel32.GetVolumeInformationW(
                ctypes.c_wchar_p(mountpoint), buffer, 261,
                None, None, None, None, 0,
            )
            if buffer.value:
                return buffer.value
        except Exception:
            pass
        return mountpoint.rstrip("\\")
    return Path(mountpoint).name or mountpoint


def scannable_roots(skip_network: bool = True, skip_removable: bool = False) -> list[str]:
    """The drive paths a full-system scan should cover."""
    roots = []
    for drive in list_drives():
        if not drive.is_scannable:
            continue
        if skip_network and drive.kind == "network":
            continue
        if skip_removable and drive.kind == "removable":
            continue
        roots.append(drive.path)
    return roots


def removable_drives() -> list[Drive]:
    """Removable volumes — the ones worth offering an on-insert scan for."""
    return [d for d in list_drives() if d.kind == "removable" and d.total > 0]
