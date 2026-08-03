"""Measuring the machine, and deciding how hard to work it.

Users cannot answer "what performance mode would you like?". They do not know
what a worker thread is, they have no way to guess what 20,000 YARA rules
cost, and asking makes them responsible for a decision they will get wrong
and then blame the software for. So Sentinel measures the machine at first
launch and picks its own settings.

But it *tells them what it chose*, in words they can check against what they
know about their own computer:

    Your drive is a hard disk, so Sentinel checks one file at a time.
    That is faster on drives like yours.

That sentence converts a limitation into evidence that the software looked at
their machine and respected it, which is worth more than the setting itself.

The three measurements that matter
----------------------------------
**Is the disk spinning?** The single biggest factor, and the least obvious.
Parallel reads on a rotating platter make the head seek between them and
roughly halve throughput — so on a hard disk the right number of workers is
one, and the core count is irrelevant. Getting this backwards is the
difference between a forty-minute scan and a ninety-minute one.

**How much memory is there?** Rule sets are the largest allocation in the
process by far, and on a 4 GB machine that is also running a browser, a
smaller high-value rule set costs a little detection and buys back a lot of
the user's afternoon.

**How many cores?** Only once the disk has been ruled out as the bottleneck.

Detection order is: ask the operating system, and if it will not say, time
some random reads — a rotating disk cannot hide a seek. Anything still
unresolved is treated as rotating, because being conservative on a solid-state
drive costs some speed, while being wrong the other way makes a hard disk
thrash.
"""

from __future__ import annotations

import os
import random
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from sentinel.core.logger import get_logger

log = get_logger(__name__)

try:
    import psutil

    PSUTIL_AVAILABLE = True
except ImportError:  # pragma: no cover - depends on the environment
    psutil = None  # type: ignore[assignment]
    PSUTIL_AVAILABLE = False


class StorageKind(str, Enum):
    ROTATIONAL = "rotational"
    SOLID_STATE = "solid-state"
    UNKNOWN = "unknown"


class MachineTier(str, Enum):
    """How much this computer can spare."""

    MODEST = "modest"
    CAPABLE = "capable"


#: At or below this much RAM, trim the rule set and the buffers. Chosen at
#: 6 GB rather than 4 so the 4 GB target machine is comfortably inside it
#: rather than sitting on the boundary.
MODEST_RAM_BYTES = 6 * 1024**3

#: Seek latency above this says "rotating platter". A hard disk seek is
#: 5-15ms; an SSD is under half a millisecond. The gap is two orders of
#: magnitude, so the threshold does not need to be precise.
SEEK_PENALTY_MS = 2.0

#: Random reads taken by the probe. Enough to average out one unlucky hit in
#: the OS cache, few enough to finish in well under a second either way.
PROBE_READS = 12
PROBE_BLOCK = 4096


@dataclass(frozen=True, slots=True)
class HardwareProfile:
    """What this machine is."""

    total_ram_bytes: int = 0
    physical_cores: int = 1
    logical_cores: int = 1
    storage: StorageKind = StorageKind.UNKNOWN
    #: How the storage kind was established, for the log and for support.
    storage_source: str = "not detected"

    @property
    def tier(self) -> MachineTier:
        if self.total_ram_bytes and self.total_ram_bytes <= MODEST_RAM_BYTES:
            return MachineTier.MODEST
        if self.logical_cores <= 2:
            return MachineTier.MODEST
        return MachineTier.CAPABLE

    @property
    def ram_gb(self) -> float:
        return self.total_ram_bytes / 1024**3

    @property
    def spins(self) -> bool:
        """Whether to assume a seek penalty.

        Unknown counts as spinning. On a solid-state drive that costs some
        speed; the other way round makes a hard disk thrash, and one of those
        mistakes is much worse than the other.
        """
        return self.storage is not StorageKind.SOLID_STATE


@dataclass(frozen=True, slots=True)
class Tuning:
    """The settings chosen for a machine, and why."""

    threads: int = 1
    max_file_size: int = 256 * 1024 * 1024
    #: Cap on YARA rule files compiled. 0 means no limit.
    yara_file_budget: int = 0
    reasons: list[str] = field(default_factory=list)

    def explain(self) -> str:
        """The plain-English summary shown to the user."""
        return "\n".join(self.reasons)


# ----------------------------------------------------------------------
# measuring
# ----------------------------------------------------------------------

def detect_storage(path: str | os.PathLike[str] | None = None) -> tuple[StorageKind, str]:
    """Whether the drive holding *path* spins. Returns ``(kind, how)``."""
    target = Path(path) if path else Path.home()

    for probe in (_storage_from_os, _storage_from_seek_time):
        try:
            kind, source = probe(target)
        except Exception as exc:
            log.debug("storage probe %s failed: %s", probe.__name__, exc)
            continue
        if kind is not StorageKind.UNKNOWN:
            return kind, source

    return StorageKind.UNKNOWN, "not detected"


def _storage_from_os(target: Path) -> tuple[StorageKind, str]:
    """Ask the operating system directly."""
    if os.name == "nt":
        return _windows_seek_penalty(target)
    if _is_linux():
        return _linux_rotational(target)
    if _is_macos():
        return _macos_solid_state(target)
    return StorageKind.UNKNOWN, ""


def _is_linux() -> bool:
    import sys

    return sys.platform.startswith("linux")


def _is_macos() -> bool:
    import sys

    return sys.platform == "darwin"


def _linux_rotational(target: Path) -> tuple[StorageKind, str]:
    """Read ``/sys/block/<device>/queue/rotational``.

    1 means a rotating platter, 0 means solid state. The kernel knows, so
    there is nothing to infer.
    """
    try:
        device = os.stat(target).st_dev
    except OSError:
        return StorageKind.UNKNOWN, ""

    # os.major/os.minor exist only on Unix, and this function only runs
    # there — fetched by name so a type checker on Windows does not have to
    # pretend otherwise.
    major = getattr(os, "major")(device)  # noqa: B009
    minor = getattr(os, "minor")(device)  # noqa: B009
    link = Path(f"/sys/dev/block/{major}:{minor}")
    try:
        resolved = link.resolve()
    except OSError:
        return StorageKind.UNKNOWN, ""

    # Walk up from the partition to its parent disk, which is where the
    # queue directory lives.
    for candidate in (resolved, *resolved.parents):
        flag = candidate / "queue" / "rotational"
        if flag.is_file():
            value = flag.read_text(encoding="ascii").strip()
            kind = StorageKind.ROTATIONAL if value == "1" else StorageKind.SOLID_STATE
            return kind, f"the kernel ({flag})"
    return StorageKind.UNKNOWN, ""


def _macos_solid_state(target: Path) -> tuple[StorageKind, str]:
    """Ask ``diskutil`` whether the volume is solid state."""
    import subprocess

    completed = subprocess.run(
        ["/usr/sbin/diskutil", "info", str(target)],
        capture_output=True, text=True, timeout=10, check=False,
    )
    for line in completed.stdout.splitlines():
        if "Solid State" in line:
            value = line.split(":", 1)[-1].strip().lower()
            kind = StorageKind.SOLID_STATE if value.startswith("yes") else (
                StorageKind.ROTATIONAL
            )
            return kind, "diskutil"
    return StorageKind.UNKNOWN, ""


def _windows_seek_penalty(target: Path) -> tuple[StorageKind, str]:
    """Ask the storage driver whether this device incurs a seek penalty.

    ``IOCTL_STORAGE_QUERY_PROPERTY`` with
    ``StorageDeviceSeekPenaltyProperty`` is the authoritative answer, and the
    volume handle can be opened with *no* access rights, so this works
    without administrator privileges — which matters, because most people
    will never run this elevated.
    """
    import ctypes
    from ctypes import wintypes

    drive = os.path.splitdrive(os.path.abspath(target))[0]
    if not drive:
        return StorageKind.UNKNOWN, ""

    class STORAGE_PROPERTY_QUERY(ctypes.Structure):
        _fields_ = [
            ("PropertyId", wintypes.DWORD),
            ("QueryType", wintypes.DWORD),
            ("AdditionalParameters", ctypes.c_byte * 1),
        ]

    class DEVICE_SEEK_PENALTY_DESCRIPTOR(ctypes.Structure):
        _fields_ = [
            ("Version", wintypes.DWORD),
            ("Size", wintypes.DWORD),
            ("IncursSeekPenalty", wintypes.BOOLEAN),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    ]

    handle = kernel32.CreateFileW(
        f"\\\\.\\{drive}", 0,                       # no access rights needed
        0x00000001 | 0x00000002,                    # share read | write
        None, 3,                                    # OPEN_EXISTING
        0x00000080, None,                           # FILE_ATTRIBUTE_NORMAL
    )
    if handle == wintypes.HANDLE(-1).value or not handle:
        return StorageKind.UNKNOWN, ""

    try:
        query = STORAGE_PROPERTY_QUERY()
        query.PropertyId = 7      # StorageDeviceSeekPenaltyProperty
        query.QueryType = 0       # PropertyStandardQuery

        result = DEVICE_SEEK_PENALTY_DESCRIPTOR()
        returned = wintypes.DWORD()

        ok = kernel32.DeviceIoControl(
            handle,
            0x002D1400,                             # IOCTL_STORAGE_QUERY_PROPERTY
            ctypes.byref(query), ctypes.sizeof(query),
            ctypes.byref(result), ctypes.sizeof(result),
            ctypes.byref(returned), None,
        )
        if not ok or returned.value == 0:
            return StorageKind.UNKNOWN, ""

        kind = (
            StorageKind.ROTATIONAL if result.IncursSeekPenalty
            else StorageKind.SOLID_STATE
        )
        return kind, "the storage driver"
    finally:
        kernel32.CloseHandle(handle)


def _storage_from_seek_time(target: Path) -> tuple[StorageKind, str]:
    """Time some random reads. A rotating platter cannot hide a seek.

    The fallback for when the OS will not say — a USB enclosure, an unusual
    driver, a virtual machine. Reads an existing file at random offsets, so
    nothing is written and nothing is left behind.
    """
    probe_file = _largest_nearby_file(target)
    if probe_file is None:
        return StorageKind.UNKNOWN, ""

    size = probe_file.stat().st_size
    if size < PROBE_BLOCK * 64:
        return StorageKind.UNKNOWN, ""

    # Fixed seed: the probe should give the same answer twice on the same
    # machine, or the setting it decides flickers between launches.
    return _time_reads(probe_file, size, random.Random(20260803))


def _time_reads(
    probe_file: Path, size: int, rng: random.Random
) -> tuple[StorageKind, str]:
    latencies: list[float] = []
    try:
        with open(probe_file, "rb", buffering=0) as handle:
            for _ in range(PROBE_READS):
                offset = rng.randrange(0, size - PROBE_BLOCK)
                started = time.perf_counter()
                handle.seek(offset)
                handle.read(PROBE_BLOCK)
                latencies.append((time.perf_counter() - started) * 1000)
    except OSError:
        return StorageKind.UNKNOWN, ""

    if len(latencies) < PROBE_READS // 2:
        return StorageKind.UNKNOWN, ""

    # Median, not mean: one page-cache hit near zero and one unlucky 40ms
    # outlier should both fail to move the answer.
    latencies.sort()
    median = latencies[len(latencies) // 2]
    kind = (
        StorageKind.ROTATIONAL if median >= SEEK_PENALTY_MS else StorageKind.SOLID_STATE
    )
    log.debug("seek probe median %.2fms -> %s", median, kind.value)
    return kind, f"timing reads ({median:.1f}ms per seek)"


def _largest_nearby_file(target: Path) -> Path | None:
    """A file on the same volume big enough to seek around in."""
    directory = target if target.is_dir() else target.parent
    best: Path | None = None
    best_size = 0
    try:
        for entry in os.scandir(directory):
            try:
                if entry.is_file() and entry.stat().st_size > best_size:
                    best, best_size = Path(entry.path), entry.stat().st_size
            except OSError:
                continue
    except OSError:
        return None
    return best


def profile_machine(data_dir: str | os.PathLike[str] | None = None) -> HardwareProfile:
    """Measure this computer. Never raises."""
    total_ram = 0
    physical = logical = os.cpu_count() or 1

    if PSUTIL_AVAILABLE:
        try:
            total_ram = int(psutil.virtual_memory().total)
            physical = psutil.cpu_count(logical=False) or physical
            logical = psutil.cpu_count(logical=True) or logical
        except Exception as exc:  # pragma: no cover - platform dependent
            log.debug("cannot read memory or cpu counts: %s", exc)

    kind, source = detect_storage(data_dir)
    profile = HardwareProfile(
        total_ram_bytes=total_ram,
        physical_cores=physical,
        logical_cores=logical,
        storage=kind,
        storage_source=source,
    )
    log.info(
        "hardware: %.1f GB RAM, %d cores, %s storage (%s)",
        profile.ram_gb, profile.logical_cores, kind.value, source,
    )
    return profile


# ----------------------------------------------------------------------
# deciding
# ----------------------------------------------------------------------

def recommend(profile: HardwareProfile) -> Tuning:
    """Pick settings for *profile*, with a sentence for each choice.

    Every reason is written to be checkable by someone who knows nothing
    about scanners but does know what is in their own computer.
    """
    reasons: list[str] = []

    if profile.spins:
        threads = 1
        if profile.storage is StorageKind.ROTATIONAL:
            reasons.append(
                "Your drive is a hard disk, so Sentinel checks one file at a "
                "time. That is faster on drives like yours — reading several "
                "at once makes the drive jump back and forth."
            )
        else:
            reasons.append(
                "Sentinel couldn't tell what kind of drive you have, so it "
                "checks one file at a time. That is the safe choice: it is "
                "never much slower, and on an older drive it is much faster."
            )
    else:
        # Solid state: parallelism helps, but past a handful of workers the
        # gain flattens while memory keeps climbing.
        threads = max(2, min(profile.logical_cores, 8))
        reasons.append(
            f"Your drive is a solid-state drive, so Sentinel checks "
            f"{threads} files at once."
        )

    if profile.tier is MachineTier.MODEST:
        yara_budget = 400
        max_file_size = 64 * 1024 * 1024
        reasons.append(
            f"Your computer has {profile.ram_gb:.0f} GB of memory, so Sentinel "
            f"uses a smaller list of the most common threats. It stays out of "
            f"the way of whatever else you're doing."
        )
    else:
        yara_budget = 0
        max_file_size = 256 * 1024 * 1024
        reasons.append(
            f"Your computer has {profile.ram_gb:.0f} GB of memory, so Sentinel "
            f"uses its full list of threats."
        )

    return Tuning(
        threads=threads,
        max_file_size=max_file_size,
        yara_file_budget=yara_budget,
        reasons=reasons,
    )


def apply_to(config: object, tuning: Tuning) -> None:
    """Write *tuning* onto a configuration object in place."""
    scan = getattr(config, "scan", None)
    if scan is not None:
        scan.threads = tuning.threads
        scan.max_file_size = tuning.max_file_size

    detectors = getattr(config, "detectors", None)
    if detectors is not None and hasattr(detectors, "yara_file_budget"):
        detectors.yara_file_budget = tuning.yara_file_budget


#: kv keys recording that this machine has been measured, and what was found.
TUNED_KEY = "hardware.tuned_at"
SUMMARY_KEY = "hardware.summary"


def tune_once(config: object, db: object, *, force: bool = False) -> Tuning | None:
    """Measure the machine and apply the result, the first time only.

    Returns the :class:`Tuning` if one was applied, or None if this machine
    has already been measured. Never raises — a failure here must not stop a
    scan, it just means the defaults stand.

    Persisted rather than re-measured every launch for two reasons. The seek
    probe costs a tenth of a second, which is not free on the machines this
    matters for; and a value that is re-derived on every start can *change*
    on every start, so the user who read "checks one file at a time" and
    later sees something else has caught the software contradicting itself.
    ``force`` re-runs it, for when the hardware really has changed.
    """
    try:
        if not force and _get(db, TUNED_KEY):
            return None
    except Exception as exc:
        log.debug("cannot read the tuning marker: %s", exc)
        return None

    try:
        data_dir = getattr(getattr(config, "paths", None), "data_dir", None)
        profile = profile_machine(data_dir)
        tuning = recommend(profile)
        apply_to(config, tuning)
    except Exception as exc:
        log.warning("could not measure this machine; using defaults: %s", exc)
        return None

    # Write the chosen values to the configuration file, not just to the
    # object in memory. Without this the settings last exactly one run: the
    # next start reloads threads=0, which means "decide automatically", which
    # on a hard disk means sixteen workers thrashing a drive we already
    # established should be reading one file at a time. Persisting also makes
    # the choice visible and editable, which is the point of telling the user
    # about it at all.
    _persist(config)

    try:
        _set(db, TUNED_KEY, str(time.time()))
        _set(db, SUMMARY_KEY, tuning.explain())
    except Exception as exc:
        log.debug("cannot record the tuning result: %s", exc)

    log.info("tuned for this machine: %s", tuning.explain().replace("\n", " "))
    return tuning


def stored_summary(db: object) -> str:
    """The explanation recorded the last time this machine was measured."""
    try:
        return _get(db, SUMMARY_KEY) or ""
    except Exception:
        return ""


def _persist(config: object) -> None:
    """Write the configuration back to disk, tolerating a read-only one."""
    try:
        from sentinel.core.config import Config, save_config

        if isinstance(config, Config):
            path = save_config(config)
            log.debug("wrote the chosen settings to %s", path)
    except Exception as exc:
        # A read-only config directory means the settings apply to this run
        # only, which is worse than persisting but far better than failing.
        log.warning("could not save the chosen settings: %s", exc)


def _get(db: object, key: str) -> str | None:
    getter = getattr(db, "get_setting", None)
    return getter(key) if getter else None


def _set(db: object, key: str, value: str) -> None:
    setter = getattr(db, "set_setting", None)
    if setter:
        setter(key, value)
