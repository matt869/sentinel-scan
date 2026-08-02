"""The detector plugin contract.

A detector inspects one :class:`ScanTarget` and returns zero or more
:class:`~sentinel.engine.verdict.Detection` objects. Rules of the road:

* **Never raise.** A detector that throws is disabled for the rest of the
  scan and logged. Return an empty list when you cannot decide.
* **Never mutate the target.** Detectors run concurrently on the same object.
* **Read through the target, not the path.** :class:`ScanTarget` caches the
  file's bytes and hashes so eight detectors do not read the same file eight
  times.
* **Declare your appetite.** Override :attr:`wants` so the engine can skip
  you cheaply for file types you do not care about.

See docs/writing-detectors.md for a worked example.
"""

from __future__ import annotations

import abc
import os
import threading
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ClassVar

from sentinel.core.logger import get_logger
from sentinel.engine.verdict import Detection
from sentinel.utils.entropy import EntropyProfile, profile
from sentinel.utils.file_types import FileType, TypeInfo, guess_type
from sentinel.utils.hashing import HashError, hash_file_multi

log = get_logger(__name__)

#: Files bigger than this are never fully buffered; detectors that need the
#: whole file get None from :meth:`ScanTarget.data` and should fall back to
#: streaming or skip.
MAX_BUFFER_SIZE = 64 * 1024 * 1024


@dataclass
class ScanTarget:
    """One file being scanned, with lazily-computed shared state.

    Instances are created per file by the engine and shared across all
    detectors for that file. Every expensive property is memoised behind a
    lock so concurrent detectors compute it once.
    """

    path: Path
    size: int = 0
    #: Depth inside nested archives; 0 for a file on disk.
    depth: int = 0
    #: For extracted archive members, the path of the containing archive.
    container: Path | None = None
    #: Name inside the container, when different from ``path.name``.
    member_name: str = ""

    # Re-entrant on purpose: the memoised properties call each other while
    # holding the lock (type_info -> header, entropy -> data). A plain Lock
    # deadlocks the worker thread on the second acquire.
    _lock: Any = field(default_factory=threading.RLock, repr=False)
    _data: bytes | None = field(default=None, repr=False)
    _data_loaded: bool = field(default=False, repr=False)
    _header: bytes | None = field(default=None, repr=False)
    _hashes: dict[str, str] | None = field(default=None, repr=False)
    _type_info: TypeInfo | None = field(default=None, repr=False)
    _entropy: EntropyProfile | None = field(default=None, repr=False)
    #: Set when the file could not be read; detectors should bail out.
    read_error: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        self.path = Path(self.path)
        if not self.size:
            try:
                self.size = self.path.stat().st_size
            except OSError:
                self.size = 0

    # -- lazily computed views over the file ---------------------------

    @property
    def header(self) -> bytes:
        """First 4 KiB of the file. Cheap; safe to call on huge files."""
        with self._lock:
            if self._header is None:
                if self._data_loaded and self._data is not None:
                    self._header = self._data[:4096]
                else:
                    try:
                        with open(self.path, "rb", buffering=0) as fh:
                            self._header = fh.read(4096)
                    except OSError as exc:
                        self.read_error = str(exc)
                        self._header = b""
            return self._header

    @property
    def data(self) -> bytes | None:
        """The whole file, or None if it is too large to buffer."""
        with self._lock:
            if not self._data_loaded:
                self._data_loaded = True
                if self.size > MAX_BUFFER_SIZE:
                    log.debug("not buffering %s (%d bytes)", self.path, self.size)
                    self._data = None
                else:
                    try:
                        self._data = self.path.read_bytes()
                    except OSError as exc:
                        self.read_error = str(exc)
                        self._data = None
            return self._data

    @property
    def hashes(self) -> dict[str, str]:
        """md5/sha1/sha256 of the file, computed in one pass."""
        with self._lock:
            if self._hashes is None:
                try:
                    self._hashes = hash_file_multi(self.path)
                except HashError as exc:
                    self.read_error = str(exc)
                    self._hashes = {}
            return self._hashes

    @property
    def sha256(self) -> str:
        return self.hashes.get("sha256", "")

    @property
    def md5(self) -> str:
        return self.hashes.get("md5", "")

    @property
    def sha1(self) -> str:
        return self.hashes.get("sha1", "")

    @property
    def type_info(self) -> TypeInfo:
        with self._lock:
            if self._type_info is None:
                self._type_info = guess_type(self.path, self.header)
            return self._type_info

    @property
    def file_type(self) -> FileType:
        return self.type_info.file_type

    @property
    def entropy(self) -> EntropyProfile:
        """Entropy profile of the buffered contents (zeros if unbuffered)."""
        with self._lock:
            if self._entropy is None:
                data = self.data
                self._entropy = profile(data if data is not None else b"")
            return self._entropy

    # -- convenience ---------------------------------------------------

    @property
    def display_path(self) -> str:
        """Path shown to the user, including the archive chain."""
        if self.container is not None:
            inner = self.member_name or self.path.name
            return f"{self.container}!{inner}"
        return str(self.path)

    @property
    def extension(self) -> str:
        return self.path.suffix.lower()

    def text(self, encoding: str = "utf-8", limit: int = 4 * 1024 * 1024) -> str:
        """Decode the file as text, replacing undecodable bytes.

        Returns an empty string when the file is unbuffered or unreadable.
        Truncated at *limit* bytes — script heuristics do not need more.
        """
        data = self.data
        if data is None:
            return ""
        return data[:limit].decode(encoding, errors="replace")

    def release(self) -> None:
        """Drop the buffered contents once every detector has run."""
        with self._lock:
            self._data = None
            self._data_loaded = False
            self._entropy = None


class Detector(abc.ABC):
    """Base class for all detectors."""

    #: Stable identifier, used in config keys and detection records.
    name: ClassVar[str] = "unnamed"

    #: One-line description shown by ``sentinel detectors``.
    description: ClassVar[str] = ""

    #: File types this detector wants. Empty means "everything".
    wants: ClassVar[frozenset[FileType]] = frozenset()

    #: Detectors with a lower value run first. Cheap, decisive detectors
    #: (hash lookups) go first so an early conclusive hit can short-circuit.
    priority: ClassVar[int] = 100

    #: Set False for detectors that must not run on archive members.
    scans_archive_members: ClassVar[bool] = True

    def __init__(self, config: Any = None) -> None:
        self.config = config
        self.log = get_logger(f"detector.{self.name}")
        self._unavailable_reason: str | None = None

    # -- lifecycle -----------------------------------------------------

    def available(self) -> bool:
        """Whether this detector can run at all.

        Override to check for an optional import or a reachable daemon. The
        default is always available. Set :attr:`_unavailable_reason` when
        returning False so the CLI can explain the gap.
        """
        return True

    @property
    def unavailable_reason(self) -> str:
        return self._unavailable_reason or "not available"

    # Deliberately concrete no-ops, not abstract: most detectors need no
    # setup at all, and forcing every subclass to write two empty methods
    # would be noise.
    def setup(self) -> None:  # noqa: B027
        """Load rules, open sockets, warm caches. Called once per scan.

        Raising here disables the detector for that scan; the engine logs the
        reason and continues with the rest.
        """

    def teardown(self) -> None:  # noqa: B027
        """Release anything :meth:`setup` acquired. Always called."""

    # -- scanning ------------------------------------------------------

    def interested_in(self, target: ScanTarget) -> bool:
        """Fast pre-filter, called before :meth:`scan`.

        The default honours :attr:`wants`. Override for cheaper checks that
        avoid touching the file at all.
        """
        if target.depth > 0 and not self.scans_archive_members:
            return False
        if not self.wants:
            return True
        return target.file_type in self.wants

    @abc.abstractmethod
    def scan(self, target: ScanTarget) -> Sequence[Detection]:
        """Inspect *target* and return any detections.

        Must not raise; return an empty sequence when undecided.
        """

    # -- helpers for subclasses ----------------------------------------

    def detection(
        self,
        name: str,
        confidence: float,
        description: str = "",
        *,
        conclusive: bool = False,
        **metadata: Any,
    ) -> Detection:
        """Build a :class:`Detection` attributed to this detector."""
        return Detection(
            detector=self.name,
            name=name,
            confidence=confidence,
            description=description,
            conclusive=conclusive,
            metadata=metadata,
        )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<{type(self).__name__} name={self.name!r}>"


class DetectorRegistry:
    """Holds the known detector classes and instantiates the enabled ones."""

    def __init__(self) -> None:
        self._classes: dict[str, type[Detector]] = {}

    def register(self, cls: type[Detector]) -> type[Detector]:
        """Register a detector class. Usable as a decorator."""
        if cls.name in self._classes and self._classes[cls.name] is not cls:
            raise ValueError(f"duplicate detector name {cls.name!r}")
        self._classes[cls.name] = cls
        return cls

    def names(self) -> list[str]:
        return sorted(self._classes)

    def get(self, name: str) -> type[Detector] | None:
        return self._classes.get(name)

    def build(
        self,
        config: Any,
        enabled: Iterable[str] | None = None,
    ) -> list[Detector]:
        """Instantiate the enabled, available detectors in priority order.

        Detectors that report themselves unavailable are logged at INFO and
        omitted — a missing optional dependency is a normal state, not an
        error.
        """
        wanted = set(enabled) if enabled is not None else set(self._classes)
        built: list[Detector] = []

        for name in sorted(self._classes):
            if name not in wanted:
                continue
            cls = self._classes[name]
            try:
                detector = cls(config)
            except Exception as exc:
                log.warning("detector %s failed to construct: %s", name, exc)
                continue
            if not detector.available():
                log.info("detector %s unavailable: %s", name, detector.unavailable_reason)
                continue
            built.append(detector)

        built.sort(key=lambda d: (d.priority, d.name))
        return built


#: The process-wide registry. Detector modules register themselves on import;
#: :mod:`sentinel.engine.detectors` imports them all.
registry = DetectorRegistry()


def target_from_path(path: str | os.PathLike[str], **kwargs: Any) -> ScanTarget:
    """Convenience constructor used by tests and one-off scans."""
    return ScanTarget(path=Path(path), **kwargs)
