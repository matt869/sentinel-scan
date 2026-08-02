"""Filesystem traversal.

Walking a whole disk safely is fiddlier than it looks. This module handles:

* **Symlink loops** — off by default; when enabled, visited directories are
  tracked by ``(st_dev, st_ino)`` so a cycle terminates.
* **Windows reparse points** — junctions and OneDrive placeholders look like
  ordinary directories to :func:`os.scandir` but recursing into them either
  loops forever or silently downloads gigabytes from the cloud.
* **Pseudo-filesystems** — ``/proc`` and ``/sys`` are excluded by default.
* **Permission errors** — reported once per directory, never fatal.
* **Cancellation** — checked between entries so a scan stops promptly.

The walker yields :class:`FileEntry` rather than raw paths, because it
already has the ``stat`` result and re-statting every file in the scanner
would double the syscall count.
"""

from __future__ import annotations

import os
import stat
import threading
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path

from sentinel.core.logger import get_logger

log = get_logger(__name__)

#: Windows file attribute bit for a reparse point (junction, symlink,
#: OneDrive placeholder). Not exposed as a named constant by `stat`.
FILE_ATTRIBUTE_REPARSE_POINT = 0x400

#: Windows attribute set on cloud files whose contents are not local.
#: Reading one triggers a download; scanning a OneDrive folder must not
#: pull the user's entire cloud storage onto their disk.
FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS = 0x400000
FILE_ATTRIBUTE_OFFLINE = 0x1000


@dataclass(slots=True)
class FileEntry:
    """One file found by the walker, with its stat information."""

    path: Path
    size: int
    mtime: float
    #: True when the walker itself declined to descend or read it.
    is_symlink: bool = False


@dataclass(slots=True)
class WalkStats:
    """Counters describing what a traversal encountered."""

    files_found: int = 0
    files_skipped: int = 0
    directories: int = 0
    permission_errors: int = 0
    bytes_found: int = 0

    def as_dict(self) -> dict[str, int]:
        return {
            "files_found": self.files_found,
            "files_skipped": self.files_skipped,
            "directories": self.directories,
            "permission_errors": self.permission_errors,
            "bytes_found": self.bytes_found,
        }


class FileWalker:
    """Yields the files under a set of roots, honouring the scan settings."""

    def __init__(
        self,
        settings: object | None = None,
        cancel_event: threading.Event | None = None,
        on_skip: Callable[[Path, str], None] | None = None,
    ) -> None:
        """
        Args:
            settings: A :class:`~sentinel.core.config.ScanSettings`, or None
                for defaults.
            cancel_event: Set to abort traversal between entries.
            on_skip: Called as ``(path, reason)`` for anything skipped.
        """
        self.cancel_event = cancel_event or threading.Event()
        self.on_skip = on_skip
        self.stats = WalkStats()

        self.follow_symlinks = bool(getattr(settings, "follow_symlinks", False))
        self.max_file_size = int(getattr(settings, "max_file_size", 256 * 1024 * 1024))
        self.skip_network = bool(getattr(settings, "skip_network_drives", True))

        excludes: Sequence[str] = getattr(settings, "exclude_paths", ()) or ()
        self._excluded = [self._normalise(p) for p in excludes]

        extensions: Sequence[str] = getattr(settings, "exclude_extensions", ()) or ()
        self._excluded_extensions = {e.lower() for e in extensions}

        # (device, inode) of every directory visited, for loop detection.
        self._seen_dirs: set[tuple[int, int]] = set()

    # -- public API ----------------------------------------------------

    def walk(self, roots: Sequence[str | os.PathLike[str]]) -> Iterator[FileEntry]:
        """Yield every scannable file under *roots*.

        A root that is itself a file is yielded directly, so
        ``sentinel scan one-file.exe`` works.
        """
        for root in roots:
            if self.cancel_event.is_set():
                return

            path = Path(root).expanduser()
            try:
                resolved = path.resolve()
            except OSError as exc:
                self._skip(path, f"cannot resolve: {exc}")
                continue

            if not resolved.exists():
                self._skip(resolved, "does not exist")
                continue

            if resolved.is_file():
                entry = self._entry_for(resolved)
                if entry is not None:
                    yield entry
                continue

            yield from self._walk_directory(resolved)

    def cancel(self) -> None:
        self.cancel_event.set()

    # -- traversal -----------------------------------------------------

    def _walk_directory(self, root: Path) -> Iterator[FileEntry]:
        """Iterative depth-first traversal. Recursion would blow the stack on
        deep trees, and this lets us check cancellation cheaply."""
        pending: list[Path] = [root]

        while pending:
            if self.cancel_event.is_set():
                return

            directory = pending.pop()
            if self._is_excluded(directory):
                self._skip(directory, "excluded by configuration")
                continue

            if not self._enter(directory):
                continue

            self.stats.directories += 1

            try:
                with os.scandir(directory) as entries:
                    for entry in entries:
                        if self.cancel_event.is_set():
                            return
                        # Both handle their own OSError; a single unreadable
                        # entry must not abort the whole directory.
                        self._dispatch(entry, pending)
                        result = self._maybe_file(entry)
                        if result is not None:
                            yield result
            except PermissionError:
                self.stats.permission_errors += 1
                self._skip(directory, "permission denied")
            except OSError as exc:
                self._skip(directory, f"cannot list: {exc}")

    def _dispatch(self, entry: os.DirEntry[str], pending: list[Path]) -> None:
        """Queue directories for later; files are handled by _maybe_file."""
        try:
            is_dir = entry.is_dir(follow_symlinks=self.follow_symlinks)
        except OSError:
            return
        if is_dir:
            pending.append(Path(entry.path))

    def _maybe_file(self, entry: os.DirEntry[str]) -> FileEntry | None:
        """Return a :class:`FileEntry` if this entry should be scanned."""
        try:
            if entry.is_dir(follow_symlinks=self.follow_symlinks):
                return None
        except OSError:
            return None

        path = Path(entry.path)

        try:
            is_symlink = entry.is_symlink()
        except OSError:
            is_symlink = False

        if is_symlink and not self.follow_symlinks:
            # Skipped rather than followed: the target is either inside the
            # scan (and gets scanned on its own) or outside it (and the user
            # did not ask for it).
            self._skip(path, "symlink")
            return None

        try:
            info = entry.stat(follow_symlinks=self.follow_symlinks)
        except OSError as exc:
            self._skip(path, f"stat failed: {exc}")
            return None

        if not stat.S_ISREG(info.st_mode):
            # Devices, FIFOs and sockets. Reading a FIFO blocks forever.
            self._skip(path, "not a regular file")
            return None

        if self._is_cloud_placeholder(info):
            self._skip(path, "cloud placeholder (contents not stored locally)")
            return None

        if path.suffix.lower() in self._excluded_extensions:
            self._skip(path, "excluded extension")
            return None

        if self._is_excluded(path):
            self._skip(path, "excluded by configuration")
            return None

        if info.st_size == 0:
            # Nothing to detect in an empty file, and there are millions.
            self.stats.files_skipped += 1
            return None

        self.stats.files_found += 1
        self.stats.bytes_found += info.st_size
        return FileEntry(
            path=path,
            size=info.st_size,
            mtime=info.st_mtime,
            is_symlink=is_symlink,
        )

    def _entry_for(self, path: Path) -> FileEntry | None:
        """Build an entry for an explicitly-named file, bypassing filters.

        A user who names a file directly means it, so extension exclusions do
        not apply — only hard safety limits.
        """
        try:
            info = path.stat()
        except OSError as exc:
            self._skip(path, f"stat failed: {exc}")
            return None
        if not stat.S_ISREG(info.st_mode):
            self._skip(path, "not a regular file")
            return None

        self.stats.files_found += 1
        self.stats.bytes_found += info.st_size
        return FileEntry(path=path, size=info.st_size, mtime=info.st_mtime)

    # -- filters -------------------------------------------------------

    def _enter(self, directory: Path) -> bool:
        """Decide whether to descend into *directory*."""
        try:
            info = directory.stat()
        except OSError as exc:
            self._skip(directory, f"cannot stat: {exc}")
            return False

        if os.name == "nt" and self._is_reparse_point(info):
            # Junctions create cycles (C:\Users\All Users -> C:\ProgramData)
            # and cloud folders re-download on access.
            self._skip(directory, "reparse point / junction")
            return False

        key = (info.st_dev, info.st_ino)
        if key in self._seen_dirs:
            self._skip(directory, "already visited (symlink loop)")
            return False
        # Only track when following links; otherwise a hardlinked directory
        # cannot occur and the set just wastes memory on a large disk.
        if self.follow_symlinks:
            self._seen_dirs.add(key)

        return True

    def _is_excluded(self, path: Path) -> bool:
        normalised = self._normalise(path)
        return any(
            normalised == excluded or normalised.startswith(excluded + os.sep)
            for excluded in self._excluded
        )

    @staticmethod
    def _normalise(path: str | os.PathLike[str]) -> str:
        """Case-fold on Windows so exclusions are not case-sensitive there."""
        text = os.path.normpath(str(path))
        return text.lower() if os.name == "nt" else text

    @staticmethod
    def _is_reparse_point(info: os.stat_result) -> bool:
        attributes = getattr(info, "st_file_attributes", 0)
        return bool(attributes & FILE_ATTRIBUTE_REPARSE_POINT)

    @staticmethod
    def _is_cloud_placeholder(info: os.stat_result) -> bool:
        """True for OneDrive/Dropbox files that are not stored locally."""
        attributes = getattr(info, "st_file_attributes", 0)
        if not attributes:
            return False
        return bool(
            attributes & FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS
            or (attributes & FILE_ATTRIBUTE_OFFLINE and attributes
                & FILE_ATTRIBUTE_REPARSE_POINT)
        )

    def _skip(self, path: Path, reason: str) -> None:
        self.stats.files_skipped += 1
        log.debug("skipping %s: %s", path, reason)
        if self.on_skip is not None:
            try:
                self.on_skip(path, reason)
            except Exception:  # pragma: no cover - listener bug
                log.exception("on_skip callback failed")


def count_files(roots: Sequence[str | os.PathLike[str]], settings: object | None = None,
                limit: int = 500_000) -> int:
    """Estimate the file count under *roots*, for a determinate progress bar.

    Stops at *limit* — knowing "more than half a million" is enough to switch
    the UI to an indeterminate spinner, and counting the rest costs a full
    extra traversal.
    """
    walker = FileWalker(settings)
    total = 0
    for _ in walker.walk(roots):
        total += 1
        if total >= limit:
            break
    return total
