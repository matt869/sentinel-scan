"""Suppression of known-good files.

Three kinds of entry:

``sha256``
    Exact content match. Survives the file being renamed or moved, and
    cannot be abused by an attacker who can write to a whitelisted path.
    This is the kind to prefer.

``path``
    One exact path. Convenient, but weaker: whatever ends up at that path is
    trusted, so whitelisting a path an attacker can write to is a hole.

``prefix``
    A directory subtree. Weakest of all, and the one that actually gets
    people compromised — ``C:\\`` in this list disables the scanner. The
    engine refuses obviously dangerous prefixes outright.

Entries live in the local database. This class loads them into memory once
per scan, because the check runs on every file and a SQL round trip per file
would dominate the scan time.
"""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sentinel.core.logger import get_logger

log = get_logger(__name__)

#: Prefixes that would neuter the scanner. Rejected when adding.
_FORBIDDEN_PREFIXES = frozenset(
    {"/", "\\", "c:", "c:\\", "c:/", "/home", "/users", "/root", "/etc", "/usr",
     "/var", "/tmp", "c:\\users", "c:\\windows", "c:\\program files"}
)

VALID_KINDS = ("sha256", "path", "prefix")


class WhitelistError(ValueError):
    """Raised when an entry would be unsafe or is malformed."""


@dataclass(frozen=True, slots=True)
class WhitelistHit:
    """Why a file was suppressed."""

    kind: str
    value: str
    note: str = ""

    def describe(self) -> str:
        label = {
            "sha256": "content hash",
            "path": "exact path",
            "prefix": "directory",
        }.get(self.kind, self.kind)
        suffix = f" — {self.note}" if self.note else ""
        return f"whitelisted by {label} ({self.value}){suffix}"


class Whitelist:
    """In-memory index of whitelist entries, loaded from the database."""

    def __init__(self, db: Any = None) -> None:
        self.db = db
        self._lock = threading.RLock()
        self._hashes: dict[str, str] = {}
        self._paths: dict[str, str] = {}
        self._prefixes: list[tuple[str, str]] = []
        if db is not None:
            self.reload()

    # -- loading -------------------------------------------------------

    def reload(self) -> None:
        """Re-read every entry from the database."""
        if self.db is None:
            return
        with self._lock:
            self._hashes.clear()
            self._paths.clear()
            self._prefixes.clear()

            for row in self.db.list_whitelist():
                kind = row["kind"]
                value = row["value"]
                note = row.get("note", "")
                if kind == "sha256":
                    self._hashes[value.lower()] = note
                elif kind == "path":
                    self._paths[_normalise(value)] = note
                elif kind == "prefix":
                    self._prefixes.append((_normalise(value), note))

            # Longest prefix first so the most specific note wins.
            self._prefixes.sort(key=lambda item: len(item[0]), reverse=True)

        log.debug(
            "whitelist loaded: %d hashes, %d paths, %d prefixes",
            len(self._hashes), len(self._paths), len(self._prefixes),
        )

    # -- queries -------------------------------------------------------

    def check(self, path: str | os.PathLike[str], sha256: str = "") -> WhitelistHit | None:
        """Return the matching entry, or None.

        Hash is checked first: it is the strongest form of match and a plain
        dict lookup.
        """
        with self._lock:
            if sha256:
                digest = sha256.lower()
                if digest in self._hashes:
                    return WhitelistHit("sha256", digest, self._hashes[digest])

            if not self._paths and not self._prefixes:
                return None

            normalised = _normalise(path)

            note = self._paths.get(normalised)
            if note is not None:
                return WhitelistHit("path", str(path), note)

            for prefix, prefix_note in self._prefixes:
                if normalised == prefix or normalised.startswith(prefix + os.sep):
                    return WhitelistHit("prefix", prefix, prefix_note)

        return None

    def is_whitelisted(self, path: str | os.PathLike[str], sha256: str = "") -> bool:
        return self.check(path, sha256) is not None

    def __len__(self) -> int:
        with self._lock:
            return len(self._hashes) + len(self._paths) + len(self._prefixes)

    @property
    def is_empty(self) -> bool:
        return len(self) == 0

    # -- mutation ------------------------------------------------------

    def add(self, value: str, kind: str | None = None, note: str = "") -> bool:
        """Add an entry, inferring *kind* when not given.

        Returns False if the entry already existed.

        Raises:
            WhitelistError: the value is malformed or the prefix is unsafe.
        """
        if self.db is None:
            raise WhitelistError("no database attached")

        kind = kind or infer_kind(value)
        if kind not in VALID_KINDS:
            raise WhitelistError(f"invalid kind {kind!r}; expected one of {VALID_KINDS}")

        value = _validate(kind, value)
        added = self.db.add_whitelist(kind, value, note)
        self.reload()
        return added

    def remove(self, value: str) -> bool:
        """Remove an entry by value. Returns False if it was not present."""
        if self.db is None:
            raise WhitelistError("no database attached")
        removed = self.db.remove_whitelist(value)
        if not removed:
            # A path may have been stored normalised.
            removed = self.db.remove_whitelist(_normalise(value))
        self.reload()
        return removed

    def entries(self) -> list[dict[str, Any]]:
        if self.db is None:
            return []
        return self.db.list_whitelist()


# ----------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------

def infer_kind(value: str) -> str:
    """Guess whether *value* is a hash, an exact path, or a directory prefix."""
    stripped = value.strip()
    if len(stripped) == 64 and all(c in "0123456789abcdefABCDEF" for c in stripped):
        return "sha256"
    if stripped.endswith(("/", "\\")) or Path(stripped).is_dir():
        return "prefix"
    return "path"


def _validate(kind: str, value: str) -> str:
    """Normalise and safety-check an entry value."""
    value = value.strip()
    if not value:
        raise WhitelistError("whitelist value cannot be empty")

    if kind == "sha256":
        digest = value.lower()
        if len(digest) != 64 or not all(c in "0123456789abcdef" for c in digest):
            raise WhitelistError(f"{value!r} is not a sha256 hex digest")
        return digest

    resolved = _normalise(value)

    if kind == "prefix":
        if resolved in _FORBIDDEN_PREFIXES or resolved.rstrip("\\/") in _FORBIDDEN_PREFIXES:
            raise WhitelistError(
                f"refusing to whitelist {value!r}: it covers most of the "
                f"filesystem, which would disable scanning entirely. Whitelist "
                f"the specific file or its sha256 instead."
            )
        # A one- or two-component path is nearly always too broad.
        depth = len([p for p in resolved.replace("\\", "/").split("/") if p])
        if depth < 2:
            raise WhitelistError(
                f"refusing to whitelist {value!r}: too broad. Use a more "
                f"specific directory."
            )

    return resolved


def _normalise(path: str | os.PathLike[str]) -> str:
    """Absolute, case-folded (on Windows), separator-normalised path."""
    text = os.path.normpath(os.path.abspath(os.path.expanduser(str(path))))
    return text.lower() if os.name == "nt" else text
