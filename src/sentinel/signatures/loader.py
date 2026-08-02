"""Locating and reading signature data.

Signatures live in two places:

``src/sentinel/signatures/local/``
    Shipped with the package. Small, and enough for the scanner to be useful
    immediately after ``pip install``.

``<data_dir>/signatures/``
    Written by :mod:`sentinel.signatures.updater`. Overrides the bundled set
    file by file, so an update never has to touch the installation directory
    (which is often read-only, and always is inside a PyInstaller bundle).

A user-specified rules directory is layered on top of both.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sentinel.core.logger import get_logger

log = get_logger(__name__)

#: Directory inside the package holding the bundled signatures.
BUNDLED_DIR = Path(__file__).resolve().parent / "local"

#: Manifest describing the bundled and downloadable signature sets.
MANIFEST_PATH = Path(__file__).resolve().parent / "manifest.json"

YARA_EXTENSIONS = (".yar", ".yara")


@dataclass(frozen=True, slots=True)
class HashEntry:
    """One row from the known-sample hash database."""

    digest: str
    algorithm: str
    name: str
    severity: str
    source: str = ""
    first_seen: str = ""


class HashDatabase:
    """Read-only access to the known-malware hash database.

    The file is a plain SQLite database with a ``signatures`` table; see
    ``scripts/build_hash_db.py`` for the builder. Opened read-only so a
    corrupt or hostile database file cannot be written to, and one connection
    per thread because SQLite requires it.
    """

    SCHEMA = """
        CREATE TABLE IF NOT EXISTS signatures (
            digest     TEXT PRIMARY KEY,
            algorithm  TEXT NOT NULL,
            name       TEXT NOT NULL,
            severity   TEXT NOT NULL DEFAULT 'high',
            source     TEXT NOT NULL DEFAULT '',
            first_seen TEXT NOT NULL DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_signatures_algorithm ON signatures(algorithm);
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        if not self.path.is_file():
            raise FileNotFoundError(f"hash database not found: {self.path}")
        self._local = threading.local()
        self._count: int | None = None
        # Fail fast on a file that is not a usable database.
        self._validate()

    def _validate(self) -> None:
        row = self.connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='signatures'"
        ).fetchone()
        if row is None:
            raise ValueError(f"{self.path} has no 'signatures' table")

    @property
    def connection(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            # immutable=1 tells SQLite the file will not change, which skips
            # locking entirely and makes concurrent reads faster.
            uri = f"file:{self.path.as_posix()}?mode=ro&immutable=1"
            conn = sqlite3.connect(uri, uri=True, check_same_thread=True)
            conn.row_factory = sqlite3.Row
            self._local.conn = conn
        return conn

    def lookup(self, md5: str = "", sha1: str = "", sha256: str = "") -> HashEntry | None:
        """Find an entry matching any of the supplied digests.

        Checked md5 first: most public feeds are keyed on it, so it hits most
        often and costs one index probe.
        """
        for algorithm, digest in (("md5", md5), ("sha1", sha1), ("sha256", sha256)):
            if not digest:
                continue
            row = self.connection.execute(
                "SELECT * FROM signatures WHERE digest=? AND algorithm=?",
                (digest.lower(), algorithm),
            ).fetchone()
            if row is not None:
                return HashEntry(
                    digest=row["digest"],
                    algorithm=row["algorithm"],
                    name=row["name"],
                    severity=row["severity"],
                    source=row["source"],
                    first_seen=row["first_seen"],
                )
        return None

    def contains(self, digest: str) -> bool:
        row = self.connection.execute(
            "SELECT 1 FROM signatures WHERE digest=?", (digest.lower(),)
        ).fetchone()
        return row is not None

    def __len__(self) -> int:
        if self._count is None:
            self._count = self.connection.execute(
                "SELECT COUNT(*) FROM signatures"
            ).fetchone()[0]
        return self._count

    def iter_entries(self, limit: int | None = None) -> Iterator[HashEntry]:
        """Stream entries, for ``scripts/benchmark.py`` and diagnostics."""
        sql = "SELECT * FROM signatures"
        if limit:
            sql += f" LIMIT {int(limit)}"
        for row in self.connection.execute(sql):
            yield HashEntry(
                digest=row["digest"],
                algorithm=row["algorithm"],
                name=row["name"],
                severity=row["severity"],
                source=row["source"],
                first_seen=row["first_seen"],
            )

    def close(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None


class SignatureStore:
    """Resolves where each kind of signature data lives."""

    def __init__(self, config: Any = None) -> None:
        self.config = config
        paths = getattr(config, "paths", None)
        self.user_dir: Path | None = (
            Path(paths.signatures_dir) if paths is not None else None
        )
        self.bundled_dir = BUNDLED_DIR

    # -- individual data sets ------------------------------------------

    @property
    def hash_db_path(self) -> Path | None:
        """Newest available hash database, user copy winning over bundled."""
        return self._first_existing("hashes.db")

    def yara_rule_files(self) -> list[Path]:
        """Every ``.yar``/``.yara`` file to compile, deduplicated by name.

        Later sources win, so a user rule named ``example.yar`` replaces the
        bundled one rather than colliding with it.
        """
        by_name: dict[str, Path] = {}

        for directory in self._rule_directories():
            if not directory.is_dir():
                continue
            for path in sorted(directory.iterdir()):
                if path.suffix.lower() in YARA_EXTENSIONS and path.is_file():
                    by_name[path.name] = path

        return list(by_name.values())

    def _rule_directories(self) -> list[Path]:
        """Rule directories in increasing order of precedence."""
        dirs = [self.bundled_dir / "rules"]
        if self.user_dir is not None:
            dirs.append(self.user_dir / "rules")

        detectors = getattr(self.config, "detectors", None)
        extra = getattr(detectors, "yara_rules_dir", None) if detectors else None
        if extra:
            dirs.append(Path(extra).expanduser())
        return dirs

    def clamav_db_paths(self) -> list[Path]:
        """ClamAV ``.cvd``/``.cud`` bundles, for pointing clamd at our copy."""
        found: list[Path] = []
        for directory in self._data_directories():
            if not directory.is_dir():
                continue
            found.extend(
                p for p in sorted(directory.iterdir())
                if p.suffix.lower() in (".cvd", ".cud") and p.stat().st_size > 0
            )
        return found

    def _data_directories(self) -> list[Path]:
        dirs = [self.bundled_dir]
        if self.user_dir is not None:
            dirs.append(self.user_dir)
        return dirs

    def _first_existing(self, filename: str) -> Path | None:
        """Return the highest-precedence copy of *filename* that has content."""
        candidates = []
        if self.user_dir is not None:
            candidates.append(self.user_dir / filename)
        candidates.append(self.bundled_dir / filename)

        for path in candidates:
            try:
                if path.is_file() and path.stat().st_size > 0:
                    return path
            except OSError:
                continue
        return None

    # -- manifest ------------------------------------------------------

    def manifest(self) -> dict[str, Any]:
        """Merged manifest: bundled defaults overlaid with the downloaded one."""
        data = _read_json(MANIFEST_PATH)
        if self.user_dir is not None:
            local = _read_json(self.user_dir / "manifest.json")
            if local:
                data = {**data, **local}
        return data

    @property
    def version(self) -> str:
        """Signature set version, used to invalidate the scan result cache."""
        manifest = self.manifest()
        return str(manifest.get("version", "0"))

    def summary(self) -> dict[str, Any]:
        """Human-readable inventory for ``sentinel update --status``."""
        hash_db = self.hash_db_path
        hash_count = 0
        if hash_db is not None:
            try:
                db = HashDatabase(hash_db)
                hash_count = len(db)
                db.close()
            except Exception as exc:
                log.debug("cannot count hash signatures: %s", exc)

        manifest = self.manifest()
        return {
            "version": manifest.get("version", "0"),
            "updated": manifest.get("updated", "never"),
            "hash_db": str(hash_db) if hash_db else None,
            "hash_count": hash_count,
            "yara_files": len(self.yara_rule_files()),
            "clamav_bundles": len(self.clamav_db_paths()),
            "user_dir": str(self.user_dir) if self.user_dir else None,
        }


def _read_json(path: Path) -> dict[str, Any]:
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError) as exc:
        log.debug("cannot read manifest %s: %s", path, exc)
        return {}
