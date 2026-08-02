"""Local SQLite storage: scan history, findings, quarantine index, whitelist.

Threading model
---------------
SQLite connections cannot be shared between threads, so :class:`Database`
keeps one connection per thread in a :class:`threading.local`. WAL mode lets
the scan workers read while the main thread writes. All writes go through
short transactions — a scan of a million files must not hold one open
transaction for its entire run.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sentinel.core.logger import get_logger
from sentinel.version import DB_SCHEMA_VERSION

log = get_logger(__name__)

# Each entry is one migration step; index N upgrades the schema from
# user_version N to N+1. Never edit a released migration — append a new one.
_MIGRATIONS: tuple[tuple[str, ...], ...] = (
    # 0 -> 1: initial schema
    (
        """
        CREATE TABLE IF NOT EXISTS scans (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            started_at     REAL    NOT NULL,
            finished_at    REAL,
            status         TEXT    NOT NULL DEFAULT 'running',
            roots          TEXT    NOT NULL,
            files_scanned  INTEGER NOT NULL DEFAULT 0,
            files_skipped  INTEGER NOT NULL DEFAULT 0,
            bytes_scanned  INTEGER NOT NULL DEFAULT 0,
            threats        INTEGER NOT NULL DEFAULT 0,
            suspicious     INTEGER NOT NULL DEFAULT 0,
            errors         INTEGER NOT NULL DEFAULT 0,
            engine_version TEXT    NOT NULL DEFAULT ''
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS findings (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id     INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
            path        TEXT    NOT NULL,
            sha256      TEXT    NOT NULL DEFAULT '',
            size        INTEGER NOT NULL DEFAULT 0,
            severity    TEXT    NOT NULL,
            score       INTEGER NOT NULL DEFAULT 0,
            name        TEXT    NOT NULL DEFAULT '',
            detections  TEXT    NOT NULL DEFAULT '[]',
            action      TEXT    NOT NULL DEFAULT 'none',
            created_at  REAL    NOT NULL
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id)",
        "CREATE INDEX IF NOT EXISTS idx_findings_sha ON findings(sha256)",
        """
        CREATE TABLE IF NOT EXISTS quarantine (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            token         TEXT    NOT NULL UNIQUE,
            original_path TEXT    NOT NULL,
            stored_name   TEXT    NOT NULL,
            sha256        TEXT    NOT NULL DEFAULT '',
            size          INTEGER NOT NULL DEFAULT 0,
            name          TEXT    NOT NULL DEFAULT '',
            severity      TEXT    NOT NULL DEFAULT 'medium',
            key_nonce     TEXT    NOT NULL DEFAULT '',
            metadata      TEXT    NOT NULL DEFAULT '{}',
            created_at    REAL    NOT NULL,
            restored_at   REAL
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_quarantine_sha ON quarantine(sha256)",
        """
        CREATE TABLE IF NOT EXISTS whitelist (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            kind       TEXT NOT NULL,
            value      TEXT NOT NULL,
            note       TEXT NOT NULL DEFAULT '',
            created_at REAL NOT NULL,
            UNIQUE(kind, value)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS kv (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
        """,
    ),
    # 1 -> 2: remember which report a finding was submitted under, so the
    # feedback UI can show "already reported" instead of allowing duplicates.
    (
        "ALTER TABLE findings ADD COLUMN report_id TEXT NOT NULL DEFAULT ''",
        "CREATE INDEX IF NOT EXISTS idx_findings_report ON findings(report_id)",
    ),
    # 2 -> 3: cache of per-file results, keyed on a cheap fingerprint, so a
    # repeat scan of an unchanged tree skips the expensive detectors.
    (
        """
        CREATE TABLE IF NOT EXISTS scan_cache (
            fingerprint TEXT PRIMARY KEY,
            sha256      TEXT NOT NULL,
            score       INTEGER NOT NULL,
            severity    TEXT NOT NULL,
            name        TEXT NOT NULL DEFAULT '',
            sig_version TEXT NOT NULL DEFAULT '',
            created_at  REAL NOT NULL
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_cache_created ON scan_cache(created_at)",
    ),
)

assert len(_MIGRATIONS) == DB_SCHEMA_VERSION, (
    "DB_SCHEMA_VERSION must equal the number of migrations"
)


@dataclass(slots=True)
class ScanRecord:
    """A row from the ``scans`` table."""

    id: int
    started_at: float
    finished_at: float | None
    status: str
    roots: list[str]
    files_scanned: int
    files_skipped: int
    bytes_scanned: int
    threats: int
    suspicious: int
    errors: int
    engine_version: str

    @property
    def duration(self) -> float:
        return (self.finished_at or time.time()) - self.started_at

    @property
    def started_display(self) -> str:
        return datetime.fromtimestamp(self.started_at, tz=timezone.utc).astimezone().strftime(
            "%Y-%m-%d %H:%M:%S"
        )


class Database:
    """Thread-safe wrapper over the local SQLite file."""

    def __init__(self, path: str | Path, timeout: float = 30.0) -> None:
        self.path = Path(path)
        self.timeout = timeout
        self._local = threading.local()
        self._write_lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._migrate()

    # -- connection handling -------------------------------------------

    @property
    def connection(self) -> sqlite3.Connection:
        """The calling thread's connection, opened on first use."""
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(
                self.path,
                timeout=self.timeout,
                isolation_level=None,  # explicit transactions only
                check_same_thread=True,
            )
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA foreign_keys=ON")
            # 8 MiB page cache; the findings queries are the only heavy ones.
            conn.execute("PRAGMA cache_size=-8000")
            self._local.conn = conn
        return conn

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Run a block inside a single immediate transaction."""
        conn = self.connection
        with self._write_lock:
            conn.execute("BEGIN IMMEDIATE")
            try:
                yield conn
            except Exception:
                conn.execute("ROLLBACK")
                raise
            else:
                conn.execute("COMMIT")

    def close(self) -> None:
        """Close this thread's connection."""
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None

    def __enter__(self) -> Database:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    # -- schema --------------------------------------------------------

    def _migrate(self) -> None:
        conn = self.connection
        current = conn.execute("PRAGMA user_version").fetchone()[0]
        if current > DB_SCHEMA_VERSION:
            raise RuntimeError(
                f"{self.path} was written by a newer Sentinel Scan "
                f"(schema {current} > {DB_SCHEMA_VERSION}). Upgrade, or point "
                f"SENTINEL_DATA_DIR at a different directory."
            )
        if current == DB_SCHEMA_VERSION:
            return

        log.info("migrating database schema %d -> %d", current, DB_SCHEMA_VERSION)
        with self._write_lock:
            conn.execute("BEGIN IMMEDIATE")
            try:
                for version in range(current, DB_SCHEMA_VERSION):
                    for statement in _MIGRATIONS[version]:
                        conn.execute(statement)
                conn.execute(f"PRAGMA user_version={DB_SCHEMA_VERSION}")
            except Exception:
                conn.execute("ROLLBACK")
                raise
            conn.execute("COMMIT")

    # -- scans ---------------------------------------------------------

    def start_scan(self, roots: list[str], engine_version: str) -> int:
        """Insert a running scan row and return its id."""
        with self.transaction() as conn:
            cur = conn.execute(
                "INSERT INTO scans (started_at, status, roots, engine_version) "
                "VALUES (?, 'running', ?, ?)",
                (time.time(), json.dumps(roots), engine_version),
            )
            return int(cur.lastrowid)

    def finish_scan(self, scan_id: int, status: str, **counters: int) -> None:
        """Mark a scan finished and store its totals."""
        allowed = {
            "files_scanned", "files_skipped", "bytes_scanned",
            "threats", "suspicious", "errors",
        }
        unknown = set(counters) - allowed
        if unknown:
            raise ValueError(f"unknown scan counters: {sorted(unknown)}")

        assignments = ", ".join(f"{k}=?" for k in counters)
        sql = "UPDATE scans SET finished_at=?, status=?"
        params: list[Any] = [time.time(), status]
        if assignments:
            sql += ", " + assignments
            params.extend(counters.values())
        sql += " WHERE id=?"
        params.append(scan_id)

        with self.transaction() as conn:
            conn.execute(sql, params)

    def get_scan(self, scan_id: int) -> ScanRecord | None:
        row = self.connection.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        return _row_to_scan(row) if row else None

    def recent_scans(self, limit: int = 20) -> list[ScanRecord]:
        rows = self.connection.execute(
            "SELECT * FROM scans ORDER BY started_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [_row_to_scan(r) for r in rows]

    # -- findings ------------------------------------------------------

    def add_findings(self, scan_id: int, findings: list[dict[str, Any]]) -> None:
        """Bulk-insert findings for a scan.

        Called once at the end of a scan rather than per file, so a long scan
        does not thrash the write lock.
        """
        if not findings:
            return
        now = time.time()
        rows = [
            (
                scan_id,
                f["path"],
                f.get("sha256", ""),
                int(f.get("size", 0)),
                f["severity"],
                int(f.get("score", 0)),
                f.get("name", ""),
                json.dumps(f.get("detections", [])),
                f.get("action", "none"),
                now,
            )
            for f in findings
        ]
        with self.transaction() as conn:
            conn.executemany(
                "INSERT INTO findings "
                "(scan_id, path, sha256, size, severity, score, name, detections, "
                " action, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                rows,
            )

    def findings_for_scan(self, scan_id: int) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT * FROM findings WHERE scan_id=? ORDER BY score DESC", (scan_id,)
        ).fetchall()
        return [_row_to_finding(r) for r in rows]

    def mark_finding_action(self, finding_id: int, action: str) -> None:
        with self.transaction() as conn:
            conn.execute("UPDATE findings SET action=? WHERE id=?", (action, finding_id))

    def mark_finding_reported(self, finding_id: int, report_id: str) -> None:
        with self.transaction() as conn:
            conn.execute(
                "UPDATE findings SET report_id=? WHERE id=?", (report_id, finding_id)
            )

    # -- quarantine index ----------------------------------------------

    def add_quarantine(self, entry: dict[str, Any]) -> int:
        with self.transaction() as conn:
            cur = conn.execute(
                "INSERT INTO quarantine "
                "(token, original_path, stored_name, sha256, size, name, severity, "
                " key_nonce, metadata, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    entry["token"],
                    entry["original_path"],
                    entry["stored_name"],
                    entry.get("sha256", ""),
                    int(entry.get("size", 0)),
                    entry.get("name", ""),
                    entry.get("severity", "medium"),
                    entry.get("key_nonce", ""),
                    json.dumps(entry.get("metadata", {})),
                    time.time(),
                ),
            )
            return int(cur.lastrowid)

    def list_quarantine(self, include_restored: bool = False) -> list[dict[str, Any]]:
        sql = "SELECT * FROM quarantine"
        if not include_restored:
            sql += " WHERE restored_at IS NULL"
        sql += " ORDER BY created_at DESC"
        return [dict(r) | {"metadata": json.loads(r["metadata"])}
                for r in self.connection.execute(sql).fetchall()]

    def get_quarantine(self, token: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM quarantine WHERE token=?", (token,)
        ).fetchone()
        if row is None:
            return None
        return dict(row) | {"metadata": json.loads(row["metadata"])}

    def mark_restored(self, token: str) -> None:
        with self.transaction() as conn:
            conn.execute(
                "UPDATE quarantine SET restored_at=? WHERE token=?", (time.time(), token)
            )

    def remove_quarantine(self, token: str) -> None:
        with self.transaction() as conn:
            conn.execute("DELETE FROM quarantine WHERE token=?", (token,))

    # -- whitelist -----------------------------------------------------

    def add_whitelist(self, kind: str, value: str, note: str = "") -> bool:
        """Add an entry. Returns False if it was already present."""
        if kind not in {"sha256", "path", "prefix"}:
            raise ValueError(f"invalid whitelist kind {kind!r}")
        try:
            with self.transaction() as conn:
                conn.execute(
                    "INSERT INTO whitelist (kind, value, note, created_at) VALUES (?,?,?,?)",
                    (kind, value, note, time.time()),
                )
            return True
        except sqlite3.IntegrityError:
            return False

    def remove_whitelist(self, value: str) -> bool:
        with self.transaction() as conn:
            cur = conn.execute("DELETE FROM whitelist WHERE value=?", (value,))
            return cur.rowcount > 0

    def list_whitelist(self) -> list[dict[str, Any]]:
        return [dict(r) for r in self.connection.execute(
            "SELECT * FROM whitelist ORDER BY kind, value"
        ).fetchall()]

    def whitelist_values(self, kind: str) -> set[str]:
        """All values of one kind, for building an in-memory index."""
        return {
            r[0] for r in self.connection.execute(
                "SELECT value FROM whitelist WHERE kind=?", (kind,)
            ).fetchall()
        }

    # -- result cache --------------------------------------------------

    def cache_get(self, fingerprint: str, sig_version: str) -> dict[str, Any] | None:
        """Look up a cached verdict, ignoring entries from older signatures."""
        row = self.connection.execute(
            "SELECT * FROM scan_cache WHERE fingerprint=? AND sig_version=?",
            (fingerprint, sig_version),
        ).fetchone()
        return dict(row) if row else None

    def cache_put(self, fingerprint: str, sha256: str, score: int,
                  severity: str, name: str, sig_version: str) -> None:
        with self.transaction() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO scan_cache "
                "(fingerprint, sha256, score, severity, name, sig_version, created_at) "
                "VALUES (?,?,?,?,?,?,?)",
                (fingerprint, sha256, score, severity, name, sig_version, time.time()),
            )

    def cache_prune(self, max_age_days: int = 30) -> int:
        """Delete cache entries older than *max_age_days*. Returns rows removed."""
        cutoff = time.time() - max_age_days * 86400
        with self.transaction() as conn:
            cur = conn.execute("DELETE FROM scan_cache WHERE created_at < ?", (cutoff,))
            return cur.rowcount

    # -- key/value -----------------------------------------------------

    def get_setting(self, key: str, default: str | None = None) -> str | None:
        row = self.connection.execute("SELECT value FROM kv WHERE key=?", (key,)).fetchone()
        return row[0] if row else default

    def set_setting(self, key: str, value: str) -> None:
        with self.transaction() as conn:
            conn.execute("INSERT OR REPLACE INTO kv (key, value) VALUES (?,?)", (key, value))

    # -- maintenance ---------------------------------------------------

    def stats(self) -> dict[str, int]:
        """Row counts, for ``sentinel status``."""
        conn = self.connection
        return {
            table: conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in ("scans", "findings", "quarantine", "whitelist", "scan_cache")
        }

    def prune_history(self, keep_scans: int = 100) -> int:
        """Delete all but the newest *keep_scans* scans. Returns rows removed."""
        with self.transaction() as conn:
            cur = conn.execute(
                "DELETE FROM scans WHERE id NOT IN "
                "(SELECT id FROM scans ORDER BY started_at DESC LIMIT ?)",
                (keep_scans,),
            )
            return cur.rowcount

    def vacuum(self) -> None:
        """Compact the file. Cannot run inside a transaction."""
        self.connection.execute("VACUUM")


def _row_to_scan(row: sqlite3.Row) -> ScanRecord:
    return ScanRecord(
        id=row["id"],
        started_at=row["started_at"],
        finished_at=row["finished_at"],
        status=row["status"],
        roots=json.loads(row["roots"]),
        files_scanned=row["files_scanned"],
        files_skipped=row["files_skipped"],
        bytes_scanned=row["bytes_scanned"],
        threats=row["threats"],
        suspicious=row["suspicious"],
        errors=row["errors"],
        engine_version=row["engine_version"],
    )


def _row_to_finding(row: sqlite3.Row) -> dict[str, Any]:
    data = dict(row)
    data["detections"] = json.loads(data.get("detections") or "[]")
    return data
