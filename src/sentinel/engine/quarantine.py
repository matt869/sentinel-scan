"""The quarantine vault.

Quarantining moves a file out of harm's way without destroying it, because
the scanner is sometimes wrong and a deleted file the user needed is a worse
outcome than a contained one.

Files in the vault are stored obfuscated with a keystream cipher. To be
explicit about what that does and does not buy:

* It **does** stop the file being executed, double-clicked, indexed, or
  picked up by another scanner and re-flagged in a loop. It stops a
  ransomware payload sitting decrypted in a folder the user might open.
* It is **not** confidentiality against someone who has the vault key, and
  the key sits next to the vault. It cannot be otherwise: restoring must
  work without prompting for a passphrase the user never set.

The vault key is generated on first use, stored owner-readable only, and
never leaves the machine.

Layout::

    <data_dir>/quarantine/
        vault.key            32 random bytes, mode 0600
        <token>.quar         header + obfuscated contents

The database (``quarantine`` table) holds the metadata: original path,
original hash, threat name, per-file nonce.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import shutil
import struct
import tempfile
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO

from sentinel.core.events import EventBus, EventType
from sentinel.core.logger import get_logger
from sentinel.engine.verdict import Severity, Verdict

log = get_logger(__name__)

#: File format: b"SNTQ" + version. Bumping the version requires a reader for
#: the old one — quarantined files outlive upgrades.
MAGIC = b"SNTQ"
FORMAT_VERSION = 1

#: Header: magic(4) version(2) nonce(16) original_size(8) sha256(32)
_HEADER = struct.Struct("<4sH16sQ32s")

KEY_SIZE = 32
NONCE_SIZE = 16
CHUNK_SIZE = 1024 * 1024


class QuarantineError(RuntimeError):
    """Raised when a quarantine operation cannot be completed."""


@dataclass(slots=True)
class QuarantineEntry:
    """A file held in the vault."""

    token: str
    original_path: str
    stored_name: str
    sha256: str
    size: int
    name: str
    severity: str
    created_at: float
    restored_at: float | None = None
    metadata: dict[str, Any] | None = None

    @property
    def original_name(self) -> str:
        return Path(self.original_path).name

    @property
    def age_days(self) -> float:
        return (time.time() - self.created_at) / 86400

    @property
    def is_restored(self) -> bool:
        return self.restored_at is not None


class Quarantine:
    """Manages the vault directory and its database index."""

    def __init__(self, config: Any, db: Any, bus: EventBus | None = None) -> None:
        self.config = config
        self.db = db
        self.bus = bus
        self.directory = Path(config.paths.quarantine_dir)
        self.directory.mkdir(parents=True, exist_ok=True)
        self._key: bytes | None = None

    # -- key management ------------------------------------------------

    @property
    def key_path(self) -> Path:
        return self.directory / "vault.key"

    @property
    def key(self) -> bytes:
        """The vault key, generated on first access."""
        if self._key is None:
            self._key = self._load_or_create_key()
        return self._key

    def _load_or_create_key(self) -> bytes:
        if self.key_path.is_file():
            data = self.key_path.read_bytes()
            if len(data) != KEY_SIZE:
                raise QuarantineError(
                    f"{self.key_path} is corrupt ({len(data)} bytes, expected "
                    f"{KEY_SIZE}). Quarantined files cannot be restored without "
                    f"it — restore the file from a backup if you have one."
                )
            return data

        key = secrets.token_bytes(KEY_SIZE)
        # Create with restrictive permissions from the outset rather than
        # chmod-ing afterwards, which leaves a window where it is readable.
        #
        # O_BINARY is not optional on Windows: os.open defaults to text mode
        # there, so every 0x0A byte in the key is written as 0x0D 0x0A. Around
        # one key in eight contains a newline byte, and the resulting 33-byte
        # file fails the length check above forever — taking every already
        # quarantined file with it, since nothing can be decrypted without the
        # key. On POSIX the flag does not exist and is a no-op.
        binary = getattr(os, "O_BINARY", 0)
        fd = os.open(
            self.key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | binary, 0o600
        )
        try:
            os.write(fd, key)
        finally:
            os.close(fd)
        log.info("created quarantine vault key at %s", self.key_path)
        return key

    # -- quarantining --------------------------------------------------

    def quarantine(self, verdict: Verdict, delete_original: bool = True) -> QuarantineEntry:
        """Move the file described by *verdict* into the vault.

        Args:
            verdict: The finding that justified quarantining.
            delete_original: Remove the source file afterwards. Set False to
                copy instead of move (used by ``--dry-run``).

        Raises:
            QuarantineError: the file could not be read or stored.
        """
        source = Path(verdict.path)
        if not source.is_file():
            raise QuarantineError(f"{source} is not a file")

        # Never quarantine our own vault, database or key.
        if self._is_own_file(source):
            raise QuarantineError(f"refusing to quarantine Sentinel's own file {source}")

        token = secrets.token_hex(16)
        nonce = secrets.token_bytes(NONCE_SIZE)
        stored_name = f"{token}.quar"
        destination = self.directory / stored_name

        try:
            size, digest = self._store(source, destination, nonce)
        except OSError as exc:
            destination.unlink(missing_ok=True)
            raise QuarantineError(f"cannot quarantine {source}: {exc}") from exc

        entry = QuarantineEntry(
            token=token,
            original_path=str(source.resolve()),
            stored_name=stored_name,
            sha256=digest,
            size=size,
            name=verdict.name or "Unknown",
            severity=verdict.severity.value,
            created_at=time.time(),
            metadata={
                "score": verdict.score,
                "detectors": verdict.detector_names,
                "detections": [d.to_dict() for d in verdict.detections[:10]],
            },
        )

        self.db.add_quarantine(
            {
                "token": entry.token,
                "original_path": entry.original_path,
                "stored_name": entry.stored_name,
                "sha256": entry.sha256,
                "size": entry.size,
                "name": entry.name,
                "severity": entry.severity,
                "key_nonce": nonce.hex(),
                "metadata": entry.metadata,
            }
        )

        if delete_original:
            try:
                source.unlink()
            except OSError as exc:
                # The copy is safely in the vault; a locked original is worth
                # reporting but not worth rolling back for.
                log.warning("quarantined %s but could not remove the original: %s",
                            source, exc)

        log.info("quarantined %s as %s (%s)", source, token, entry.name)
        self._emit(EventType.QUARANTINE_ADDED, token=token, path=str(source),
                   name=entry.name, severity=entry.severity)
        return entry

    def _store(self, source: Path, destination: Path, nonce: bytes) -> tuple[int, str]:
        """Write the obfuscated copy. Returns ``(size, sha256)``."""
        digest = hashlib.sha256()
        size = 0

        # Write to a temp file in the vault, then rename: a crash mid-write
        # must not leave a half-written .quar that looks restorable.
        fd, temp_name = tempfile.mkstemp(prefix=".quar-", dir=self.directory)
        temp_path = Path(temp_name)

        try:
            with os.fdopen(fd, "r+b") as out, open(source, "rb", buffering=0) as src:
                # Placeholder header; rewritten once the hash is known.
                out.write(_HEADER.pack(MAGIC, FORMAT_VERSION, nonce, 0, b"\x00" * 32))

                for offset, chunk in _chunks(src):
                    digest.update(chunk)
                    size += len(chunk)
                    out.write(_xor(chunk, self.key, nonce, offset))

                out.seek(0)
                out.write(_HEADER.pack(MAGIC, FORMAT_VERSION, nonce, size, digest.digest()))
                out.flush()
                os.fsync(out.fileno())

            os.replace(temp_path, destination)
            if os.name == "posix":
                os.chmod(destination, 0o600)
        except Exception:
            temp_path.unlink(missing_ok=True)
            raise

        return size, digest.hexdigest()

    # -- restoring -----------------------------------------------------

    def restore(
        self,
        token: str,
        destination: str | os.PathLike[str] | None = None,
        overwrite: bool = False,
    ) -> Path:
        """Return a quarantined file to disk.

        The decrypted contents are verified against the hash recorded at
        quarantine time before the file is put back, so a corrupted vault
        cannot silently restore garbage.

        Args:
            token: Identifier from :meth:`list_entries`.
            destination: Where to restore. Defaults to the original path.
            overwrite: Replace an existing file at the destination.
        """
        record = self.db.get_quarantine(token)
        if record is None:
            raise QuarantineError(f"no quarantined file with token {token!r}")

        stored = self.directory / record["stored_name"]
        if not stored.is_file():
            raise QuarantineError(
                f"vault file {stored} is missing; the entry is recorded but the "
                f"contents are gone"
            )

        target = Path(destination) if destination else Path(record["original_path"])
        if target.exists() and not overwrite:
            raise QuarantineError(
                f"{target} already exists; pass overwrite=True to replace it"
            )

        target.parent.mkdir(parents=True, exist_ok=True)

        fd, temp_name = tempfile.mkstemp(prefix=".restore-", dir=target.parent)
        temp_path = Path(temp_name)
        try:
            digest = self._extract(stored, os.fdopen(fd, "wb"))
            if digest != record["sha256"]:
                raise QuarantineError(
                    f"integrity check failed for {token}: the vault copy does not "
                    f"match the hash recorded when it was quarantined. It has not "
                    f"been restored."
                )
            os.replace(temp_path, target)
        except Exception:
            temp_path.unlink(missing_ok=True)
            raise

        self.db.mark_restored(token)
        log.warning("restored %s to %s — this file was flagged as %s",
                    token, target, record["name"])
        self._emit(EventType.QUARANTINE_RESTORED, token=token, path=str(target),
                   name=record["name"])
        return target

    def _extract(self, stored: Path, output: BinaryIO) -> str:
        """Decode a vault file into *output*. Returns the sha256 of the result."""
        digest = hashlib.sha256()
        with output, open(stored, "rb", buffering=0) as src:
            header = src.read(_HEADER.size)
            if len(header) < _HEADER.size:
                raise QuarantineError(f"{stored} is truncated")

            magic, version, nonce, size, expected = _HEADER.unpack(header)
            if magic != MAGIC:
                raise QuarantineError(f"{stored} is not a quarantine file")
            if version != FORMAT_VERSION:
                raise QuarantineError(
                    f"{stored} uses format version {version}; this build reads "
                    f"version {FORMAT_VERSION}"
                )

            written = 0
            for offset, chunk in _chunks(src):
                plain = _xor(chunk, self.key, nonce, offset)
                digest.update(plain)
                output.write(plain)
                written += len(plain)

            if written != size:
                raise QuarantineError(
                    f"{stored} declares {size} bytes but holds {written}"
                )
            if not hmac.compare_digest(digest.digest(), expected):
                raise QuarantineError(f"{stored} failed its internal integrity check")

        return digest.hexdigest()

    def extract_to(self, token: str, destination: str | os.PathLike[str]) -> Path:
        """Decode a vault file to an arbitrary path without marking it restored.

        Used by the sample-upload flow, which needs the original bytes but
        must not put a live payload back on the user's disk.
        """
        record = self.db.get_quarantine(token)
        if record is None:
            raise QuarantineError(f"no quarantined file with token {token!r}")
        stored = self.directory / record["stored_name"]
        target = Path(destination)
        target.parent.mkdir(parents=True, exist_ok=True)
        with open(target, "wb") as out:
            self._extract(stored, out)
        return target

    # -- removal -------------------------------------------------------

    def delete(self, token: str) -> None:
        """Permanently destroy a quarantined file. Not reversible."""
        record = self.db.get_quarantine(token)
        if record is None:
            raise QuarantineError(f"no quarantined file with token {token!r}")

        stored = self.directory / record["stored_name"]
        try:
            stored.unlink(missing_ok=True)
        except OSError as exc:
            raise QuarantineError(f"cannot delete {stored}: {exc}") from exc

        self.db.remove_quarantine(token)
        log.info("deleted quarantined file %s (%s)", token, record["name"])
        self._emit(EventType.QUARANTINE_DELETED, token=token, name=record["name"])

    def purge(self, older_than_days: int = 30, dry_run: bool = False) -> list[str]:
        """Delete vault entries older than *older_than_days*.

        Returns the tokens purged (or that would be, when *dry_run*).
        """
        cutoff = time.time() - older_than_days * 86400
        purged: list[str] = []
        for record in self.db.list_quarantine(include_restored=False):
            if record["created_at"] >= cutoff:
                continue
            purged.append(record["token"])
            if not dry_run:
                self.delete(record["token"])
        return purged

    # -- inspection ----------------------------------------------------

    def list_entries(self, include_restored: bool = False) -> list[QuarantineEntry]:
        return [
            QuarantineEntry(
                token=r["token"],
                original_path=r["original_path"],
                stored_name=r["stored_name"],
                sha256=r["sha256"],
                size=r["size"],
                name=r["name"],
                severity=r["severity"],
                created_at=r["created_at"],
                restored_at=r["restored_at"],
                metadata=r.get("metadata", {}),
            )
            for r in self.db.list_quarantine(include_restored)
        ]

    def get(self, token: str) -> QuarantineEntry | None:
        for entry in self.list_entries(include_restored=True):
            if entry.token == token:
                return entry
        return None

    def verify(self, token: str) -> bool:
        """Check a vault file's integrity without restoring it."""
        record = self.db.get_quarantine(token)
        if record is None:
            return False
        stored = self.directory / record["stored_name"]
        if not stored.is_file():
            return False
        try:
            with open(os.devnull, "wb") as sink:
                digest = self._extract(stored, sink)
        except QuarantineError:
            return False
        return digest == record["sha256"]

    def total_size(self) -> int:
        """Bytes the vault occupies on disk."""
        total = 0
        for path in self.directory.glob("*.quar"):
            try:
                total += path.stat().st_size
            except OSError:
                continue
        return total

    def orphans(self) -> list[Path]:
        """Vault files with no database row — safe to delete."""
        known = {r["stored_name"] for r in self.db.list_quarantine(include_restored=True)}
        return [p for p in self.directory.glob("*.quar") if p.name not in known]

    # -- helpers -------------------------------------------------------

    def _is_own_file(self, path: Path) -> bool:
        """True if *path* is part of Sentinel's own data directory."""
        try:
            resolved = path.resolve()
            data_dir = Path(self.config.paths.data_dir).resolve()
            resolved.relative_to(data_dir)
            return True
        except (ValueError, OSError):
            return False

    def _emit(self, event: EventType, **payload: Any) -> None:
        if self.bus is not None:
            self.bus.emit(event, **payload)


# ----------------------------------------------------------------------
# keystream
# ----------------------------------------------------------------------

def _chunks(stream: BinaryIO) -> Iterator[tuple[int, bytes]]:
    """Yield ``(byte_offset, chunk)`` pairs from a binary stream."""
    offset = 0
    while True:
        chunk = stream.read(CHUNK_SIZE)
        if not chunk:
            return
        yield offset, chunk
        offset += len(chunk)


def _xor(data: bytes, key: bytes, nonce: bytes, offset: int) -> bytes:
    """XOR *data* with a keystream derived from (key, nonce, offset).

    Counter mode over SHA-256: block *n* of the keystream is
    ``sha256(key || nonce || n)``. Keying on the absolute byte offset means
    chunks can be processed independently and out of order, and the same
    (key, nonce) pair never repeats a keystream block within a file.
    """
    block_size = hashlib.sha256().digest_size
    start_block, lead = divmod(offset, block_size)
    needed = lead + len(data)

    keystream = bytearray()
    block = start_block
    while len(keystream) < needed:
        keystream += hashlib.sha256(
            key + nonce + block.to_bytes(8, "little")
        ).digest()
        block += 1

    window = keystream[lead : lead + len(data)]
    # strict=True on purpose: a length mismatch here would silently truncate
    # the output and corrupt the stored file. Better to raise.
    return bytes(a ^ b for a, b in zip(data, window, strict=True))


def severity_allows_auto_quarantine(severity: Severity, threshold: Severity) -> bool:
    """Whether a finding is severe enough for automatic quarantine.

    Auto-quarantine defaults to HIGH and above. Acting automatically on
    MEDIUM findings — which are heuristic combinations, not certainties —
    would move users' legitimate files without asking.
    """
    return severity >= threshold


def free_space(path: str | os.PathLike[str]) -> int:
    """Bytes available on the filesystem holding *path*."""
    try:
        return shutil.disk_usage(path).free
    except OSError:
        return 0
