"""Tests for the quarantine vault and the whitelist."""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from sentinel.core.events import EventType
from sentinel.engine.quarantine import MAGIC, Quarantine, QuarantineError, _xor
from sentinel.engine.verdict import Detection, Severity, build_verdict
from sentinel.engine.whitelist import Whitelist, WhitelistError, infer_kind
from sentinel.utils.hashing import hash_file


@pytest.fixture
def vault(config, db, bus) -> Quarantine:
    return Quarantine(config, db, bus)


@pytest.fixture
def flagged_file(tmp_path: Path):
    """A file plus a verdict condemning it."""
    path = tmp_path / "malware.exe"
    path.write_bytes(b"MZ" + os.urandom(4096))
    verdict = build_verdict(
        str(path),
        [Detection("test", "Trojan.Test", 95, "test detection")],
        sha256=hash_file(path),
        size=path.stat().st_size,
    )
    return path, verdict


# ----------------------------------------------------------------------
# keystream
# ----------------------------------------------------------------------

class TestKeystream:
    def test_xor_round_trips(self) -> None:
        key, nonce = os.urandom(32), os.urandom(16)
        plaintext = b"the quick brown fox" * 100
        obfuscated = _xor(plaintext, key, nonce, 0)
        assert obfuscated != plaintext
        assert _xor(obfuscated, key, nonce, 0) == plaintext

    def test_offset_is_respected(self) -> None:
        """Chunks must decode correctly regardless of where they start."""
        key, nonce = os.urandom(32), os.urandom(16)
        data = os.urandom(5000)

        whole = _xor(data, key, nonce, 0)
        # Encode in two pieces at their true offsets; must match the whole.
        first = _xor(data[:2000], key, nonce, 0)
        second = _xor(data[2000:], key, nonce, 2000)
        assert first + second == whole

    def test_different_nonces_give_different_output(self) -> None:
        key = os.urandom(32)
        data = b"same input"
        assert _xor(data, key, b"\x00" * 16, 0) != _xor(data, key, b"\x11" * 16, 0)


# ----------------------------------------------------------------------
# vault
# ----------------------------------------------------------------------

class TestQuarantine:
    def test_key_is_created_once_and_reused(self, vault: Quarantine) -> None:
        first = vault.key
        assert len(first) == 32
        assert vault.key_path.is_file()

        vault._key = None
        assert vault.key == first

    @pytest.mark.skipif(os.name == "nt", reason="POSIX permissions only")
    def test_key_is_owner_readable_only(self, vault: Quarantine) -> None:
        _ = vault.key
        assert (vault.key_path.stat().st_mode & 0o077) == 0

    def test_quarantine_moves_the_file(self, vault: Quarantine, flagged_file) -> None:
        path, verdict = flagged_file
        entry = vault.quarantine(verdict)

        assert not path.exists(), "the original should be removed"
        assert (vault.directory / entry.stored_name).is_file()
        assert entry.name == "Trojan.Test"
        # A single 95%-confidence detection aggregates to a CRITICAL verdict.
        assert entry.severity == Severity.CRITICAL.value

    def test_stored_copy_is_not_plaintext(self, vault: Quarantine, tmp_path: Path) -> None:
        marker = b"UNIQUE-PLAINTEXT-MARKER-9f3a2b"
        path = tmp_path / "sample.bin"
        path.write_bytes(b"MZ" + marker + os.urandom(1024))
        verdict = build_verdict(
            str(path), [Detection("t", "X", 90)], sha256=hash_file(path)
        )

        entry = vault.quarantine(verdict)
        raw = (vault.directory / entry.stored_name).read_bytes()

        assert raw.startswith(MAGIC)
        assert marker not in raw, "quarantined content must not sit in plaintext"

    def test_restore_returns_identical_bytes(
        self, vault: Quarantine, flagged_file
    ) -> None:
        path, verdict = flagged_file
        original = path.read_bytes()
        original_hash = verdict.sha256

        entry = vault.quarantine(verdict)
        restored = vault.restore(entry.token)

        assert restored == path
        assert restored.read_bytes() == original
        assert hash_file(restored) == original_hash

    def test_restore_to_another_location(
        self, vault: Quarantine, flagged_file, tmp_path: Path
    ) -> None:
        _, verdict = flagged_file
        entry = vault.quarantine(verdict)

        destination = tmp_path / "elsewhere" / "recovered.bin"
        restored = vault.restore(entry.token, destination)
        assert restored == destination and destination.is_file()

    def test_restore_refuses_to_overwrite(self, vault: Quarantine, flagged_file) -> None:
        path, verdict = flagged_file
        entry = vault.quarantine(verdict)
        path.write_bytes(b"something else is here now")

        with pytest.raises(QuarantineError, match="already exists"):
            vault.restore(entry.token)

        assert vault.restore(entry.token, overwrite=True) == path

    def test_verify_detects_tampering(self, vault: Quarantine, flagged_file) -> None:
        _, verdict = flagged_file
        entry = vault.quarantine(verdict)
        assert vault.verify(entry.token)

        # Flip a byte in the payload, past the header.
        stored = vault.directory / entry.stored_name
        data = bytearray(stored.read_bytes())
        data[-1] ^= 0xFF
        stored.write_bytes(bytes(data))

        assert not vault.verify(entry.token)

    def test_restore_refuses_a_corrupt_vault_file(
        self, vault: Quarantine, flagged_file
    ) -> None:
        path, verdict = flagged_file
        entry = vault.quarantine(verdict)

        stored = vault.directory / entry.stored_name
        data = bytearray(stored.read_bytes())
        data[-5] ^= 0xFF
        stored.write_bytes(bytes(data))

        with pytest.raises(QuarantineError):
            vault.restore(entry.token)
        assert not path.exists(), "a failed restore must not leave a partial file"

    def test_unknown_token_raises(self, vault: Quarantine) -> None:
        with pytest.raises(QuarantineError, match="no quarantined file"):
            vault.restore("0" * 32)

    def test_delete_is_permanent(self, vault: Quarantine, flagged_file) -> None:
        _, verdict = flagged_file
        entry = vault.quarantine(verdict)
        stored = vault.directory / entry.stored_name

        vault.delete(entry.token)
        assert not stored.exists()
        assert vault.get(entry.token) is None

    def test_listing_and_size(self, vault: Quarantine, flagged_file) -> None:
        _, verdict = flagged_file
        vault.quarantine(verdict)

        entries = vault.list_entries()
        assert len(entries) == 1
        assert vault.total_size() > 0

    def test_restored_entries_are_hidden_by_default(
        self, vault: Quarantine, flagged_file
    ) -> None:
        _, verdict = flagged_file
        entry = vault.quarantine(verdict)
        vault.restore(entry.token)

        assert vault.list_entries() == []
        assert len(vault.list_entries(include_restored=True)) == 1

    def test_events_are_emitted(self, vault: Quarantine, recorder, flagged_file) -> None:
        _, verdict = flagged_file
        entry = vault.quarantine(verdict)
        vault.restore(entry.token)

        assert recorder.count(EventType.QUARANTINE_ADDED) == 1
        assert recorder.count(EventType.QUARANTINE_RESTORED) == 1

    def test_refuses_to_quarantine_its_own_data(
        self, vault: Quarantine, config
    ) -> None:
        """The vault must never swallow the database or its own key."""
        target = Path(config.paths.data_dir) / "sentinel.db"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b"not really a database")
        verdict = build_verdict(str(target), [Detection("t", "X", 90)])

        with pytest.raises(QuarantineError, match="own file"):
            vault.quarantine(verdict)

    def test_copy_mode_leaves_the_original(self, vault: Quarantine, flagged_file) -> None:
        path, verdict = flagged_file
        vault.quarantine(verdict, delete_original=False)
        assert path.exists()

    def test_purge_by_age(self, vault: Quarantine, flagged_file, db) -> None:
        _, verdict = flagged_file
        entry = vault.quarantine(verdict)

        # Backdate the row by 60 days.
        with db.transaction() as conn:
            conn.execute(
                "UPDATE quarantine SET created_at=? WHERE token=?",
                (time.time() - 60 * 86400, entry.token),
            )

        assert vault.purge(older_than_days=90, dry_run=True) == []
        assert vault.purge(older_than_days=30, dry_run=True) == [entry.token]

        vault.purge(older_than_days=30)
        assert vault.list_entries() == []


# ----------------------------------------------------------------------
# whitelist
# ----------------------------------------------------------------------

class TestWhitelist:
    def test_hash_entry_matches_regardless_of_path(self, db, tmp_path: Path) -> None:
        whitelist = Whitelist(db)
        digest = "a" * 64
        whitelist.add(digest, "sha256", note="known good")

        hit = whitelist.check(tmp_path / "anywhere.exe", digest)
        assert hit is not None and hit.kind == "sha256"

    def test_path_entry(self, db, clean_file: Path) -> None:
        whitelist = Whitelist(db)
        whitelist.add(str(clean_file), "path")
        assert whitelist.is_whitelisted(clean_file)

    def test_prefix_entry_covers_children(self, db, tmp_path: Path) -> None:
        whitelist = Whitelist(db)
        directory = tmp_path / "projects" / "build"
        directory.mkdir(parents=True)
        whitelist.add(str(directory), "prefix")

        assert whitelist.is_whitelisted(directory / "output.exe")
        assert not whitelist.is_whitelisted(tmp_path / "elsewhere.exe")

    @pytest.mark.parametrize(
        "value",
        ["C:\\", "C:\\Users", "C:\\Windows"]
        if os.name == "nt"
        else ["/", "/home", "/etc", "/usr"],
    )
    def test_overbroad_prefixes_are_refused(self, db, value: str) -> None:
        """A prefix covering the filesystem would silently disable scanning.

        The candidates are platform-specific because entries are normalised
        to absolute paths: on Windows "/home" resolves to "C:\\home", which
        is a perfectly reasonable thing to whitelist.
        """
        with pytest.raises(WhitelistError, match="refusing to whitelist"):
            Whitelist(db).add(value, "prefix")

    def test_invalid_hash_is_refused(self, db) -> None:
        with pytest.raises(WhitelistError, match="not a sha256"):
            Whitelist(db).add("not-a-hash", "sha256")

    def test_duplicate_add_returns_false(self, db) -> None:
        whitelist = Whitelist(db)
        assert whitelist.add("b" * 64, "sha256") is True
        assert whitelist.add("b" * 64, "sha256") is False

    def test_remove(self, db) -> None:
        whitelist = Whitelist(db)
        whitelist.add("c" * 64, "sha256")
        assert whitelist.remove("c" * 64) is True
        assert whitelist.remove("c" * 64) is False
        assert whitelist.is_empty

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("d" * 64, "sha256"),
            ("/some/file.exe", "path"),
            ("/some/dir/", "prefix"),
        ],
    )
    def test_kind_inference(self, value: str, expected: str) -> None:
        assert infer_kind(value) == expected

    def test_whitelist_suppresses_a_real_detection(
        self, scanner, powershell_dropper: Path
    ) -> None:
        """End to end: a flagged file stops being flagged once whitelisted."""
        before = scanner.scan_file(powershell_dropper)
        assert before.is_threat

        scanner.whitelist.add(before.sha256, "sha256", note="test")

        after = scanner.scan_file(powershell_dropper)
        assert after.whitelisted
        assert not after.is_threat
        assert after.severity is Severity.CLEAN
