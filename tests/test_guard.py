"""Tests for the guard list and the confidence tiers.

These two defenses exist for the same scenario: a signature turns out to be
wrong. Every test here asks the same question in a different way — when the
detection logic is mistaken, does anything irreversible happen?
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from sentinel.core.config import Config
from sentinel.engine.guard import Guard, GuardError, GuardHit, GuardReason
from sentinel.engine.quarantine import Quarantine, QuarantineRefused
from sentinel.engine.verdict import Detection, Severity, build_verdict
from sentinel.utils.hashing import hash_file

WINDOWS = os.name == "nt"


@pytest.fixture
def guard(config: Config) -> Guard:
    # Signature checking off by default here: it is a syscall per call and
    # the path rules are what these tests are about. It has its own class.
    return Guard(config, check_signatures=False)


# ----------------------------------------------------------------------
# what is protected
# ----------------------------------------------------------------------

class TestSystemPaths:
    @pytest.mark.skipif(not WINDOWS, reason="Windows paths")
    @pytest.mark.parametrize(
        "path",
        [
            r"C:\Windows\System32\kernel32.dll",
            r"C:\Windows\System32\drivers\etc\hosts",
            r"C:\Windows\explorer.exe",
            r"C:\Windows",
        ],
    )
    def test_windows_system_files_are_protected(self, guard: Guard, path: str) -> None:
        hit = guard.check(path)
        assert hit is not None
        assert hit.reason is GuardReason.SYSTEM_PATH

    @pytest.mark.skipif(WINDOWS, reason="POSIX paths")
    @pytest.mark.parametrize(
        "path", ["/bin/sh", "/usr/lib/libc.so.6", "/boot/vmlinuz", "/etc/passwd"]
    )
    def test_posix_system_files_are_protected(self, guard: Guard, path: str) -> None:
        hit = guard.check(path)
        assert hit is not None
        assert hit.reason is GuardReason.SYSTEM_PATH

    @pytest.mark.skipif(not WINDOWS, reason="Windows paths")
    def test_sibling_directories_are_not_swallowed(self, guard: Guard) -> None:
        # C:\WindowsApps starts with the same characters as C:\Windows.
        # Matching on the prefix alone would protect it too, and a plain
        # string comparison is exactly the bug that would cause it.
        assert guard.check(r"C:\WindowsApps\something.exe") is None

    @pytest.mark.skipif(not WINDOWS, reason="Windows paths")
    def test_case_and_separators_do_not_matter(self, guard: Guard) -> None:
        for variant in (
            r"c:\windows\system32\kernel32.dll",
            r"C:/Windows/System32/kernel32.dll",
            r"C:\WINDOWS\System32\KERNEL32.DLL",
        ):
            assert guard.check(variant) is not None, variant

    @pytest.mark.skipif(not WINDOWS, reason="Windows paths")
    def test_traversal_cannot_escape_the_guard(self, guard: Guard) -> None:
        # Resolution happens before matching, so a path that *arrives at* a
        # system file is guarded however it was spelled.
        assert guard.check(r"C:\Users\..\Windows\System32\kernel32.dll") is not None

    def test_application_directories_are_not_protected(
        self, guard: Guard, tmp_path: Path
    ) -> None:
        # Program Files is deliberately absent from the list. Malware
        # installs there routinely, and protecting all of it would blind the
        # scanner to a whole class of real threats.
        sample = tmp_path / "app" / "installer.exe"
        sample.parent.mkdir()
        sample.write_bytes(b"MZ" + b"\x00" * 100)
        assert guard.check(sample) is None


class TestOwnFiles:
    def test_own_package_is_protected(self, guard: Guard) -> None:
        import sentinel

        # A scanner that quarantines its own code cannot restore anything,
        # including its own code.
        assert guard.check(Path(sentinel.__file__)) is not None

    def test_own_data_directory_is_protected(self, guard: Guard, config: Config) -> None:
        hit = guard.check(Path(config.paths.data_dir) / "sentinel.db")
        assert hit is not None
        assert hit.reason in (GuardReason.OWN_DATA, GuardReason.OWN_INSTALL)

    def test_vault_key_is_protected(self, guard: Guard, config: Config) -> None:
        # Losing this makes every quarantined file unrecoverable.
        assert guard.check(Path(config.paths.quarantine_dir) / "vault.key") is not None


class TestEdgeCases:
    def test_filesystem_root_is_protected(self, guard: Guard) -> None:
        root = "C:\\" if WINDOWS else "/"
        hit = guard.check(root)
        assert hit is not None
        assert hit.reason in (GuardReason.FILESYSTEM_ROOT, GuardReason.SYSTEM_PATH)

    def test_a_directory_is_not_an_ordinary_file(
        self, guard: Guard, tmp_path: Path
    ) -> None:
        directory = tmp_path / "somedir"
        directory.mkdir()
        hit = guard.check(directory)
        assert hit is not None
        assert hit.reason is GuardReason.NOT_A_FILE

    def test_ordinary_user_files_are_not_protected(
        self, guard: Guard, tmp_path: Path
    ) -> None:
        sample = tmp_path / "downloads" / "suspicious.exe"
        sample.parent.mkdir()
        sample.write_bytes(b"MZ" + b"\x00" * 100)
        assert guard.check(sample) is None

    def test_unresolvable_paths_are_guarded_not_allowed(self, guard: Guard) -> None:
        # When the answer is unclear, the safe response to "may I destroy
        # this?" is no.
        assert guard.check("\x00invalid\x00") is not None

    def test_enforce_raises(self, guard: Guard) -> None:
        system = r"C:\Windows\System32\kernel32.dll" if WINDOWS else "/bin/sh"
        with pytest.raises(GuardError):
            guard.enforce(system)

    def test_explanation_has_no_jargon(self) -> None:
        hit = GuardHit(GuardReason.SYSTEM_PATH, "C:/Windows/x.dll", "C:/Windows")
        text = hit.describe()
        assert "part of the operating system" in text
        for jargon in ("guard", "SYSTEM_PATH", "quarantine", "heuristic"):
            assert jargon not in text


# ----------------------------------------------------------------------
# the vault honours it
# ----------------------------------------------------------------------

class TestQuarantineRefusesGuardedFiles:
    def _verdict(self, path: Path, conclusive: bool = True) -> Any:
        return build_verdict(
            str(path),
            [Detection("hash", "Trojan.Test", 95, conclusive=conclusive)],
            sha256=hash_file(path) if path.is_file() else "",
        )

    def test_system_file_is_refused(
        self, config: Config, db: Any, tmp_path: Path
    ) -> None:
        # A file that is genuinely there, with a guard that considers its
        # directory a system root — the real arrangement, without needing to
        # put a test file inside C:\Windows.
        protected_root = tmp_path / "fakesystem"
        protected_root.mkdir()
        victim = protected_root / "kernel32.dll"
        victim.write_bytes(b"MZ critical operating system file")

        guard = Guard(config, check_signatures=False)
        guard._add(str(protected_root), GuardReason.SYSTEM_PATH)
        vault = Quarantine(config, db, guard=guard)

        with pytest.raises(QuarantineRefused) as caught:
            vault.quarantine(self._verdict(victim))

        assert caught.value.hit.reason is GuardReason.SYSTEM_PATH
        # The only assertion that actually matters.
        assert victim.is_file()
        assert victim.read_bytes() == b"MZ critical operating system file"

    def test_own_data_directory_is_refused(self, config: Config, db: Any) -> None:
        victim = Path(config.paths.data_dir) / "sentinel.db"
        victim.parent.mkdir(parents=True, exist_ok=True)
        victim.write_bytes(b"the scan history")

        vault = Quarantine(config, db, guard=Guard(config, check_signatures=False))
        with pytest.raises(QuarantineRefused):
            vault.quarantine(self._verdict(victim))
        assert victim.is_file()

    def test_ordinary_file_is_still_quarantined(
        self, config: Config, db: Any, tmp_path: Path
    ) -> None:
        # The guard must not be so broad that nothing can be quarantined.
        victim = tmp_path / "downloads" / "malware.exe"
        victim.parent.mkdir()
        victim.write_bytes(b"MZ definitely malicious")

        vault = Quarantine(config, db, guard=Guard(config, check_signatures=False))
        entry = vault.quarantine(self._verdict(victim))

        assert not victim.exists()
        assert (Path(config.paths.quarantine_dir) / entry.stored_name).is_file()

    def test_guard_cannot_be_switched_off_by_configuration(
        self, config: Config, db: Any
    ) -> None:
        # There is no setting for this on purpose. A vault built the normal
        # way always has a guard.
        vault = Quarantine(config, db)
        assert vault.guard is not None
        assert vault.guard.is_protected(Path(config.paths.data_dir) / "sentinel.db")


# ----------------------------------------------------------------------
# confidence tiers
# ----------------------------------------------------------------------

class TestConfidenceTiers:
    def _heuristic_verdict(self, path: str) -> Any:
        # The exact shape a PowerShell dropper produces: six independent
        # script heuristics, not one of them conclusive.
        return build_verdict(path, [
            Detection("script", "Heuristic.Script.Dropper", 60),
            Detection("script", "Heuristic.Script.Dropper", 40),
            Detection("script", "Heuristic.Script.ps_bypass", 35),
            Detection("script", "Heuristic.Script.ps_download", 30),
            Detection("script", "Heuristic.Script.ps_hidden_window", 25),
            Detection("script", "Heuristic.Script.eval_string", 22),
        ])

    def test_stacked_heuristics_clear_the_severity_threshold(self) -> None:
        # Establishes the premise: severity alone would let these through.
        verdict = self._heuristic_verdict("x.ps1")
        assert verdict.severity is Severity.CRITICAL
        assert verdict.severity >= Severity.HIGH

    def test_heuristics_are_reported_not_quarantined(
        self, scanner: Any, tmp_path: Path, powershell_dropper: Path
    ) -> None:
        directory = tmp_path / "drop"
        directory.mkdir()
        target = directory / powershell_dropper.name
        target.write_bytes(powershell_dropper.read_bytes())

        result = scanner.scan_paths([directory], quarantine_threats=True)

        assert result.threat_count == 1
        finding = result.threats[0]
        assert finding.severity >= Severity.HIGH
        assert finding.action == "reported"
        # Still there. The user is told; nothing was done to their file.
        assert target.is_file()

    def test_exact_hash_match_does_act(
        self, scanner: Any, hash_signature_db: Any, tmp_path: Path
    ) -> None:
        directory = tmp_path / "known"
        directory.mkdir()
        target = directory / "sample.bin"
        target.write_bytes(b"a known bad payload" * 50)
        hash_signature_db(hash_file(target), "Trojan.Test.Known", "critical")

        result = scanner.scan_paths([directory], quarantine_threats=True)

        assert result.threat_count == 1
        assert result.threats[0].action == "quarantined"
        assert not target.exists()

    def test_guarded_finding_is_marked_protected_not_failed(
        self, config: Config, db: Any, bus: Any, tmp_path: Path,
        hash_signature_db: Any,
    ) -> None:
        from sentinel.engine.scanner import Scanner

        protected_root = tmp_path / "sysdir"
        protected_root.mkdir()
        target = protected_root / "important.dll"
        target.write_bytes(b"a known bad payload" * 50)
        hash_signature_db(hash_file(target), "Trojan.Test.Known", "critical")

        scanner = Scanner(config, bus=bus, db=db, detectors=["hash"])
        scanner.quarantine.guard._add(str(protected_root), GuardReason.SYSTEM_PATH)
        try:
            result = scanner.scan_paths([protected_root], quarantine_threats=True)
        finally:
            scanner.close()

        assert result.threat_count == 1
        # "protected", not "quarantine-failed": a refusal that protected the
        # user is not an error they need to chase.
        assert result.threats[0].action == "protected"
        assert target.is_file()
