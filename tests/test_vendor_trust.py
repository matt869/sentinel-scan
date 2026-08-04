"""Who counts as "the operating system vendor put this here".

Windows and macOS answer with a signature. Linux has no such thing —
distribution binaries are vouched for by the package manager that installed
them — so the question becomes whether a package owns the path.

The asymmetry is the point, and it is why the extra conditions exist.
Authenticode signs the *bytes*. dpkg and rpm record the *path*, so an
attacker who overwrote /usr/bin/apt-key would leave dpkg still claiming it.
Ownership alone would launder that; ownership plus root-only write does not,
because an attacker who can rewrite a root-owned file in /usr/bin already has
root and is not being held back by a heuristic on a shell script.
"""

from __future__ import annotations

import stat
import sys
from pathlib import Path

import pytest

from sentinel.system import authenticode
from sentinel.system.authenticode import os_vendor_signer

linux_only = pytest.mark.skipif(
    not sys.platform.startswith("linux"), reason="Linux package manager"
)


def test_it_never_raises(tmp_path: Path) -> None:
    """Called on every file about to be reported. It must not be able to fail."""
    for candidate in (tmp_path / "missing", tmp_path, Path("")):
        assert isinstance(os_vendor_signer(candidate), str)


def test_an_ordinary_file_is_not_vendor_provided(tmp_path: Path) -> None:
    """The case that matters: malware must not be cleared."""
    script = tmp_path / "dropper.sh"
    script.write_text("#!/bin/sh\necho hi\n", encoding="utf-8")
    assert os_vendor_signer(script) == ""


# ----------------------------------------------------------------------
# Linux
# ----------------------------------------------------------------------

@linux_only
def test_a_distribution_binary_is_recognised() -> None:
    """/usr/bin/ls belongs to a package on every distribution that has one."""
    if not authenticode._linux_package_query():
        pytest.skip("no dpkg or rpm on this host")
    signer = os_vendor_signer("/usr/bin/ls")
    assert signer, "a packaged system binary was not recognised as vendor-provided"
    assert "package" in signer


@linux_only
def test_the_regression_this_was_written_for() -> None:
    """apt-key is a shell script that base64-decodes and evals.

    Both are real heuristics and both fire on it. It is also Debian's own
    tool, shipped by the distribution — and the benign-corpus gate scans
    /usr/bin, so this one file turned every Linux CI job red.
    """
    if not Path("/usr/bin/apt-key").is_file():
        pytest.skip("apt-key is not installed on this host")
    assert os_vendor_signer("/usr/bin/apt-key")


@linux_only
def test_usr_local_is_not_the_distribution(tmp_path: Path) -> None:
    """/usr/local is for software the distribution did not ship."""
    assert os_vendor_signer("/usr/local") == ""


@linux_only
def test_a_world_writable_system_file_is_not_trusted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Package ownership is over the path, not the bytes.

    So the permission check is load-bearing rather than belt-and-braces: it
    is the only thing standing between "a package claims this path" and "only
    root could have put these bytes here".
    """
    target = tmp_path / "writable"
    target.write_text("#!/bin/sh\n", encoding="utf-8")
    target.chmod(0o777)

    monkeypatch.setattr(
        authenticode, "_LINUX_SYSTEM_PREFIXES", (str(tmp_path) + "/",)
    )
    # Claim every path is packaged, so only the permission test can refuse.
    monkeypatch.setattr(
        authenticode, "_linux_package_query", lambda: ["/bin/echo", "pkg:"]
    )
    assert authenticode._linux_vendor_signer(target) == ""


@linux_only
def test_a_missing_package_manager_is_survivable(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    """Alpine, a container, a distribution nobody thought of."""
    monkeypatch.setattr(authenticode, "_linux_package_query", lambda: [])
    assert authenticode._linux_vendor_signer(Path("/usr/bin/ls")) == ""


# ----------------------------------------------------------------------
# macOS
# ----------------------------------------------------------------------

@pytest.mark.skipif(sys.platform != "darwin", reason="macOS system paths")
def test_macos_system_scripts_are_recognised() -> None:
    """codesign answers for Mach-O binaries, not for the scripts beside them.

    Those are covered by System Integrity Protection instead, which is why
    the fallback exists at all.
    """
    for candidate in ("/usr/bin/ls", "/bin/sh"):
        assert os_vendor_signer(candidate), f"{candidate} was not recognised"


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS system paths")
def test_macos_usr_local_is_not_the_vendor() -> None:
    assert authenticode._macos_system_integrity(Path("/usr/local")) == ""


# ----------------------------------------------------------------------
# the guarantee that must not move
# ----------------------------------------------------------------------

def test_a_conclusive_detection_is_never_suppressed(
    scanner: object, tmp_path: Path
) -> None:
    """Vendor trust suppresses heuristics only.

    Certificates get stolen and packages get compromised; an exact digest
    match against a known sample is knowledge, not a guess, and it outranks
    both. Enforced in Scanner._vendor_signature_clears.
    """
    from sentinel.engine.verdict import Detection

    clears = scanner._vendor_signature_clears  # type: ignore[attr-defined]

    class FakeTarget:
        path = "/usr/bin/ls"
        display_path = "/usr/bin/ls"
        depth = 0

    conclusive = [Detection(name="X", confidence=100, detector="hash",
                            conclusive=True)]
    assert clears(FakeTarget(), conclusive) is False


def test_prefixes_all_end_in_a_separator() -> None:
    """Otherwise /usr/binary-of-mine matches the /usr/bin prefix."""
    for prefix in (
        *authenticode._LINUX_SYSTEM_PREFIXES,
        *authenticode._MACOS_SYSTEM_PREFIXES,
    ):
        assert prefix.endswith("/"), prefix


def test_the_restricted_flag_constant_is_right() -> None:
    """SF_RESTRICTED, spelled out because Python exposes it only on BSD.

    A wrong constant here fails silently and in the safe-looking direction:
    the flag never matches, so nothing is ever recognised, so the heuristics
    keep firing on Apple's own scripts and the only symptom is a red gate on
    one platform.
    """
    assert authenticode._SF_RESTRICTED == 0x00080000
    if hasattr(stat, "SF_RESTRICTED"):
        assert authenticode._SF_RESTRICTED == stat.SF_RESTRICTED
