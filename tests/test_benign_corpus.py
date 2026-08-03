"""The benign corpus: files that must never be flagged.

This is the counterweight to every detector in the project. Detection tests
ask "does it catch the bad thing?", and it is easy to pass all of them by
becoming more aggressive. This file asks the question that stops that:
*what does the new rule do to ordinary files?* A pull request that makes any
detector flag anything here fails the build.

False positives are the number that kills trust. A missed sample is invisible
to the user; a legitimate file moved into quarantine is not, and one of those
costs more confidence than a hundred good detections buy.

Two corpora, and both matter:

**Synthetic.** Files built here to look like the ordinary things that trip
naive heuristics — a certificate in a config file is base64, an installer
does download things, minified JavaScript is unreadable, a compressed archive
is high entropy. Deterministic and runs everywhere.

**The host's own binaries.** Real DLLs and executables sampled from the
machine running the tests. Nothing is committed — the samples are whatever
the OS already installed — and this is the part that catches the rule which
looks fine against synthetic data and flags a third of ``/usr/bin``.

No malware is committed here, in keeping with ``tests/samples/README.md``.
Every file is either generated at runtime or already part of the operating
system.
"""

from __future__ import annotations

import os
import struct
import sys
import zipfile
from pathlib import Path
from typing import Any

import pytest

from sentinel.engine.verdict import Severity

# ----------------------------------------------------------------------
# synthetic look-alikes
# ----------------------------------------------------------------------

def _minimal_pe(
    sections: list[tuple[bytes, bytes]],
    *,
    characteristics: int = 0x60000020,
    entry_point: int = 0x1000,
) -> bytes:
    """A structurally valid little PE with the given named sections.

    Enough of a header for the PE heuristics to parse and form an opinion,
    which is the point — a stub they reject as unparseable tests nothing.
    """
    e_lfanew = 0x80
    dos = b"MZ" + b"\x00" * (e_lfanew - 2)
    dos = dos[:0x3C] + struct.pack("<I", e_lfanew) + dos[0x40:]

    coff = struct.pack(
        "<4sHHIIIHH",
        b"PE\x00\x00", 0x8664, len(sections), 0, 0, 0, 240, 0x2022,
    )
    # PE32+ optional header: magic, linker version, then sizes; the entry
    # point sits at offset 16.
    optional = (
        struct.pack("<HBB", 0x20B, 14, 0)
        + struct.pack("<III", 0, 0, 0)
        + struct.pack("<I", entry_point)
        + b"\x00" * 220
    )

    headers = b""
    offset = 0x400
    virtual = 0x1000
    for name, body in sections:
        size = max(len(body), 0x200)
        headers += struct.pack(
            "<8sIIIIIIHHI",
            name.ljust(8, b"\x00"), size, virtual, size, offset, 0, 0, 0, 0,
            characteristics,
        )
        offset += size
        virtual += 0x1000

    blob = dos + coff + optional + headers
    blob = blob.ljust(0x400, b"\x00")
    for _, body in sections:
        blob += body.ljust(0x200, b"\x00")
    return blob


def build_synthetic_corpus(directory: Path) -> list[Path]:
    """Write the ordinary-file corpus into *directory* and return the paths."""
    directory.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []

    def write(name: str, content: bytes | str) -> None:
        path = directory / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, str):
            path.write_text(content, encoding="utf-8")
        else:
            path.write_bytes(content)
        written.append(path)

    # A certificate in a config file. Base64 is not obfuscation, and treating
    # long encoded blobs as suspicious flags every TLS config on earth.
    write("app.config", (
        "[server]\nhost = example.com\nport = 443\n\n"
        "[tls]\ncertificate = \"\"\"\n-----BEGIN CERTIFICATE-----\n"
        + "MIIDdzCCAl+gAwIBAgIEbGVnaXQwDQYJKoZIhvcNAQELBQAwSTELMAkGA1UEBhMC\n" * 12
        + "-----END CERTIFICATE-----\n\"\"\"\n"
    ))

    # An installer that downloads things, because installers download things.
    # The dropper heuristic must want more than "fetches a URL" before it
    # fires, or every package manager on the machine becomes a threat.
    write("install.ps1", (
        "# Install the widget toolchain.\n"
        "$ErrorActionPreference = 'Stop'\n"
        "$version = '2.4.1'\n"
        "$url = \"https://downloads.example.com/widget/$version/widget.msi\"\n"
        "$dest = Join-Path $env:TEMP 'widget.msi'\n"
        "Write-Host \"Downloading widget $version...\"\n"
        "Invoke-WebRequest -Uri $url -OutFile $dest\n"
        "Start-Process msiexec.exe -ArgumentList '/i', $dest, '/quiet' -Wait\n"
        "Remove-Item $dest\n"
        "Write-Host 'Done.'\n"
    ))

    # A normal build script.
    write("build.sh", (
        "#!/usr/bin/env bash\nset -euo pipefail\n\n"
        "BUILD_DIR=${BUILD_DIR:-build}\n"
        "mkdir -p \"$BUILD_DIR\"\n"
        "cmake -S . -B \"$BUILD_DIR\" -DCMAKE_BUILD_TYPE=Release\n"
        "cmake --build \"$BUILD_DIR\" --parallel \"$(nproc)\"\n"
        "ctest --test-dir \"$BUILD_DIR\" --output-on-failure\n"
    ))

    # Minified JavaScript. Unreadable is not the same as malicious; every
    # site on the internet ships this.
    write("vendor.min.js", (
        "!function(e,t){\"object\"==typeof exports&&\"undefined\"!=typeof module?"
        "t(exports):\"function\"==typeof define&&define.amd?define([\"exports\"],t):"
        "t((e=e||self).lib={})}(this,function(e){\"use strict\";function t(e,t){"
        "return e.replace(/%s/g,t)}function n(e){return e&&e.length?e[0]:null}"
        "e.format=t,e.first=n,Object.defineProperty(e,\"__esModule\",{value:!0})});"
    ) * 6)

    # A registry export. Full of paths and Run keys, which is what a
    # persistence heuristic looks for -- and also what every backup contains.
    write("settings.reg", (
        "Windows Registry Editor Version 5.00\r\n\r\n"
        "[HKEY_CURRENT_USER\\Software\\ExampleCorp\\Widget]\r\n"
        "\"InstallPath\"=\"C:\\\\Program Files\\\\Widget\"\r\n"
        "\"Version\"=\"2.4.1\"\r\n"
        "\"FirstRun\"=dword:00000000\r\n"
    ))

    # A high-entropy blob: compressed or encrypted user data. Entropy alone
    # says nothing about intent -- every .docx and .jpg on the disk is here.
    write("archive.bin", bytes((i * 167 + 13) % 256 for i in range(200_000)))

    # A resource-only DLL: no code, no entry point, no imports, and a
    # compressed .rsrc. Every one of those is a signal in isolation, and this
    # shape is a large slice of the DLLs shipped with Windows — string
    # tables, icon packs, MUI files. It must not be interesting.
    write("resources.dll", _minimal_pe(
        [
            (b".rsrc", bytes((i * 211 + 7) % 256 for i in range(6000))),
            (b".data", b"Widget resources 2.4.1\x00"),
        ],
        characteristics=0x40000040,  # initialised data, read-only, no code
        entry_point=0,
    ))

    # A zip of documents, the ordinary case for the archive detector.
    documents = directory / "reports.zip"
    with zipfile.ZipFile(documents, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("q1.txt", "Revenue was up.\n" * 300)
        archive.writestr("q2.txt", "Revenue was flat.\n" * 300)
        archive.writestr("notes/summary.md", "# Summary\n\n- Steady.\n")
    written.append(documents)

    # Plain files that must never be interesting to anything.
    write("README.md", "# Widget\n\nA widget.\n\n## Install\n\nRun `install.ps1`.\n")
    write("data.csv", "id,name,amount\n" + "".join(
        f"{i},item-{i},{i * 3.5:.2f}\n" for i in range(500)
    ))
    write("notes.txt", "Remember to renew the domain.\n" * 50)

    return written


@pytest.fixture
def synthetic_corpus(tmp_path: Path) -> list[Path]:
    return build_synthetic_corpus(tmp_path / "benign")


# ----------------------------------------------------------------------
# the tests
# ----------------------------------------------------------------------

def _describe(verdict: Any) -> str:
    """Why this failed, in enough detail to fix the rule that caused it."""
    lines = [
        f"{Path(verdict.path).name} was flagged "
        f"{verdict.severity.value} (score {verdict.score:.0f}) — "
        f"this file is benign and nothing should fire on it."
    ]
    for detection in verdict.detections:
        lines.append(
            f"    {detection.detector}: {detection.name} "
            f"({detection.confidence:.0f}%) — {detection.description}"
        )
    return "\n".join(lines)


class TestSyntheticCorpus:
    """Ordinary files, of the shapes that trip naive heuristics."""

    def test_nothing_is_flagged(self, scanner: Any, synthetic_corpus: list[Path]) -> None:
        directory = synthetic_corpus[0].parent
        result = scanner.scan_paths([directory])

        assert result.files_scanned >= len(synthetic_corpus)
        findings = result.threats + result.suspicious
        assert not findings, "\n" + "\n".join(_describe(v) for v in findings)

    def test_no_file_even_scores(
        self, scanner: Any, synthetic_corpus: list[Path]
    ) -> None:
        # Stricter than "not a threat": a benign file scoring 25 is one new
        # weak rule away from being a threat, and that is how false positives
        # arrive — not in one bad rule, but in the fifth mediocre one.
        for path in synthetic_corpus:
            verdict = scanner.scan_file(path)
            assert verdict.severity is Severity.CLEAN, _describe(verdict)
            assert verdict.score < 30, _describe(verdict)


# ----------------------------------------------------------------------
# the host's own binaries
# ----------------------------------------------------------------------

def _system_binary_dir() -> Path | None:
    """A directory of real, trusted OS binaries on this machine."""
    if os.name == "nt":
        root = Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "System32"
    elif sys.platform == "darwin":
        root = Path("/usr/bin")
    else:
        root = Path("/usr/bin")
    return root if root.is_dir() else None


def _sample_system_binaries(limit: int = 120) -> list[Path]:
    """Up to *limit* readable binaries from the OS, in a stable order.

    Sorted rather than randomly sampled: a corpus test that picks different
    files each run turns a real regression into a flaky one, and nobody
    trusts a gate that fails at random.
    """
    directory = _system_binary_dir()
    if directory is None:
        return []

    suffixes = {".dll", ".exe"} if os.name == "nt" else {"", ".so"}
    found: list[Path] = []
    try:
        for path in sorted(directory.iterdir()):
            if len(found) >= limit:
                break
            if not path.is_file() or path.suffix.lower() not in suffixes:
                continue
            try:
                # Skip anything held open or unreadable; that is an error
                # case, not a false positive, and it has its own tests.
                with open(path, "rb") as handle:
                    handle.read(1)
            except OSError:
                continue
            found.append(path)
    except OSError:
        return []
    return found


class TestSystemBinaries:
    """Real operating-system binaries. The rules must leave them alone."""

    def test_operating_system_binaries_are_clean(self, scanner: Any) -> None:
        samples = _sample_system_binaries()
        if len(samples) < 20:
            pytest.skip("no readable directory of system binaries on this host")

        flagged = []
        for path in samples:
            verdict = scanner.scan_file(path)
            if verdict.severity is not Severity.CLEAN:
                flagged.append(verdict)

        assert not flagged, (
            f"\n{len(flagged)} of {len(samples)} operating-system binaries were "
            f"flagged. These ship with the OS; if the scanner moved them the "
            f"machine would not boot.\n"
            + "\n".join(_describe(v) for v in flagged)
        )

    def test_the_corpus_is_actually_populated(self) -> None:
        # A gate that silently tests nothing is worse than no gate, because
        # it reports success. If this skips everywhere, the guard above is
        # decorative.
        samples = _sample_system_binaries(limit=10)
        if not samples:
            pytest.skip("no system binary directory on this host")
        assert all(p.stat().st_size > 0 for p in samples)
