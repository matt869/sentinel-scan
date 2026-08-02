"""Structural heuristics for Windows PE binaries.

None of these signals is damning by itself — plenty of legitimate software is
packed, and plenty of installers call ``VirtualAlloc``. The value is in the
combination, which the noisy-OR aggregation in
:mod:`sentinel.engine.verdict` handles.

Every check here is deliberately conservative. False positives on a desktop
scanner cost far more than a missed sample: users who see their own tools
flagged stop trusting the scanner entirely.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from sentinel.engine.detectors.base import Detector, ScanTarget, registry
from sentinel.engine.verdict import Detection
from sentinel.utils.entropy import PACKED_FLOOR
from sentinel.utils.file_types import FileType, has_double_extension

try:
    import pefile

    _PEFILE_AVAILABLE = True
except ImportError:  # pragma: no cover - depends on the environment
    pefile = None  # type: ignore[assignment]
    _PEFILE_AVAILABLE = False


#: Section names used by well-known packers. Presence is informational: UPX
#: in particular is used by plenty of legitimate software.
PACKER_SECTIONS: dict[str, str] = {
    ".upx": "UPX",
    "upx0": "UPX",
    "upx1": "UPX",
    "upx2": "UPX",
    ".aspack": "ASPack",
    ".adata": "ASPack",
    ".themida": "Themida",
    ".vmp0": "VMProtect",
    ".vmp1": "VMProtect",
    ".enigma1": "Enigma",
    "petite": "Petite",
    ".mpress1": "MPRESS",
    ".mpress2": "MPRESS",
    "pebundle": "PEBundle",
    ".nsp0": "NsPack",
}

#: Imports that, taken together, describe process injection. Any one is
#: unremarkable; the whole set in one binary is not.
INJECTION_IMPORTS = frozenset(
    {
        "virtualallocex",
        "writeprocessmemory",
        "createremotethread",
        "ntwritevirtualmemory",
        "ntcreatethreadex",
        "queueuserapc",
        "setwindowshookexa",
        "setwindowshookexw",
        "rtlcreateuserthread",
    }
)

#: Imports associated with anti-analysis behaviour.
ANTI_ANALYSIS_IMPORTS = frozenset(
    {
        "isdebuggerpresent",
        "checkremotedebuggerpresent",
        "ntqueryinformationprocess",
        "outputdebugstringa",
        "getickcount",
        "queryperformancecounter",
    }
)

#: Imports used to build code at runtime — the classic packer/dropper stub.
DYNAMIC_CODE_IMPORTS = frozenset(
    {"virtualalloc", "virtualprotect", "loadlibrarya", "loadlibraryw", "getprocaddress"}
)


@registry.register
class PEHeuristicDetector(Detector):
    """Flags structural anomalies in PE/COFF executables."""

    name = "pe_heuristic"
    description = "Structural heuristics for Windows executables (packing, injection imports)"
    priority = 50
    wants = frozenset({FileType.PE})

    def available(self) -> bool:
        if not _PEFILE_AVAILABLE:
            self._unavailable_reason = (
                "pefile is not installed (pip install 'sentinel-scan[pe]')"
            )
            return False
        return True

    def scan(self, target: ScanTarget) -> Sequence[Detection]:
        data = target.data
        if data is None:
            return ()

        try:
            # fast_load skips parsing every directory; we pull only the ones
            # we need, which is roughly 10x faster on large binaries.
            pe = pefile.PE(data=data, fast_load=True)
        except Exception as exc:
            # A malformed PE is itself mildly interesting, but corrupt files
            # are common enough that we do not report on parse failure alone.
            self.log.debug("not a parseable PE: %s (%s)", target.display_path, exc)
            return ()

        try:
            return self._analyse(pe, target)
        except Exception as exc:  # pragma: no cover - defensive
            self.log.debug("PE analysis failed for %s: %s", target.display_path, exc)
            return ()
        finally:
            pe.close()

    # -- analysis ------------------------------------------------------

    def _analyse(self, pe: Any, target: ScanTarget) -> list[Detection]:
        findings: list[Detection] = []

        findings.extend(self._check_sections(pe))
        findings.extend(self._check_imports(pe))
        findings.extend(self._check_headers(pe))
        findings.extend(self._check_naming(target))

        return findings

    def _check_sections(self, pe: Any) -> list[Detection]:
        out: list[Detection] = []
        sections = getattr(pe, "sections", [])
        if not sections:
            return out

        packer_names: set[str] = set()
        high_entropy: list[str] = []
        writable_executable: list[str] = []

        for section in sections:
            raw_name = section.Name.rstrip(b"\x00").decode("ascii", errors="replace")
            lowered = raw_name.lower().strip()

            for marker, packer in PACKER_SECTIONS.items():
                if lowered.startswith(marker):
                    packer_names.add(packer)

            # Section entropy: only meaningful for sections with real data.
            if section.SizeOfRawData >= 4096:
                try:
                    entropy = section.get_entropy()
                except Exception:
                    entropy = 0.0
                if entropy >= PACKED_FLOOR:
                    high_entropy.append(f"{raw_name}:{entropy:.2f}")

            characteristics = section.Characteristics
            is_write = bool(characteristics & 0x80000000)
            is_exec = bool(characteristics & 0x20000000)
            if is_write and is_exec:
                writable_executable.append(raw_name)

        if packer_names:
            out.append(
                self.detection(
                    f"Heuristic.Packed.{sorted(packer_names)[0]}",
                    30.0,
                    f"Section names indicate the {', '.join(sorted(packer_names))} packer. "
                    "Legitimate software uses packers too — this is a weak signal.",
                    packers=sorted(packer_names),
                )
            )

        if high_entropy:
            ratio = len(high_entropy) / len(sections)
            out.append(
                self.detection(
                    "Heuristic.HighEntropySection",
                    45.0 if ratio > 0.5 else 25.0,
                    f"{len(high_entropy)} of {len(sections)} sections have entropy above "
                    f"{PACKED_FLOOR}, consistent with packed or encrypted code.",
                    sections=high_entropy[:8],
                )
            )

        if writable_executable:
            out.append(
                self.detection(
                    "Heuristic.WritableExecutableSection",
                    40.0,
                    "Sections marked both writable and executable — used by "
                    "self-modifying code and unpacking stubs.",
                    sections=writable_executable[:8],
                )
            )

        return out

    def _check_imports(self, pe: Any) -> list[Detection]:
        out: list[Detection] = []
        try:
            pe.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
            )
        except Exception:
            return out

        imports: set[str] = set()
        entries = getattr(pe, "DIRECTORY_ENTRY_IMPORT", None)
        if entries is None:
            # No import table at all. Normal for .NET assemblies and some
            # drivers, but also what a fully packed binary looks like.
            if not getattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT", None):
                out.append(
                    self.detection(
                        "Heuristic.NoImportTable",
                        30.0,
                        "The binary imports nothing, which usually means its real "
                        "imports are resolved at runtime after unpacking.",
                    )
                )
            return out

        for entry in entries:
            for imp in entry.imports or ():
                if imp.name:
                    imports.add(imp.name.decode("ascii", errors="replace").lower())

        injection = imports & INJECTION_IMPORTS
        if len(injection) >= 3:
            out.append(
                self.detection(
                    "Heuristic.ProcessInjection",
                    70.0,
                    "Imports the full set of APIs needed to write code into another "
                    "process and run it.",
                    apis=sorted(injection),
                )
            )
        elif len(injection) == 2:
            out.append(
                self.detection(
                    "Heuristic.ProcessInjection.Partial",
                    35.0,
                    "Imports several process-manipulation APIs.",
                    apis=sorted(injection),
                )
            )

        anti = imports & ANTI_ANALYSIS_IMPORTS
        if len(anti) >= 3:
            out.append(
                self.detection(
                    "Heuristic.AntiDebug",
                    40.0,
                    "Imports several debugger-detection APIs.",
                    apis=sorted(anti),
                )
            )

        dynamic = imports & DYNAMIC_CODE_IMPORTS
        if len(dynamic) >= 4 and len(imports) < 30:
            # A tiny import table consisting almost entirely of "allocate
            # memory, make it executable, resolve symbols" is a loader stub.
            out.append(
                self.detection(
                    "Heuristic.RuntimeCodeLoader",
                    45.0,
                    f"Only {len(imports)} imports, dominated by dynamic code-loading "
                    "APIs — the shape of an unpacking stub.",
                    apis=sorted(dynamic),
                    import_count=len(imports),
                )
            )

        return out

    def _check_headers(self, pe: Any) -> list[Detection]:
        out: list[Detection] = []

        # Entry point outside any section: hand-crafted or corrupted headers.
        try:
            entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            in_section = any(
                s.VirtualAddress <= entry_point < s.VirtualAddress + max(
                    s.Misc_VirtualSize, s.SizeOfRawData
                )
                for s in pe.sections
            )
            if pe.sections and not in_section:
                out.append(
                    self.detection(
                        "Heuristic.EntryPointOutsideSections",
                        55.0,
                        "The entry point does not fall inside any declared section.",
                        entry_point=hex(entry_point),
                    )
                )
        except Exception:
            pass

        # A checksum of zero is normal for non-driver user-mode binaries, so
        # only a *wrong* non-zero checksum is worth mentioning.
        try:
            declared = pe.OPTIONAL_HEADER.CheckSum
            if declared != 0:
                actual = pe.generate_checksum()
                if declared != actual:
                    out.append(
                        self.detection(
                            "Heuristic.ChecksumMismatch",
                            25.0,
                            "The PE checksum does not match the file contents, which "
                            "means the binary was modified after it was built.",
                            declared=hex(declared),
                            actual=hex(actual),
                        )
                    )
        except Exception:
            pass

        # Data appended after the last section — a common way to smuggle a
        # payload into an otherwise valid signed binary.
        try:
            last = max(pe.sections, key=lambda s: s.PointerToRawData + s.SizeOfRawData)
            end_of_image = last.PointerToRawData + last.SizeOfRawData
            overlay = len(pe.__data__) - end_of_image
            if overlay > 64 * 1024 and end_of_image > 0:
                ratio = overlay / len(pe.__data__)
                if ratio > 0.25:
                    out.append(
                        self.detection(
                            "Heuristic.LargeOverlay",
                            30.0,
                            f"{ratio:.0%} of the file sits after the last section. "
                            "Installers do this legitimately; so do droppers.",
                            overlay_bytes=overlay,
                        )
                    )
        except Exception:
            pass

        return out

    def _check_naming(self, target: ScanTarget) -> list[Detection]:
        out: list[Detection] = []

        if target.type_info.is_masquerading:
            out.append(
                self.detection(
                    "Heuristic.MasqueradingExtension",
                    75.0,
                    f"This is a Windows executable but is named '{target.extension}'. "
                    "There is no legitimate reason to disguise a program as a document.",
                    real_type="pe",
                    claimed_extension=target.extension,
                )
            )

        inner = has_double_extension(target.path)
        if inner:
            out.append(
                self.detection(
                    "Heuristic.DoubleExtension",
                    65.0,
                    f"Filename uses a double extension ('{inner}' before the real one) "
                    "to look like a document in file listings.",
                    inner_extension=inner,
                )
            )

        return out
