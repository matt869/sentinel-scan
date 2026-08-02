"""Archive inspection.

Two jobs:

1. Flag archive-level anomalies — decompression bombs, encrypted archives
   whose contents are executable, executables with deceptive member names.
2. Extract members and hand them back to the engine so every other detector
   sees them too.

Step 2 needs a way back into the scan pipeline. The :class:`Scanner` injects
a callback via :meth:`ArchiveDetector.set_member_scanner` after construction;
without it the detector still performs step 1.

Safety limits are non-negotiable here. Archive parsing is a classic
denial-of-service surface: a 42 KB zip that expands to 4.5 PB is a real,
widely-mirrored file. Every extraction is bounded by member count, per-member
size, total size and nesting depth, and every member path is validated
against traversal.
"""

from __future__ import annotations

import bz2
import gzip
import lzma
import tarfile
import tempfile
import zipfile
from collections.abc import Callable, Iterator, Sequence
from pathlib import Path
from typing import Any

from sentinel.engine.detectors.base import Detector, ScanTarget, registry
from sentinel.engine.verdict import Detection
from sentinel.utils.file_types import ARCHIVE_TYPES, FileType, guess_type

#: Hard limits. These are ceilings, not tuning knobs — raising them exposes
#: the scanner to decompression bombs.
MAX_MEMBERS = 1000
MAX_MEMBER_SIZE = 128 * 1024 * 1024
MAX_TOTAL_EXTRACTED = 512 * 1024 * 1024

#: Compressed-to-uncompressed ratio above which we call it a bomb. Ordinary
#: text compresses around 3-5x; even highly redundant logs rarely beat 100x.
BOMB_RATIO = 200.0
#: Ratio alone is not enough — a 10-byte file expanding to 10 KB is 1000x and
#: harmless. Require real expansion too.
BOMB_MIN_EXPANDED = 100 * 1024 * 1024

MemberScanner = Callable[[ScanTarget], Sequence[Detection]]


@registry.register
class ArchiveDetector(Detector):
    """Inspects archives and recurses into their members."""

    name = "archive"
    description = "Opens archives, flags bombs, and scans the contents"
    priority = 60
    wants = frozenset(ARCHIVE_TYPES)

    def __init__(self, config: Any = None) -> None:
        super().__init__(config)
        self._member_scanner: MemberScanner | None = None
        scan_cfg = getattr(config, "scan", None)
        self._max_depth = getattr(scan_cfg, "archive_depth", 2) if scan_cfg else 2

    def set_member_scanner(self, scanner: MemberScanner) -> None:
        """Give the detector a way to run the full pipeline on a member."""
        self._member_scanner = scanner

    def interested_in(self, target: ScanTarget) -> bool:
        if self._max_depth <= 0:
            return False
        if target.depth >= self._max_depth:
            return False
        return target.file_type in ARCHIVE_TYPES

    def scan(self, target: ScanTarget) -> Sequence[Detection]:
        handler = {
            FileType.ZIP: self._scan_zip,
            FileType.TAR: self._scan_tar,
            FileType.GZIP: self._scan_stream,
            FileType.BZIP2: self._scan_stream,
            FileType.XZ: self._scan_stream,
        }.get(target.file_type)

        if handler is None:
            # RAR, 7z and CAB need external libraries we do not depend on.
            # We can still say something useful about the container itself.
            return self._scan_opaque(target)

        try:
            return handler(target)
        except Exception as exc:
            self.log.debug("archive %s could not be read: %s", target.display_path, exc)
            return (
                self.detection(
                    "Heuristic.Archive.Unreadable",
                    15.0,
                    "The archive header is valid but the contents could not be "
                    "read. Truncated or deliberately malformed archives are "
                    "sometimes used to defeat scanners.",
                    error=str(exc)[:200],
                ),
            )

    # -- format handlers -----------------------------------------------

    def _scan_zip(self, target: ScanTarget) -> list[Detection]:
        findings: list[Detection] = []

        with zipfile.ZipFile(target.path) as archive:
            infos = archive.infolist()[:MAX_MEMBERS + 1]
            if len(infos) > MAX_MEMBERS:
                findings.append(
                    self.detection(
                        "Heuristic.Archive.TooManyMembers",
                        25.0,
                        f"Archive holds more than {MAX_MEMBERS:,} entries; only the "
                        "first batch was inspected.",
                        member_count=len(infos),
                    )
                )
                infos = infos[:MAX_MEMBERS]

            compressed = sum(i.compress_size for i in infos)
            expanded = sum(i.file_size for i in infos)
            findings.extend(self._check_bomb(compressed, expanded))

            encrypted = [i for i in infos if i.flag_bits & 0x1]
            names = [i.filename for i in infos if not i.is_dir()]
            findings.extend(self._check_member_names(names))

            if encrypted:
                findings.extend(self._check_encrypted(encrypted, names))
                # Encrypted members cannot be extracted without the password.
                return findings

            if self._member_scanner is not None:
                findings.extend(self._scan_members(target, self._extract_zip(archive, infos)))

        return findings

    def _extract_zip(
        self, archive: zipfile.ZipFile, infos: list[zipfile.ZipInfo]
    ) -> Iterator[tuple[str, Path, Path]]:
        """Yield (member_name, extracted_path, temp_root) for safe members."""
        total = 0
        with tempfile.TemporaryDirectory(prefix="sentinel-zip-") as tmp:
            root = Path(tmp)
            for info in infos:
                if info.is_dir():
                    continue
                if info.file_size > MAX_MEMBER_SIZE:
                    self.log.debug("skipping oversized member %s", info.filename)
                    continue
                if total + info.file_size > MAX_TOTAL_EXTRACTED:
                    self.log.debug("extraction budget exhausted in %s", archive.filename)
                    break

                destination = _safe_destination(root, info.filename)
                if destination is None:
                    # Path traversal attempt; reported separately by
                    # _check_member_names.
                    continue

                try:
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    with archive.open(info) as src, open(destination, "wb") as dst:
                        # Copy with a cap rather than trusting the declared
                        # size — the header can lie.
                        written = _bounded_copy(src, dst, MAX_MEMBER_SIZE)
                    total += written
                except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
                    self.log.debug("cannot extract %s: %s", info.filename, exc)
                    continue

                yield info.filename, destination, root

    def _scan_tar(self, target: ScanTarget) -> list[Detection]:
        findings: list[Detection] = []

        with tarfile.open(target.path) as archive:
            members = []
            for index, member in enumerate(archive):
                if index >= MAX_MEMBERS:
                    break
                members.append(member)

            names = [m.name for m in members if m.isfile()]
            findings.extend(self._check_member_names(names))

            expanded = sum(m.size for m in members)
            findings.extend(self._check_bomb(target.size, expanded))

            # tar supports symlinks and hardlinks pointing outside the tree.
            escaping = [
                m.name for m in members
                if (m.issym() or m.islnk()) and _escapes(m.linkname)
            ]
            if escaping:
                findings.append(
                    self.detection(
                        "Heuristic.Archive.LinkEscape",
                        70.0,
                        "Archive contains links pointing outside the extraction "
                        "directory, which can overwrite arbitrary files when "
                        "unpacked by a naive tool.",
                        members=escaping[:5],
                    )
                )

            if self._member_scanner is not None:
                findings.extend(
                    self._scan_members(target, self._extract_tar(archive, members))
                )

        return findings

    def _extract_tar(
        self, archive: tarfile.TarFile, members: list[tarfile.TarInfo]
    ) -> Iterator[tuple[str, Path, Path]]:
        total = 0
        with tempfile.TemporaryDirectory(prefix="sentinel-tar-") as tmp:
            root = Path(tmp)
            for member in members:
                if not member.isfile() or member.size > MAX_MEMBER_SIZE:
                    continue
                if total + member.size > MAX_TOTAL_EXTRACTED:
                    break

                destination = _safe_destination(root, member.name)
                if destination is None:
                    continue

                try:
                    source = archive.extractfile(member)
                    if source is None:
                        continue
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    with source, open(destination, "wb") as dst:
                        total += _bounded_copy(source, dst, MAX_MEMBER_SIZE)
                except (OSError, tarfile.TarError) as exc:
                    self.log.debug("cannot extract %s: %s", member.name, exc)
                    continue

                yield member.name, destination, root

    def _scan_stream(self, target: ScanTarget) -> list[Detection]:
        """Handle single-stream compressors (gzip, bzip2, xz)."""
        opener = {
            FileType.GZIP: gzip.open,
            FileType.BZIP2: bz2.open,
            FileType.XZ: lzma.open,
        }[target.file_type]

        findings: list[Detection] = []
        if self._member_scanner is None:
            return findings

        inner_name = target.path.stem or target.path.name
        with tempfile.TemporaryDirectory(prefix="sentinel-gz-") as tmp:
            destination = Path(tmp) / inner_name
            try:
                with opener(target.path, "rb") as src, open(destination, "wb") as dst:
                    expanded = _bounded_copy(src, dst, MAX_MEMBER_SIZE)
            except (OSError, EOFError, lzma.LZMAError) as exc:
                self.log.debug("cannot decompress %s: %s", target.display_path, exc)
                return findings

            findings.extend(self._check_bomb(target.size, expanded))
            findings.extend(
                self._scan_members(target, iter([(inner_name, destination, Path(tmp))]))
            )

        return findings

    def _scan_opaque(self, target: ScanTarget) -> list[Detection]:
        """Formats we cannot open — report only what the container implies."""
        # A .rar or .7z is not suspicious. Say nothing rather than guess.
        self.log.debug(
            "no extractor for %s (%s); contents not inspected",
            target.display_path, target.file_type.value,
        )
        return []

    # -- shared checks -------------------------------------------------

    def _check_bomb(self, compressed: int, expanded: int) -> list[Detection]:
        if compressed <= 0 or expanded < BOMB_MIN_EXPANDED:
            return []
        ratio = expanded / compressed
        if ratio < BOMB_RATIO:
            return []
        return [
            self.detection(
                "Heuristic.Archive.DecompressionBomb",
                80.0,
                f"Expands {ratio:,.0f}x to {expanded / 1024 / 1024:,.0f} MB. "
                "Archives with this ratio are built to exhaust disk or memory.",
                ratio=round(ratio, 1),
                compressed_size=compressed,
                expanded_size=expanded,
            )
        ]

    def _check_member_names(self, names: list[str]) -> list[Detection]:
        out: list[Detection] = []

        traversal = [n for n in names if _escapes(n)]
        if traversal:
            out.append(
                self.detection(
                    "Heuristic.Archive.PathTraversal",
                    75.0,
                    "Member paths escape the extraction directory ('../' or an "
                    "absolute path). This is used to drop files into startup "
                    "folders during a normal-looking unzip.",
                    members=traversal[:5],
                )
            )

        # Right-to-left override: makes "photo\u202Egnp.exe" render as
        # "photoexe.png" in every file manager.
        rtl = [n for n in names if "\u202e" in n or "\u202d" in n]
        if rtl:
            out.append(
                self.detection(
                    "Heuristic.Archive.RTLOverride",
                    85.0,
                    "Member names contain a right-to-left override character, "
                    "which reverses the displayed extension to disguise an "
                    "executable. There is no legitimate use for this.",
                    members=[n.encode("unicode_escape").decode() for n in rtl[:5]],
                )
            )

        deceptive = [
            n for n in names
            if guess_type(n, b"").claimed_type in {FileType.PE, FileType.SCRIPT}
            and len(Path(n).name.split(".")) >= 3
        ]
        if deceptive:
            out.append(
                self.detection(
                    "Heuristic.Archive.DoubleExtensionMember",
                    45.0,
                    "Archive contains executables using double extensions to look "
                    "like documents.",
                    members=deceptive[:5],
                )
            )

        return out

    def _check_encrypted(
        self, encrypted: list[zipfile.ZipInfo], names: list[str]
    ) -> list[Detection]:
        """Password-protected archives cannot be inspected — say so honestly."""
        executable_members = [
            n for n in names
            if guess_type(n, b"").claimed_type in {FileType.PE, FileType.SCRIPT}
        ]
        if executable_members:
            return [
                self.detection(
                    "Heuristic.Archive.EncryptedExecutable",
                    55.0,
                    "Password-protected archive containing executables. The "
                    "contents cannot be scanned, and this is the standard way "
                    "to slip a payload past a mail gateway.",
                    members=executable_members[:5],
                    encrypted_count=len(encrypted),
                )
            ]
        return [
            self.detection(
                "Info.Archive.Encrypted",
                10.0,
                "Password-protected archive; contents were not inspected.",
                encrypted_count=len(encrypted),
            )
        ]

    def _scan_members(
        self,
        parent: ScanTarget,
        members: Iterator[tuple[str, Path, Path]],
    ) -> list[Detection]:
        """Run the pipeline over extracted members and re-attribute the hits."""
        assert self._member_scanner is not None
        out: list[Detection] = []

        for member_name, extracted, _root in members:
            child = ScanTarget(
                path=extracted,
                depth=parent.depth + 1,
                container=parent.path,
                member_name=member_name,
            )
            try:
                detections = self._member_scanner(child)
            except Exception as exc:  # pragma: no cover - defensive
                self.log.debug("member scan failed for %s: %s", member_name, exc)
                continue
            finally:
                child.release()

            for detection in detections:
                # Rewrite so the user sees which member matched, not a
                # meaningless temp path.
                out.append(
                    Detection(
                        detector=f"{self.name}:{detection.detector}",
                        name=detection.name,
                        confidence=detection.confidence,
                        description=f"In archive member '{member_name}': "
                                    f"{detection.description}",
                        conclusive=detection.conclusive,
                        metadata={**detection.metadata, "member": member_name},
                    )
                )

            if any(d.conclusive for d in detections):
                # A definite hit inside is enough; stop burning CPU.
                break

        return out


# ----------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------

def _escapes(name: str) -> bool:
    """True if an archive member path would land outside the target directory."""
    if not name:
        return False
    normalised = name.replace("\\", "/")
    if normalised.startswith("/") or normalised.startswith("../"):
        return True
    if len(normalised) > 1 and normalised[1] == ":":  # C:\...
        return True
    return "/../" in normalised


def _safe_destination(root: Path, member_name: str) -> Path | None:
    """Resolve a member name under *root*, or None if it escapes.

    Belt and braces: :func:`_escapes` catches the obvious cases, and this
    resolves the final path to catch anything clever.
    """
    if _escapes(member_name):
        return None
    # Flatten to a name that cannot contain separators pointing upward, while
    # keeping enough of the original for the user to recognise.
    candidate = (root / member_name.replace("\\", "/")).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError:
        return None
    return candidate


def _bounded_copy(source: Any, destination: Any, limit: int) -> int:
    """Copy at most *limit* bytes; returns the number written.

    Used instead of :func:`shutil.copyfileobj` because a zip header's declared
    size cannot be trusted — the stream may be far longer than advertised.
    """
    written = 0
    chunk_size = min(1024 * 1024, limit)
    while written < limit:
        chunk = source.read(min(chunk_size, limit - written))
        if not chunk:
            break
        destination.write(chunk)
        written += len(chunk)
    return written
