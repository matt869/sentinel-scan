"""File type identification from magic bytes.

We deliberately do not trust file extensions: renaming ``payload.exe`` to
``invoice.pdf`` is the oldest trick there is. Every detector that cares about
format asks this module, which reads the leading bytes of the file.

This is a focused table, not a libmagic replacement — it covers the formats
the detectors actually branch on.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class FileType(str, Enum):
    """Coarse format classification used for detector dispatch."""

    PE = "pe"                  # Windows executable / DLL
    ELF = "elf"                # Linux executable
    MACHO = "macho"            # macOS executable
    ZIP = "zip"                # includes jar, apk, docx, xlsx, odt
    RAR = "rar"
    SEVENZIP = "7z"
    GZIP = "gzip"
    BZIP2 = "bzip2"
    XZ = "xz"
    TAR = "tar"
    CAB = "cab"
    PDF = "pdf"
    OLE = "ole"                # legacy Office (.doc/.xls) and MSI
    RTF = "rtf"
    SCRIPT = "script"          # shebang or known script text
    TEXT = "text"
    IMAGE = "image"
    AUDIO_VIDEO = "media"
    FONT = "font"
    UNKNOWN = "unknown"
    EMPTY = "empty"


#: Formats that can carry executable code directly.
EXECUTABLE_TYPES = frozenset(
    {FileType.PE, FileType.ELF, FileType.MACHO, FileType.SCRIPT}
)

#: Formats the archive detector knows how to open.
ARCHIVE_TYPES = frozenset(
    {
        FileType.ZIP,
        FileType.RAR,
        FileType.SEVENZIP,
        FileType.GZIP,
        FileType.BZIP2,
        FileType.XZ,
        FileType.TAR,
        FileType.CAB,
    }
)

#: Formats that commonly embed macros or active content.
DOCUMENT_TYPES = frozenset({FileType.PDF, FileType.OLE, FileType.RTF})

#: Extensions treated as scripts when the content is text. Kept lowercase.
SCRIPT_EXTENSIONS = frozenset(
    {
        ".ps1", ".psm1", ".psd1",
        ".bat", ".cmd",
        ".vbs", ".vbe", ".wsf", ".wsh", ".hta",
        ".js", ".jse", ".mjs",
        ".sh", ".bash", ".zsh",
        ".py", ".pyw",
        ".pl", ".rb", ".php",
        ".lnk", ".scf",
    }
)

#: Extensions that claim to be documents. Used to spot masquerading files.
DECEPTIVE_EXTENSIONS = frozenset(
    {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".txt", ".jpg", ".jpeg", ".png", ".gif"}
)

# (offset, magic, type). Order matters: longer/more specific signatures first.
_MAGIC_TABLE: tuple[tuple[int, bytes, FileType], ...] = (
    (0, b"MZ", FileType.PE),
    (0, b"\x7fELF", FileType.ELF),
    (0, b"\xfe\xed\xfa\xce", FileType.MACHO),
    (0, b"\xfe\xed\xfa\xcf", FileType.MACHO),
    (0, b"\xce\xfa\xed\xfe", FileType.MACHO),
    (0, b"\xcf\xfa\xed\xfe", FileType.MACHO),
    (0, b"\xca\xfe\xba\xbe", FileType.MACHO),  # universal binary
    (0, b"PK\x03\x04", FileType.ZIP),
    (0, b"PK\x05\x06", FileType.ZIP),          # empty archive
    (0, b"PK\x07\x08", FileType.ZIP),          # spanned archive
    (0, b"Rar!\x1a\x07", FileType.RAR),
    (0, b"7z\xbc\xaf\x27\x1c", FileType.SEVENZIP),
    (0, b"\x1f\x8b", FileType.GZIP),
    (0, b"BZh", FileType.BZIP2),
    (0, b"\xfd7zXZ\x00", FileType.XZ),
    (0, b"MSCF", FileType.CAB),
    (0, b"%PDF-", FileType.PDF),
    (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", FileType.OLE),
    (0, b"{\\rt", FileType.RTF),
    (0, b"\x89PNG\r\n\x1a\n", FileType.IMAGE),
    (0, b"\xff\xd8\xff", FileType.IMAGE),
    (0, b"GIF87a", FileType.IMAGE),
    (0, b"GIF89a", FileType.IMAGE),
    (0, b"BM", FileType.IMAGE),
    (0, b"\x00\x01\x00\x00\x00", FileType.FONT),
    (0, b"OTTO", FileType.FONT),
    (0, b"ID3", FileType.AUDIO_VIDEO),
    (0, b"OggS", FileType.AUDIO_VIDEO),
    (0, b"\x1aE\xdf\xa3", FileType.AUDIO_VIDEO),  # matroska / webm
    (257, b"ustar", FileType.TAR),
    (4, b"ftyp", FileType.AUDIO_VIDEO),           # mp4 family
    (8, b"WEBP", FileType.IMAGE),
    (8, b"WAVE", FileType.AUDIO_VIDEO),
    (8, b"AVI ", FileType.AUDIO_VIDEO),
)

#: Bytes read from the head of a file to identify it. Must exceed the largest
#: offset in the magic table plus the longest signature.
HEADER_SIZE = 512


@dataclass(frozen=True, slots=True)
class TypeInfo:
    """Result of identifying a file."""

    file_type: FileType
    #: Type implied by the extension alone, for comparison.
    claimed_type: FileType
    extension: str

    @property
    def is_masquerading(self) -> bool:
        """True when an executable wears a document or image extension.

        Catches ``invoice.pdf`` that is really a PE binary. Note that a ZIP
        wearing ``.docx`` is normal, so container formats are excluded.
        """
        if self.file_type not in EXECUTABLE_TYPES:
            return False
        return self.extension in DECEPTIVE_EXTENSIONS

    @property
    def has_double_extension(self) -> bool:
        """Placeholder kept for symmetry; see :func:`has_double_extension`."""
        return False


def sniff_magic(header: bytes) -> FileType:
    """Classify a file from its leading bytes.

    Args:
        header: At least :data:`HEADER_SIZE` bytes from the start of the file
            (fewer is fine — signatures past the end simply do not match).
    """
    if not header:
        return FileType.EMPTY

    for offset, magic, file_type in _MAGIC_TABLE:
        if header[offset : offset + len(magic)] == magic:
            return file_type

    if header.startswith(b"#!"):
        return FileType.SCRIPT
    if _looks_like_text(header):
        return FileType.TEXT
    return FileType.UNKNOWN


def _looks_like_text(data: bytes) -> bool:
    """Heuristic: mostly printable, no NUL bytes.

    UTF-16 text is full of NULs and would fail this, so the BOMs are checked
    explicitly first.
    """
    if data.startswith((b"\xff\xfe", b"\xfe\xff", b"\xef\xbb\xbf")):
        return True
    if b"\x00" in data:
        return False
    printable = sum(1 for b in data if 0x20 <= b < 0x7F or b in (0x09, 0x0A, 0x0D))
    return printable / len(data) > 0.90


def read_header(path: str | os.PathLike[str], size: int = HEADER_SIZE) -> bytes:
    """Read the leading bytes of a file, returning b"" on any I/O error."""
    try:
        with open(path, "rb", buffering=0) as fh:
            return fh.read(size)
    except OSError:
        return b""


def type_from_extension(extension: str) -> FileType:
    """Map a lowercase extension (with dot) to the type it advertises."""
    ext = extension.lower()
    if ext in SCRIPT_EXTENSIONS:
        return FileType.SCRIPT
    return {
        ".exe": FileType.PE, ".dll": FileType.PE, ".sys": FileType.PE,
        ".scr": FileType.PE, ".ocx": FileType.PE, ".cpl": FileType.PE,
        ".zip": FileType.ZIP, ".jar": FileType.ZIP, ".apk": FileType.ZIP,
        ".docx": FileType.ZIP, ".xlsx": FileType.ZIP, ".pptx": FileType.ZIP,
        ".rar": FileType.RAR, ".7z": FileType.SEVENZIP,
        ".gz": FileType.GZIP, ".tgz": FileType.GZIP,
        ".bz2": FileType.BZIP2, ".xz": FileType.XZ, ".tar": FileType.TAR,
        ".cab": FileType.CAB, ".msi": FileType.OLE,
        ".doc": FileType.OLE, ".xls": FileType.OLE, ".ppt": FileType.OLE,
        ".pdf": FileType.PDF, ".rtf": FileType.RTF,
        ".png": FileType.IMAGE, ".jpg": FileType.IMAGE, ".jpeg": FileType.IMAGE,
        ".gif": FileType.IMAGE, ".bmp": FileType.IMAGE, ".webp": FileType.IMAGE,
        ".mp3": FileType.AUDIO_VIDEO, ".mp4": FileType.AUDIO_VIDEO,
        ".txt": FileType.TEXT, ".log": FileType.TEXT, ".md": FileType.TEXT,
    }.get(ext, FileType.UNKNOWN)


def guess_type(path: str | os.PathLike[str], header: bytes | None = None) -> TypeInfo:
    """Identify *path*, reading its header if not supplied.

    The extension is recorded alongside the real type so callers can flag a
    mismatch without a second stat.
    """
    p = Path(path)
    if header is None:
        header = read_header(p)

    real = sniff_magic(header)
    extension = p.suffix.lower()

    # A text file with a script extension is a script, not plain text.
    if real is FileType.TEXT and extension in SCRIPT_EXTENSIONS:
        real = FileType.SCRIPT

    return TypeInfo(file_type=real, claimed_type=type_from_extension(extension),
                    extension=extension)


def is_executable_type(file_type: FileType) -> bool:
    """True if the format can carry directly executable code."""
    return file_type in EXECUTABLE_TYPES


def is_archive_type(file_type: FileType) -> bool:
    """True if the archive detector can open this format."""
    return file_type in ARCHIVE_TYPES


def has_double_extension(path: str | os.PathLike[str]) -> str | None:
    """Return the deceptive inner extension for names like ``report.pdf.exe``.

    Returns None when the name is unremarkable. Only flags the case where the
    *inner* extension advertises a document and the *outer* one is executable
    — ``archive.tar.gz`` and ``script.min.js`` must not trip this.
    """
    name = Path(path).name.lower()
    parts = name.split(".")
    if len(parts) < 3:
        return None

    outer = "." + parts[-1]
    inner = "." + parts[-2]
    outer_type = type_from_extension(outer)
    if outer_type in EXECUTABLE_TYPES and inner in DECEPTIVE_EXTENSIONS:
        return inner
    return None
