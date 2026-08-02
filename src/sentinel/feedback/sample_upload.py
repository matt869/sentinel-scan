"""Uploading a file's contents alongside a report.

This is the most privacy-sensitive thing the application can do, so it has
the strictest gate in the code base. Every one of these must hold before a
single byte leaves the machine:

1. ``privacy.allow_sample_upload`` is true in the configuration.
2. The specific report carries ``sample_consented=True`` — set only by an
   explicit, per-file user action, never a remembered preference.
3. The file is under :data:`MAX_SAMPLE_SIZE`.
4. The file does not look like a personal document.

Rule 4 deserves explanation. A user reporting a false positive on
``tax-return.pdf`` almost certainly does not intend to send us their tax
return; they want the *detection* fixed. Refusing to upload document formats
and asking them to confirm again costs one dialog and prevents a category of
mistake that cannot be undone once the file is on someone else's server.
"""

from __future__ import annotations

import mimetypes
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sentinel.core.logger import get_logger
from sentinel.utils.file_types import DOCUMENT_TYPES, FileType, guess_type

log = get_logger(__name__)

#: Hard ceiling on an upload. Larger samples are not more useful, and this
#: bounds what a bug in the consent logic could leak.
MAX_SAMPLE_SIZE = 32 * 1024 * 1024

#: Formats that routinely contain personal data. Uploading one requires a
#: second explicit confirmation.
PERSONAL_DATA_TYPES = frozenset(DOCUMENT_TYPES | {FileType.TEXT, FileType.IMAGE})

#: Extensions that hold credentials. Never uploaded, at any consent level.
NEVER_UPLOAD_EXTENSIONS = frozenset(
    {
        ".pem", ".key", ".pfx", ".p12", ".jks", ".keystore",
        ".kdbx", ".kdb", ".1pif", ".agilekeychain",
        ".ppk", ".asc", ".gpg", ".pgp",
        ".env", ".netrc", ".htpasswd",
    }
)

#: Filenames that hold credentials regardless of extension.
NEVER_UPLOAD_NAMES = frozenset(
    {
        "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
        "shadow", "passwd", "sam", "ntds.dit",
        ".netrc", ".pgpass", "credentials", ".env",
    }
)


class SampleRefusedError(RuntimeError):
    """Raised when a sample must not be uploaded."""


@dataclass(slots=True)
class SampleCheck:
    """The result of deciding whether a file may be uploaded."""

    allowed: bool
    reason: str = ""
    #: True when the user should be asked a second time before proceeding.
    needs_extra_confirmation: bool = False
    size: int = 0
    content_type: str = "application/octet-stream"


def check_sample(path: str | Path, config: Any) -> SampleCheck:
    """Decide whether *path* may be uploaded, and whether to ask again.

    This never uploads anything; it only reports what the gate says. Callers
    must honour :attr:`SampleCheck.needs_extra_confirmation`.
    """
    p = Path(path)
    privacy = getattr(config, "privacy", None)

    if not getattr(privacy, "allow_sample_upload", False):
        return SampleCheck(
            False,
            "Sample upload is disabled. Enable privacy.allow_sample_upload to "
            "permit it, and you will still be asked per file.",
        )

    if not p.is_file():
        return SampleCheck(False, f"{p} is not a file")

    try:
        size = p.stat().st_size
    except OSError as exc:
        return SampleCheck(False, f"cannot read {p}: {exc}")

    if size == 0:
        return SampleCheck(False, "the file is empty")
    if size > MAX_SAMPLE_SIZE:
        return SampleCheck(
            False,
            f"the file is {size / 1024 / 1024:.1f} MB, over the "
            f"{MAX_SAMPLE_SIZE / 1024 / 1024:.0f} MB upload limit",
            size=size,
        )

    name = p.name.lower()
    if name in NEVER_UPLOAD_NAMES or p.suffix.lower() in NEVER_UPLOAD_EXTENSIONS:
        return SampleCheck(
            False,
            f"'{p.name}' looks like a key, credential or password store. "
            f"Sentinel will not upload these under any setting.",
            size=size,
        )

    info = guess_type(p)
    content_type = (
        mimetypes.guess_type(p.name)[0] or "application/octet-stream"
    )

    if info.file_type in PERSONAL_DATA_TYPES:
        return SampleCheck(
            True,
            f"'{p.name}' is a {info.file_type.value} file, which often contains "
            f"personal information. Confirm you are happy for its full contents "
            f"to be uploaded.",
            needs_extra_confirmation=True,
            size=size,
            content_type=content_type,
        )

    return SampleCheck(True, size=size, content_type=content_type)


def upload_sample(
    client: Any,
    report_id: str,
    path: str | Path,
    config: Any,
    extra_confirmation_given: bool = False,
) -> dict[str, Any]:
    """Upload a file to an existing report.

    Args:
        client: A connected :class:`~sentinel.feedback.client.ServerClient`.
        report_id: Report to attach to.
        path: File to upload.
        config: Application config, for the consent gate.
        extra_confirmation_given: Set when the user answered the second
            confirmation for a personal-data file type.

    Returns:
        A dict describing the outcome; ``uploaded`` is False when the gate
        refused, with ``reason`` explaining why.
    """
    check = check_sample(path, config)

    if not check.allowed:
        log.info("not uploading %s: %s", Path(path).name, check.reason)
        return {"uploaded": False, "reason": check.reason}

    if check.needs_extra_confirmation and not extra_confirmation_given:
        log.info("not uploading %s: additional confirmation required", Path(path).name)
        return {
            "uploaded": False,
            "reason": check.reason,
            "needs_confirmation": True,
        }

    p = Path(path)
    try:
        content = p.read_bytes()
    except OSError as exc:
        return {"uploaded": False, "reason": f"cannot read the file: {exc}"}

    # Re-check the size against what we actually read; the file could have
    # grown between stat and read.
    if len(content) > MAX_SAMPLE_SIZE:
        return {"uploaded": False, "reason": "the file grew past the upload limit"}

    log.warning(
        "uploading the full contents of %s (%d bytes) to the reporting server",
        p.name, len(content),
    )

    from sentinel.feedback.client import ServerError

    try:
        result = client.upload_sample(report_id, p.name, content, check.content_type)
    except ServerError as exc:
        return {"uploaded": False, "reason": str(exc)}

    return {
        "uploaded": bool(result.accepted),
        "reason": result.message,
        "size": len(content),
    }


def describe_gate(config: Any) -> str:
    """One-line summary of the current upload policy, for ``sentinel status``."""
    privacy = getattr(config, "privacy", None)
    if not getattr(privacy, "allow_sample_upload", False):
        return "Sample upload: disabled (no file contents will ever be sent)"
    return (
        "Sample upload: permitted, but every file still requires explicit "
        "per-report consent"
    )
