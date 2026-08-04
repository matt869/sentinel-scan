"""Asking the operating system who signed a file.

Used by :mod:`sentinel.engine.guard` for one narrow question: did the makers
of this operating system sign this binary? A Microsoft-signed DLL sitting
outside ``C:\\Windows`` is still something we must not quarantine, and the
path rules cannot see it.

Only the OS vendor counts. "Signed by somebody" is not a safety property —
malware is signed with stolen certificates often enough that treating any
valid signature as protection would hand attackers an opt-out from the
scanner. The publisher name is checked, not merely the trust result.

Everything here fails closed *towards scanning*: any error, any unsupported
platform, any missing API returns "not vendor signed", so the guard falls
back to its path rules. The failure we refuse to allow is the opposite one —
concluding a file is protected when we could not actually verify it.
"""

from __future__ import annotations

import os
from pathlib import Path

from sentinel.core.logger import get_logger

log = get_logger(__name__)

#: Subject substrings that identify the OS vendor. Matched case-insensitively
#: against the signing certificate's subject name.
_WINDOWS_VENDOR_MARKERS = (
    "microsoft corporation",
    "microsoft windows",
    "microsoft root",
)

_MACOS_VENDOR_MARKERS = (
    "software signing",
    "apple code signing",
    "apple inc.",
)

#: WinVerifyTrust returns 0 when the signature is valid and trusted.
_TRUST_OK = 0


def os_vendor_signer(path: str | os.PathLike[str]) -> str:
    """Return the signer name if the OS vendor signed *path*, else ``""``.

    Never raises.
    """
    try:
        if os.name == "nt":
            return _windows_vendor_signer(Path(path))
        if _is_macos():
            return _macos_vendor_signer(Path(path))
        if _is_linux():
            return _linux_vendor_signer(Path(path))
    except Exception as exc:
        log.debug("signature check failed for %s: %s", path, exc)
    return ""


def _is_macos() -> bool:
    import sys

    return sys.platform == "darwin"


def _is_linux() -> bool:
    import sys

    return sys.platform.startswith("linux")


# ----------------------------------------------------------------------
# Windows
# ----------------------------------------------------------------------

def _windows_vendor_signer(path: Path) -> str:
    """Verify the Authenticode signature and read its publisher.

    Two steps, and both must pass. ``WinVerifyTrust`` says the signature is
    intact and chains to a trusted root; ``CryptQueryObject`` plus
    ``CertGetNameString`` say *who* signed it. Trust alone is not enough —
    plenty of trusted certificates are not Microsoft's.
    """
    if not path.is_file():
        return ""

    if not _win_verify_trust(str(path)):
        return ""

    subject = _win_certificate_subject(str(path))
    if not subject:
        return ""

    lowered = subject.casefold()
    if any(marker in lowered for marker in _WINDOWS_VENDOR_MARKERS):
        return subject
    return ""


def _win_verify_trust(path: str) -> bool:
    """WinVerifyTrust against the generic-verify action. True when trusted."""
    import ctypes
    from ctypes import wintypes

    class GUID(ctypes.Structure):
        _fields_ = [
            ("Data1", wintypes.DWORD),
            ("Data2", wintypes.WORD),
            ("Data3", wintypes.WORD),
            ("Data4", ctypes.c_byte * 8),
        ]

    class WINTRUST_FILE_INFO(ctypes.Structure):
        _fields_ = [
            ("cbStruct", wintypes.DWORD),
            ("pcwszFilePath", wintypes.LPCWSTR),
            ("hFile", wintypes.HANDLE),
            ("pgKnownSubject", ctypes.c_void_p),
        ]

    class WINTRUST_DATA(ctypes.Structure):
        _fields_ = [
            ("cbStruct", wintypes.DWORD),
            ("pPolicyCallbackData", ctypes.c_void_p),
            ("pSIPClientData", ctypes.c_void_p),
            ("dwUIChoice", wintypes.DWORD),
            ("fdwRevocationChecks", wintypes.DWORD),
            ("dwUnionChoice", wintypes.DWORD),
            ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)),
            ("dwStateAction", wintypes.DWORD),
            ("hWVTStateData", wintypes.HANDLE),
            ("pwszURLReference", wintypes.LPCWSTR),
            ("dwProvFlags", wintypes.DWORD),
            ("dwUIContext", wintypes.DWORD),
            ("pSignatureSettings", ctypes.c_void_p),
        ]

    # WINTRUST_ACTION_GENERIC_VERIFY_V2
    action = GUID(
        0x00AAC56B, 0xCD44, 0x11D0,
        (ctypes.c_byte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE),
    )

    file_info = WINTRUST_FILE_INFO(
        cbStruct=ctypes.sizeof(WINTRUST_FILE_INFO),
        pcwszFilePath=path,
        hFile=None,
        pgKnownSubject=None,
    )

    data = WINTRUST_DATA()
    ctypes.memset(ctypes.byref(data), 0, ctypes.sizeof(data))
    data.cbStruct = ctypes.sizeof(WINTRUST_DATA)
    data.dwUIChoice = 2           # WTD_UI_NONE — never show a dialog
    data.fdwRevocationChecks = 0  # WTD_REVOKE_NONE: no network on this path
    data.dwUnionChoice = 1        # WTD_CHOICE_FILE
    data.pFile = ctypes.pointer(file_info)
    data.dwStateAction = 1        # WTD_STATEACTION_VERIFY
    data.dwProvFlags = 0x1000     # WTD_CACHE_ONLY_URL_RETRIEVAL

    wintrust = ctypes.WinDLL("wintrust.dll")
    wintrust.WinVerifyTrust.restype = wintypes.LONG

    result = wintrust.WinVerifyTrust(None, ctypes.byref(action), ctypes.byref(data))

    # Always release the state handle, whatever the verdict.
    data.dwStateAction = 2        # WTD_STATEACTION_CLOSE
    wintrust.WinVerifyTrust(None, ctypes.byref(action), ctypes.byref(data))

    return result == _TRUST_OK


def _win_certificate_subject(path: str) -> str:
    """Subject name of the certificate that signed *path*, or ``""``."""
    import ctypes
    from ctypes import wintypes

    crypt32 = ctypes.WinDLL("crypt32.dll")

    CERT_QUERY_OBJECT_FILE = 1
    CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED = 1 << 10
    CERT_QUERY_FORMAT_FLAG_BINARY = 1 << 1
    CMSG_SIGNER_INFO_PARAM = 6
    CERT_NAME_SIMPLE_DISPLAY_TYPE = 4
    X509_ASN_ENCODING = 0x00000001
    PKCS_7_ASN_ENCODING = 0x00010000
    ENCODING = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING

    class CRYPTOAPI_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD),
                    ("pbData", ctypes.POINTER(ctypes.c_byte))]

    class CRYPT_ALGORITHM_IDENTIFIER(ctypes.Structure):
        _fields_ = [("pszObjId", ctypes.c_char_p),
                    ("Parameters", CRYPTOAPI_BLOB)]

    # Field order matters and is not obvious: CERT_INFO puts SerialNumber
    # and SignatureAlgorithm *before* Issuer. Omitting SignatureAlgorithm
    # silently shifts Issuer to the wrong offset, the certificate is never
    # found, and every file looks unsigned.
    class CERT_INFO(ctypes.Structure):
        _fields_ = [
            ("dwVersion", wintypes.DWORD),
            ("SerialNumber", CRYPTOAPI_BLOB),
            ("SignatureAlgorithm", CRYPT_ALGORITHM_IDENTIFIER),
            ("Issuer", CRYPTOAPI_BLOB),
        ]

    class CMSG_SIGNER_INFO(ctypes.Structure):
        _fields_ = [
            ("dwVersion", wintypes.DWORD),
            ("Issuer", CRYPTOAPI_BLOB),
            ("SerialNumber", CRYPTOAPI_BLOB),
        ]

    crypt32.CryptQueryObject.restype = wintypes.BOOL
    crypt32.CryptQueryObject.argtypes = [
        wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
        wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_void_p,
    ]
    crypt32.CryptMsgGetParam.restype = wintypes.BOOL
    crypt32.CryptMsgGetParam.argtypes = [
        ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
        ctypes.POINTER(wintypes.DWORD),
    ]
    crypt32.CertFindCertificateInStore.restype = ctypes.c_void_p
    crypt32.CertFindCertificateInStore.argtypes = [
        ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
        ctypes.c_void_p, ctypes.c_void_p,
    ]

    store = ctypes.c_void_p()
    message = ctypes.c_void_p()

    ok = crypt32.CryptQueryObject(
        CERT_QUERY_OBJECT_FILE,
        ctypes.cast(ctypes.c_wchar_p(path), ctypes.c_void_p),
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
        CERT_QUERY_FORMAT_FLAG_BINARY,
        0,
        None, None, None,
        ctypes.byref(store),
        ctypes.byref(message),
        None,
    )
    if not ok:
        return ""

    try:
        size = wintypes.DWORD()
        if not crypt32.CryptMsgGetParam(
            message, CMSG_SIGNER_INFO_PARAM, 0, None, ctypes.byref(size)
        ):
            return ""

        buffer = ctypes.create_string_buffer(size.value)
        if not crypt32.CryptMsgGetParam(
            message, CMSG_SIGNER_INFO_PARAM, 0, buffer, ctypes.byref(size)
        ):
            return ""

        signer = ctypes.cast(buffer, ctypes.POINTER(CMSG_SIGNER_INFO)).contents

        info = CERT_INFO()
        info.Issuer = signer.Issuer
        info.SerialNumber = signer.SerialNumber

        CERT_FIND_SUBJECT_CERT = 0x000B0000
        context = crypt32.CertFindCertificateInStore(
            store, ENCODING, 0, CERT_FIND_SUBJECT_CERT, ctypes.byref(info), None
        )
        if not context:
            return ""

        try:
            crypt32.CertGetNameStringW.restype = wintypes.DWORD
            length = crypt32.CertGetNameStringW(
                ctypes.c_void_p(context), CERT_NAME_SIMPLE_DISPLAY_TYPE,
                0, None, None, 0,
            )
            if length <= 1:
                return ""
            name = ctypes.create_unicode_buffer(length)
            crypt32.CertGetNameStringW(
                ctypes.c_void_p(context), CERT_NAME_SIMPLE_DISPLAY_TYPE,
                0, None, name, length,
            )
            return name.value
        finally:
            crypt32.CertFreeCertificateContext(ctypes.c_void_p(context))
    finally:
        if message:
            crypt32.CryptMsgClose(message)
        if store:
            crypt32.CertCloseStore(store, 0)


# ----------------------------------------------------------------------
# macOS
# ----------------------------------------------------------------------

def _macos_vendor_signer(path: Path) -> str:
    """Ask ``codesign`` who signed *path*.

    Shelling out is acceptable here only because this runs on the quarantine
    path — a handful of times per scan at most, never per file.
    """
    import subprocess

    try:
        completed = subprocess.run(
            ["/usr/bin/codesign", "-dv", "--verbose=2", str(path)],
            capture_output=True, text=True, timeout=10, check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        log.debug("codesign unavailable for %s: %s", path, exc)
        return ""

    # codesign writes its report to stderr.
    for line in completed.stderr.splitlines():
        if line.startswith("Authority="):
            authority = line.split("=", 1)[1].strip()
            if any(m in authority.casefold() for m in _MACOS_VENDOR_MARKERS):
                return authority

    return _macos_system_integrity(path)


#: Paths macOS reserves for itself. ``/usr/local`` is deliberately absent:
#: that is where Homebrew and hand-installed software live, and it is exactly
#: the space we still want heuristics looking at.
_MACOS_SYSTEM_PREFIXES: tuple[str, ...] = (
    "/System/", "/usr/bin/", "/usr/sbin/", "/usr/lib/", "/usr/libexec/",
    "/bin/", "/sbin/",
)

#: ``SF_RESTRICTED``. Set by the installer on everything System Integrity
#: Protection covers, and not clearable while SIP is on — not even by root.
_SF_RESTRICTED = 0x00080000


def _macos_system_integrity(path: Path) -> str:
    """Fall back to asking whether macOS itself owns this file.

    ``codesign`` answers for Mach-O binaries and frameworks. It does not
    answer for the shell and Perl scripts that also live in ``/usr/bin`` —
    those are not individually signed, they are protected by System
    Integrity Protection instead. Without this fallback every one of them
    looks unsigned, so the heuristics that fire on any script that decodes
    base64 or evaluates a variable fire on Apple's own tooling.

    ``SF_RESTRICTED`` is the stronger signal and the one to prefer: while
    SIP is on, a file carrying it cannot be modified by root. Where the flag
    is unavailable — SIP disabled, or a filesystem that does not carry BSD
    flags, which is the case on some CI images — the fallback is the same
    test the Linux path makes: under a system prefix, owned by root, and not
    writable by anyone else.
    """
    resolved = path.resolve()
    if not str(resolved).startswith(_MACOS_SYSTEM_PREFIXES):
        return ""

    try:
        info = resolved.stat()
    except OSError:
        return ""

    if getattr(info, "st_flags", 0) & _SF_RESTRICTED:
        return "macOS System Integrity Protection"

    if info.st_uid == 0 and not info.st_mode & 0o022:
        return "the macOS system directories"
    return ""


# ----------------------------------------------------------------------
# Linux
# ----------------------------------------------------------------------
#
# Linux has no Authenticode. Distribution binaries are not signed in the
# file; they are vouched for by the package manager that installed them. So
# the equivalent question — "did the operating system vendor put this here?"
# — is answered by asking whether a package owns the path.
#
# That is a genuinely weaker guarantee than a signature and the difference
# matters. Authenticode signs the *bytes*; dpkg and rpm record the *path*.
# An attacker who overwrites /usr/bin/apt-key leaves dpkg still claiming the
# file, so package ownership alone would launder whatever they put there.
#
# Which is why ownership alone is not enough here. The file must also live
# under a system prefix, be owned by root, and not be writable by anyone
# else — so rewriting it requires root, and an attacker who already has root
# is not being held back by a heuristic on a shell script.

#: Where distribution-managed executables live. Deliberately excludes /opt
#: and /usr/local, which are for software the distribution did not ship.
_LINUX_SYSTEM_PREFIXES: tuple[str, ...] = (
    "/bin/", "/sbin/", "/lib/", "/lib64/",
    "/usr/bin/", "/usr/sbin/", "/usr/lib/", "/usr/lib64/", "/usr/libexec/",
    "/usr/share/",
)

#: Resolved once. Probing the filesystem for a package manager on every
#: reported finding would be a syscall per file for an answer that cannot
#: change while the process is running.
_package_query: list[str] | None = None


def _linux_package_query() -> list[str]:
    """The argv prefix that maps a path to its owning package, or []."""
    global _package_query
    if _package_query is None:
        for candidate in (
            ["/usr/bin/dpkg-query", "-S"],
            ["/usr/bin/dpkg", "-S"],
            ["/usr/bin/rpm", "-qf"],
            ["/bin/rpm", "-qf"],
        ):
            if os.path.exists(candidate[0]):
                _package_query = candidate
                break
        else:
            _package_query = []
    return _package_query


def _linux_vendor_signer(path: Path) -> str:
    """Return the owning distribution package, or ``""``.

    Never raises.
    """
    resolved = path.resolve()
    text = str(resolved)
    if not text.startswith(_LINUX_SYSTEM_PREFIXES):
        return ""

    try:
        info = resolved.stat()
    except OSError:
        return ""

    # Root-owned and not writable by group or other. See the note above:
    # this is what turns "a package claims this path" into "only root could
    # have put these bytes here".
    if info.st_uid != 0 or info.st_mode & 0o022:
        return ""

    query = _linux_package_query()
    if not query:
        return ""

    import subprocess

    try:
        completed = subprocess.run(
            [*query, text],
            capture_output=True, text=True, timeout=10, check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        log.debug("package lookup unavailable for %s: %s", path, exc)
        return ""

    if completed.returncode != 0:
        return ""

    answer = completed.stdout.strip()
    if not answer:
        return ""

    # dpkg answers "apt: /usr/bin/apt-key"; rpm answers "apt-2.4.11-1".
    package = answer.splitlines()[0]
    if ":" in package:
        package = package.split(":", 1)[0]
    package = package.strip()

    # "diversion by ..." is dpkg telling us the path was redirected rather
    # than naming an owner.
    if not package or package.startswith("diversion"):
        return ""
    return f"the {package} package"
