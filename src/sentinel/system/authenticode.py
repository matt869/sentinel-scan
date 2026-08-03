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
    except Exception as exc:
        log.debug("signature check failed for %s: %s", path, exc)
    return ""


def _is_macos() -> bool:
    import sys

    return sys.platform == "darwin"


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
    return ""
