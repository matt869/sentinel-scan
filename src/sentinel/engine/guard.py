"""The guard list: files this scanner will never move, whatever it thinks.

One failure mode ends a project like this. A signature turns out to be wrong,
it matches something the operating system needs, the file is quarantined, and
a stranger's computer does not boot. They cannot undo it — the machine that
would run the undo is the machine that will not start. No amount of detection
quality buys that back.

So the quarantine decision is gated twice. A detector deciding a file is bad
is *not* sufficient; the file must also not be on this list. The two checks
are independent on purpose, because the whole point is to survive the case
where the detection logic is wrong.

What is protected, and why exactly this much:

**Operating-system directories.** ``C:\\Windows`` and everything under it,
``/bin``, ``/lib``, ``/boot``, ``/System`` and their siblings. This is the
narrow list of places where losing one file stops the machine booting. It is
deliberately *not* "all of Program Files" — malware installs there routinely,
and blanket-protecting application space would blind the scanner to a whole
class of real threats to buy protection the OS directories already give.

**Sentinel's own install and data directories.** A scanner that quarantines
its own binary cannot restore anything, including its own binary. The data
directory holds the vault key; losing that makes every quarantined file
unrecoverable.

**The roots of filesystems, and paths that are not files.** Cheap to check,
and a symptom that something upstream has gone wrong.

**OS-vendor-signed binaries**, via :mod:`sentinel.system.authenticode`, for
vendor files living outside the directories above. That check is consulted
last because it costs a syscall; the path rules answer almost every case for
free.

A guarded file is still *reported*. The user is told what was found and
where — they are simply not offered a destructive action on it, and nothing
happens automatically. Detection is not the thing being suppressed here;
acting on it is.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from sentinel.core.logger import get_logger

log = get_logger(__name__)


class GuardReason(str, Enum):
    """Why a path may not be touched."""

    SYSTEM_PATH = "system-path"
    OWN_INSTALL = "own-install"
    OWN_DATA = "own-data"
    FILESYSTEM_ROOT = "filesystem-root"
    NOT_A_FILE = "not-a-file"
    VENDOR_SIGNED = "vendor-signed"


#: Plain-English explanation per reason. These reach the user, so they say
#: what was protected and why, not which rule fired.
_EXPLANATIONS = {
    GuardReason.SYSTEM_PATH: "it is part of the operating system",
    GuardReason.OWN_INSTALL: "it is part of Sentinel itself",
    GuardReason.OWN_DATA: "it is one of Sentinel's own working files",
    GuardReason.FILESYSTEM_ROOT: "it is the root of a drive",
    GuardReason.NOT_A_FILE: "it is not an ordinary file",
    GuardReason.VENDOR_SIGNED: "it is signed by the makers of your operating system",
}


@dataclass(frozen=True, slots=True)
class GuardHit:
    """A refusal to touch a path."""

    reason: GuardReason
    path: str
    #: The rule that matched — a protected root, a certificate subject.
    detail: str = ""

    def describe(self) -> str:
        """One line for the user. No jargon, no rule identifiers."""
        return (
            f"Sentinel will not move this file because "
            f"{_EXPLANATIONS[self.reason]}."
        )

    def __str__(self) -> str:
        return f"{self.reason.value}: {self.path}" + (
            f" ({self.detail})" if self.detail else ""
        )


class GuardError(RuntimeError):
    """Raised when an operation is refused because the path is guarded."""

    def __init__(self, hit: GuardHit) -> None:
        super().__init__(hit.describe())
        self.hit = hit


def _windows_system_roots() -> list[str]:
    """OS directories on Windows, from the environment rather than hardcoded.

    ``C:`` is only the usual answer, not the guaranteed one, and a machine
    that boots from ``D:`` deserves the same protection.
    """
    roots: list[str] = []
    for variable in ("SYSTEMROOT", "WINDIR"):
        value = os.environ.get(variable)
        if value:
            roots.append(value)

    system_drive = os.environ.get("SYSTEMDRIVE", "C:")
    roots += [
        # Boot files. Losing any of these is the unbootable-machine case.
        rf"{system_drive}\boot",
        rf"{system_drive}\EFI",
        rf"{system_drive}\Recovery",
        rf"{system_drive}\bootmgr",
        # The component store: every servicing operation reads from here.
        rf"{system_drive}\ProgramData\Microsoft\Windows\WER",
    ]
    if not roots:  # pragma: no cover - only when the environment is empty
        roots.append(r"C:\Windows")
    return roots


#: Directories where losing a single file can stop the machine booting or
#: leave it unable to repair itself. Application install space is *not* here.
_POSIX_SYSTEM_ROOTS = (
    "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32",
    "/usr/bin", "/usr/sbin", "/usr/lib", "/usr/lib32", "/usr/lib64",
    "/usr/libexec", "/boot", "/etc",
    # macOS. /System is sealed on modern releases, but older ones and
    # /Library/Apple are not.
    "/System", "/Library/Apple", "/usr/libexec", "/private/var/db",
)


class Guard:
    """Decides which paths must never be quarantined or deleted.

    Construct once and reuse: the protected-root list is resolved at
    construction, so each :meth:`check` is a handful of string comparisons.
    """

    def __init__(self, config: Any = None, *, check_signatures: bool = True) -> None:
        """
        Args:
            config: Configuration, used to locate the data directory. The
                guard degrades to path rules alone without one.
            check_signatures: Consult the OS signature check for files that
                pass the path rules. Costs a syscall per call, so it is only
                ever reached on the quarantine path, never during a scan.
        """
        self.config = config
        self.check_signatures = check_signatures
        self._roots: list[tuple[str, GuardReason]] = []

        for root in self._system_roots():
            self._add(root, GuardReason.SYSTEM_PATH)

        for root in self._own_install_dirs():
            self._add(root, GuardReason.OWN_INSTALL)

        data_dir = getattr(getattr(config, "paths", None), "data_dir", None)
        if data_dir:
            self._add(str(data_dir), GuardReason.OWN_DATA)

    # -- construction helpers ------------------------------------------

    @staticmethod
    def _system_roots() -> list[str]:
        if os.name == "nt":
            return _windows_system_roots()
        return list(_POSIX_SYSTEM_ROOTS)

    @staticmethod
    def _own_install_dirs() -> list[str]:
        """Where this copy of Sentinel lives.

        Two answers, both needed. Running from a source checkout or a wheel,
        it is the package directory. Frozen by PyInstaller, the package is
        inside the executable's directory and the interpreter is the app, so
        that whole directory is ours.
        """
        found: list[str] = []
        try:
            import sentinel

            package = Path(sentinel.__file__).resolve().parent
            found.append(str(package))
        except Exception as exc:  # pragma: no cover - import cannot fail here
            log.debug("cannot locate the sentinel package: %s", exc)

        if getattr(sys, "frozen", False):
            found.append(str(Path(sys.executable).resolve().parent))
        return found

    def _add(self, root: str, reason: GuardReason) -> None:
        normalised = _normalise(root)
        if normalised:
            self._roots.append((normalised, reason))

    # -- the check -----------------------------------------------------

    def check(self, path: str | os.PathLike[str]) -> GuardHit | None:
        """Return a :class:`GuardHit` if *path* must not be touched.

        Never raises. A path that cannot even be resolved is guarded rather
        than allowed — when the answer is unclear, the safe response to
        "may I destroy this?" is no.
        """
        try:
            candidate = Path(path).resolve()
        except (OSError, ValueError) as exc:
            log.warning("guarding %s: cannot resolve it (%s)", path, exc)
            return GuardHit(GuardReason.NOT_A_FILE, str(path), str(exc))

        text = _normalise(str(candidate))

        if candidate.parent == candidate:
            return GuardHit(GuardReason.FILESYSTEM_ROOT, str(candidate))

        for root, reason in self._roots:
            if _is_within(text, root):
                return GuardHit(reason, str(candidate), root)

        try:
            if candidate.exists() and not candidate.is_file():
                return GuardHit(GuardReason.NOT_A_FILE, str(candidate))
        except OSError:
            return GuardHit(GuardReason.NOT_A_FILE, str(candidate))

        if self.check_signatures:
            signer = self._vendor_signature(candidate)
            if signer:
                return GuardHit(GuardReason.VENDOR_SIGNED, str(candidate), signer)

        return None

    def is_protected(self, path: str | os.PathLike[str]) -> bool:
        return self.check(path) is not None

    def enforce(self, path: str | os.PathLike[str]) -> None:
        """Raise :class:`GuardError` if *path* is protected."""
        hit = self.check(path)
        if hit is not None:
            log.warning("refusing to touch %s — %s", path, hit)
            raise GuardError(hit)

    @staticmethod
    def _vendor_signature(path: Path) -> str:
        """Signer name if the OS vendor signed this file, else empty.

        Failure returns empty rather than raising: an unavailable signature
        check must fall back to the path rules, not disable quarantine
        altogether.
        """
        try:
            from sentinel.system.authenticode import os_vendor_signer

            return os_vendor_signer(path)
        except Exception as exc:
            log.debug("signature check unavailable for %s: %s", path, exc)
            return ""

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Guard {len(self._roots)} protected root(s)>"


def _normalise(path: str) -> str:
    """Absolute, case-folded on Windows, with a trailing separator stripped."""
    if not path:
        return ""
    try:
        text = os.path.abspath(os.path.expandvars(str(path)))
    except (OSError, ValueError):
        return ""
    if os.name == "nt":
        text = text.replace("/", "\\").casefold()
    return text.rstrip("\\/") or text


def _is_within(candidate: str, root: str) -> bool:
    """Whether *candidate* is *root* or sits underneath it.

    String comparison rather than ``Path.relative_to`` so that ``C:\\WindowsApps``
    is not treated as living inside ``C:\\Windows`` — the separator check is
    the entire point.
    """
    if candidate == root:
        return True
    return candidate.startswith(root + os.sep) or candidate.startswith(root + "/")
