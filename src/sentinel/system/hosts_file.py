"""Inspection of the system hosts file.

Hijacking ``/etc/hosts`` is a cheap, old and still-common trick: point a
bank's domain at an attacker's server, or blackhole antivirus update domains
so the machine stops receiving signatures.

This module reads and parses the file. It never edits it — a scanner that
silently rewrites system network configuration is worse than the problem.
Findings are reported with the exact line so the user can fix it themselves.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from sentinel.core.logger import get_logger

log = get_logger(__name__)

#: Loopback and null addresses. Redirecting a domain here blackholes it.
BLACKHOLE_ADDRESSES = frozenset({"127.0.0.1", "0.0.0.0", "::1", "::"})

#: Security vendors' update and telemetry domains. An entry blackholing one
#: of these is almost always malware disabling protection, not a user
#: blocking ads.
SECURITY_DOMAIN_MARKERS = (
    "sophos", "mcafee", "symantec", "norton", "kaspersky", "avast", "avg",
    "bitdefender", "eset", "trendmicro", "malwarebytes", "clamav",
    "windowsupdate", "update.microsoft", "defender", "msftncsi",
    "virustotal", "sentinel-scan", "crowdstrike", "sentinelone",
)

#: Domains whose redirection to a non-loopback address suggests phishing.
HIGH_VALUE_MARKERS = (
    "paypal", "bank", "chase", "wellsfargo", "hsbc", "barclays",
    "coinbase", "binance", "blockchain", "metamask",
    "google", "gmail", "outlook", "office365", "microsoftonline",
    "apple", "icloud", "amazon", "facebook", "instagram",
)

_LINE = re.compile(r"^\s*(\S+)\s+(.+?)\s*(?:#.*)?$")


@dataclass(slots=True)
class HostsEntry:
    """One mapping from the hosts file."""

    address: str
    hostnames: list[str]
    line_number: int
    raw: str

    @property
    def is_blackhole(self) -> bool:
        return self.address in BLACKHOLE_ADDRESSES


@dataclass(slots=True)
class HostsFinding:
    """Something noteworthy about a hosts entry."""

    severity: str  # high | medium | low | info
    message: str
    entry: HostsEntry

    def __str__(self) -> str:
        return f"[{self.severity}] line {self.entry.line_number}: {self.message}"


@dataclass(slots=True)
class HostsReport:
    """Result of inspecting the hosts file."""

    path: str
    exists: bool
    readable: bool
    entries: list[HostsEntry] = field(default_factory=list)
    findings: list[HostsFinding] = field(default_factory=list)
    error: str = ""

    @property
    def is_clean(self) -> bool:
        return not self.findings

    @property
    def custom_entry_count(self) -> int:
        """Entries beyond the default localhost mappings."""
        return sum(1 for e in self.entries if not _is_default(e))


def hosts_path() -> Path:
    """Location of the hosts file on this platform."""
    if os.name == "nt":
        # os.environ is case-insensitive on Windows, but the uppercase form
        # is the canonical one and keeps static analysis happy.
        root = os.environ.get("SYSTEMROOT", "C:\\Windows")
        return Path(root) / "System32" / "drivers" / "etc" / "hosts"
    return Path("/etc/hosts")


def read_hosts(path: str | os.PathLike[str] | None = None) -> HostsReport:
    """Parse the hosts file and flag anything suspicious."""
    target = Path(path) if path else hosts_path()

    if not target.exists():
        return HostsReport(str(target), exists=False, readable=False,
                           error="file does not exist")

    try:
        # The file is ASCII by convention but is not validated by the OS;
        # replace rather than raise on a stray byte.
        text = target.read_text(encoding="utf-8", errors="replace")
    except PermissionError:
        return HostsReport(
            str(target), exists=True, readable=False,
            error="permission denied — re-run elevated to inspect the hosts file",
        )
    except OSError as exc:
        return HostsReport(str(target), exists=True, readable=False, error=str(exc))

    entries = _parse(text)
    report = HostsReport(str(target), exists=True, readable=True, entries=entries)
    report.findings = _analyse(entries)
    return report


def _parse(text: str) -> list[HostsEntry]:
    entries: list[HostsEntry] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = _LINE.match(line)
        if not match:
            continue
        address, rest = match.group(1), match.group(2)
        hostnames = [h for h in rest.split() if h and not h.startswith("#")]
        if not hostnames:
            continue
        entries.append(HostsEntry(address, hostnames, number, raw.rstrip()))
    return entries


def _analyse(entries: list[HostsEntry]) -> list[HostsFinding]:
    findings: list[HostsFinding] = []

    for entry in entries:
        if _is_default(entry):
            continue

        lowered = [h.lower() for h in entry.hostnames]

        # Security vendor domains pointed at nowhere.
        if entry.is_blackhole:
            blocked = [
                h for h in lowered
                if any(marker in h for marker in SECURITY_DOMAIN_MARKERS)
            ]
            if blocked:
                findings.append(
                    HostsFinding(
                        "high",
                        f"Blocks security or update domains ({', '.join(blocked[:3])}). "
                        f"Malware does this to stop antivirus updating. If you did not "
                        f"add this line yourself, remove it.",
                        entry,
                    )
                )
                continue

        # A real address standing in for a high-value domain.
        if not entry.is_blackhole:
            impersonated = [
                h for h in lowered
                if any(marker in h for marker in HIGH_VALUE_MARKERS)
            ]
            if impersonated:
                findings.append(
                    HostsFinding(
                        "high",
                        f"Redirects {', '.join(impersonated[:3])} to {entry.address}. "
                        f"Anything you send to that domain goes to that address "
                        f"instead — this is how credential phishing is done locally.",
                        entry,
                    )
                )
                continue

            findings.append(
                HostsFinding(
                    "low",
                    f"Redirects {', '.join(lowered[:3])} to {entry.address}. "
                    f"Legitimate for local development; worth confirming you added it.",
                    entry,
                )
            )

    # A very large hosts file is usually an ad-blocking list, which is fine,
    # but worth mentioning because it also hides a malicious line in the noise.
    custom = [e for e in entries if not _is_default(e)]
    if len(custom) > 200:
        findings.append(
            HostsFinding(
                "info",
                f"{len(custom)} custom entries. This is normal for an ad-blocking "
                f"host list, but it is also an easy place to hide one bad line.",
                custom[0],
            )
        )

    return findings


def _is_default(entry: HostsEntry) -> bool:
    """True for the stock localhost mappings every system ships with."""
    if entry.address not in {"127.0.0.1", "::1", "255.255.255.255", "fe00::0",
                             "ff00::0", "ff02::1", "ff02::2", "ff02::3"}:
        return False
    defaults = {
        "localhost", "localhost.localdomain", "broadcasthost",
        "ip6-localhost", "ip6-loopback", "ip6-localnet", "ip6-mcastprefix",
        "ip6-allnodes", "ip6-allrouters", "ip6-allhosts",
    }
    return all(h.lower() in defaults or h.lower().startswith("localhost")
               for h in entry.hostnames)


def check() -> HostsReport:
    """Convenience wrapper used by ``sentinel system``."""
    report = read_hosts()
    if report.error:
        log.info("hosts file: %s", report.error)
    elif report.findings:
        log.warning("hosts file has %d noteworthy entries", len(report.findings))
    return report
