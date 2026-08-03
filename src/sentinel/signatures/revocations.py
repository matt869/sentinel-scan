"""Remote rule revocation — the kill switch.

A bad signature is worse than a missing one. A rule that fires on a legitimate
DLL quarantines something the user needs, on a machine we cannot reach, and
the fix normally has to wait for the next signature version to be built,
published, and pulled. Users who never run an update never get it at all.

``revoked_rules.json`` is a small file fetched independently of the signature
manifest and refreshed on every update check rather than every version bump.
Detections naming a revoked rule are dropped before they reach the aggregator,
so a rule that turns out to be wrong stops firing within hours instead of
never.

Two properties this deliberately has:

**Revocations only ever remove detections.** The worst a hostile or corrupt
list can do is make the scanner miss things — it can never cause a file to be
quarantined. That is why the file is fetched over HTTPS with no manifest
checksum: anyone who can serve a malicious revocation list can already serve
empty signature bundles, so this hands an attacker no reach they lacked.

**It fails open.** A missing, unreachable, or malformed list leaves every rule
active. A kill switch that disables the scanner when it breaks is a worse bug
than the one it exists to fix.

File format::

    {
      "version": 3,
      "updated": "2026-08-03T00:00:00Z",
      "revoked": [
        {
          "rule": "Suspicious_PowerShell_Base64",
          "detector": "yara",
          "reason": "fires on the Windows Update maintenance scripts",
          "expires": "2026-09-01"
        }
      ]
    }

``detector`` scopes the revocation to one detector; omit it to revoke the
identifier wherever it appears. ``expires`` lets a revocation lapse on its own
once the rule has been fixed — omit it for a permanent one. A bare list of
strings is also accepted, since most revocations need nothing but a name.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Any

from sentinel.core.logger import get_logger
from sentinel.engine.verdict import Detection

log = get_logger(__name__)

#: Name of the revocation file, both on the mirror and on disk.
REVOCATION_FILENAME = "revoked_rules.json"

#: Hard cap on how many rules one list may revoke. A list that suddenly wants
#: to disable a hundred thousand rules is a mistake or an attack, not a
#: correction, and silently switching off the whole scanner is exactly the
#: failure this file exists to prevent. Over the cap the list is rejected
#: outright and every rule stays active.
MAX_REVOCATIONS = 10_000

#: Detection metadata keys that can carry a rule identifier, in addition to
#: the detection's own name. YARA records the rule it matched here.
_IDENTIFIER_KEYS = ("rule", "signature", "heuristic", "id")


@dataclass(frozen=True, slots=True)
class Revocation:
    """One disabled rule."""

    #: Rule identifier, lowercased. Matched against the detection name and
    #: any identifier in its metadata.
    rule: str
    #: Detector this applies to, lowercased. Empty means every detector.
    detector: str = ""
    #: Why it was revoked. Shown in logs; never shown to the end user.
    reason: str = ""
    #: ISO-8601 date after which the revocation lapses. Empty is permanent.
    expires: str = ""

    def active_on(self, today: date) -> bool:
        """Whether this revocation still applies on *today*."""
        if not self.expires:
            return True
        try:
            return date.fromisoformat(self.expires[:10]) >= today
        except ValueError:
            # An unparseable expiry keeps the revocation in force. The rule
            # was disabled for a reason and a typo in a date is not evidence
            # that the reason went away.
            log.debug("revocation for %s has an unreadable expiry %r",
                      self.rule, self.expires)
            return True

    def matches(self, detection: Detection) -> bool:
        """Whether *detection* names this revoked rule."""
        if self.detector and self.detector != detection.detector.lower():
            return False
        return self.rule in _identifiers(detection)


class RevocationList:
    """The set of rules that must not fire.

    Immutable once built and safe to share across worker threads: lookups are
    dictionary reads and nothing mutates after construction.
    """

    def __init__(
        self,
        revocations: Iterable[Revocation] = (),
        *,
        version: str = "",
        updated: str = "",
        today: date | None = None,
    ) -> None:
        self.version = version
        self.updated = updated
        self._by_rule: dict[str, list[Revocation]] = {}

        reference = today or datetime.now().date()
        for revocation in revocations:
            if not revocation.active_on(reference):
                log.debug("revocation for %s expired on %s; rule is live again",
                          revocation.rule, revocation.expires)
                continue
            self._by_rule.setdefault(revocation.rule, []).append(revocation)

    # -- construction --------------------------------------------------

    @classmethod
    def empty(cls) -> RevocationList:
        """A list that revokes nothing. The fail-open default."""
        return cls()

    @classmethod
    def from_dict(cls, data: Any, *, today: date | None = None) -> RevocationList:
        """Build from parsed JSON, dropping entries that do not make sense.

        Never raises: a malformed list yields an empty one, because failing
        open is the whole design.
        """
        if isinstance(data, list):
            data = {"revoked": data}
        if not isinstance(data, dict):
            log.warning("revocation list is not a JSON object; ignoring it")
            return cls.empty()

        raw = data.get("revoked", data.get("rules", []))
        if not isinstance(raw, list):
            log.warning("revocation list 'revoked' is not an array; ignoring it")
            return cls.empty()

        if len(raw) > MAX_REVOCATIONS:
            log.error(
                "revocation list holds %d entries, over the %d cap; ignoring it "
                "entirely and keeping every rule active",
                len(raw), MAX_REVOCATIONS,
            )
            return cls.empty()

        parsed: list[Revocation] = []
        for entry in raw:
            revocation = _parse_entry(entry)
            if revocation is not None:
                parsed.append(revocation)

        return cls(
            parsed,
            version=str(data.get("version", "")),
            updated=str(data.get("updated", "")),
            today=today,
        )

    @classmethod
    def load(cls, config: Any = None) -> RevocationList:
        """Load the installed list for *config*, or an empty one.

        Honours ``updates.honor_revocations``. Any failure — no file, bad
        JSON, unreadable directory — logs and returns an empty list.
        """
        updates = getattr(config, "updates", None)
        if updates is not None and not getattr(updates, "honor_revocations", True):
            log.info("rule revocations are disabled in the configuration")
            return cls.empty()

        from sentinel.signatures.loader import SignatureStore

        path = SignatureStore(config).revocations_path
        if path is None:
            return cls.empty()
        return cls.from_file(path)

    @classmethod
    def from_file(cls, path: str | Path) -> RevocationList:
        """Read and parse one revocation file, failing open."""
        try:
            with open(path, encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            log.warning("cannot read the revocation list at %s: %s", path, exc)
            return cls.empty()

        revocations = cls.from_dict(data)
        if revocations:
            log.info("%d rule(s) revoked by %s", len(revocations), path)
        return revocations

    # -- queries -------------------------------------------------------

    def find(self, detection: Detection) -> Revocation | None:
        """Return the revocation covering *detection*, if any."""
        for identifier in _identifiers(detection):
            for revocation in self._by_rule.get(identifier, ()):
                if revocation.matches(detection):
                    return revocation
        return None

    def is_revoked(self, detection: Detection) -> bool:
        return self.find(detection) is not None

    def filter(self, detections: Sequence[Detection]) -> list[Detection]:
        """Drop every revoked detection, keeping the rest in order."""
        if not self._by_rule or not detections:
            return list(detections)

        kept: list[Detection] = []
        for detection in detections:
            revocation = self.find(detection)
            if revocation is None:
                kept.append(detection)
                continue
            log.debug(
                "suppressed %s from %s: rule revoked%s",
                detection.name, detection.detector,
                f" ({revocation.reason})" if revocation.reason else "",
            )
        return kept

    def __len__(self) -> int:
        return sum(len(group) for group in self._by_rule.values())

    def __bool__(self) -> bool:
        return bool(self._by_rule)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<RevocationList {len(self)} rule(s) version={self.version!r}>"


def _identifiers(detection: Detection) -> set[str]:
    """Every lowercased name *detection* could be revoked under."""
    found = {detection.name.lower()} if detection.name else set()
    for key in _IDENTIFIER_KEYS:
        value = detection.metadata.get(key)
        if isinstance(value, str) and value:
            found.add(value.lower())
    return found


def _parse_entry(entry: Any) -> Revocation | None:
    """Turn one JSON entry into a :class:`Revocation`, or None if unusable."""
    if isinstance(entry, str):
        entry = {"rule": entry}
    if not isinstance(entry, dict):
        log.debug("ignoring revocation entry of type %s", type(entry).__name__)
        return None

    rule = str(entry.get("rule") or entry.get("name") or "").strip().lower()
    if not rule:
        log.debug("ignoring revocation entry with no rule name")
        return None

    # No wildcards, deliberately. "Disable everything matching Trojan.*" is a
    # switch nobody should be able to flip remotely, and every real revocation
    # names the one rule that misfired.
    if "*" in rule or "?" in rule:
        log.warning("ignoring wildcard revocation %r; revocations name one rule", rule)
        return None

    return Revocation(
        rule=rule,
        detector=str(entry.get("detector", "")).strip().lower(),
        reason=str(entry.get("reason", "")).strip(),
        expires=str(entry.get("expires", "")).strip(),
    )
