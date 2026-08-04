"""What the tray icon says, and how it decides.

The tray is the only part of this application most people will ever look at.
It has to answer one question — *am I okay?* — in the corner of the eye, at
16 pixels, while they are doing something else.

The hard part is that several things are true at once. A scan is running,
two files are sitting in the vault from yesterday, and the threat list is
nine days old. That is three separate truths and one icon.

The failure this module exists to prevent
-----------------------------------------
The classic antivirus bug is a finished scan flipping the icon green while
quarantined threats are still waiting for a decision. The scan result was
"clean", so the scan reports clean, so the icon goes green — and the two
files nobody has looked at vanish from the user's awareness entirely. They
believe they are fine. They are not.

So the rule here is: **state is derived from every fact at once, never from
the last event that happened.** :class:`TrayStatus` holds all of them,
:attr:`TrayStatus.state` picks the icon by priority, and the tooltip carries
the facts the icon could not. ``SAFE`` is the lowest priority in the list and
is reachable only when nothing else is true, which is the property worth
testing hardest.

Colour, per the design rules, means exactly one thing:

============  ==========  ==================================================
State         Colour      Meaning
============  ==========  ==================================================
``THREAT``    coral       Something bad is here and needs you
``DISABLED``  grey        Not watching
``SCANNING``  blue        Working
``ATTENTION`` amber       Needs you, but not urgently
``SAFE``      jade        Nothing to do
============  ==========  ==================================================

Coral appears only when a threat genuinely exists. Decorative red trains
people to ignore red.
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass
from enum import Enum

from sentinel.utils.humanize import human_count

#: The threat list is not fresh after this many days. Not an emergency —
#: ambient, not a notification.
STALE_AFTER_DAYS = 7

#: Below this, "just now" is a better answer than a duration.
JUST_NOW_SECONDS = 90


class TrayState(str, Enum):
    """What the icon shows. Declared in priority order, highest first."""

    THREAT = "threat"
    DISABLED = "disabled"
    SCANNING = "scanning"
    ATTENTION = "attention"
    SAFE = "safe"

    @property
    def priority(self) -> int:
        """Lower wins. Derived from declaration order, so the table above
        and the behaviour cannot drift apart."""
        return _PRIORITY[self]

    @property
    def colour(self) -> str:
        return _COLOURS[self]


_PRIORITY: dict[TrayState, int] = {
    state: index for index, state in enumerate(TrayState)
}

#: One meaning each. Shared with the stylesheet.
_COLOURS: dict[TrayState, str] = {
    TrayState.THREAT: "#e06c75",     # coral
    TrayState.DISABLED: "#6b7280",   # grey
    TrayState.SCANNING: "#61afef",   # blue
    TrayState.ATTENTION: "#d9a441",  # amber
    TrayState.SAFE: "#5fb37c",       # jade
}


@dataclass(frozen=True, slots=True)
class TrayStatus:
    """Every fact the tray needs, held at once.

    Constructed fresh from the world rather than mutated by events, so a
    stale field cannot outlive the thing it described.

    Attributes:
        watching: Whether Sentinel is watching for threats at all.
        scanning: Whether a scan is running now.
        scan_fraction: Progress in 0-1, or None while still counting files.
        scan_eta_seconds: Seconds remaining, or None when not yet known.
        unresolved_threats: Findings the user has not dealt with.
        in_vault: Files moved somewhere safe and still there.
        threat_list_age_days: Age of the threat list, or None if never
            fetched.
        last_scan_at: Unix time of the last completed scan.
        last_scan_was_clean: Whether that scan found nothing.
    """

    watching: bool = True
    scanning: bool = False
    scan_fraction: float | None = None
    scan_eta_seconds: float | None = None
    unresolved_threats: int = 0
    in_vault: int = 0
    threat_list_age_days: float | None = None
    last_scan_at: float | None = None
    last_scan_was_clean: bool = True

    # -- derived state -------------------------------------------------

    @property
    def threat_list_is_stale(self) -> bool:
        if self.threat_list_age_days is None:
            return True
        return self.threat_list_age_days >= STALE_AFTER_DAYS

    @property
    def needs_attention(self) -> bool:
        """True for things the user should get to, but not right now."""
        return self.threat_list_is_stale or self.in_vault > 0

    @property
    def state(self) -> TrayState:
        """The single state the icon shows.

        Order is the whole point. Note especially that a *finished* scan does
        not enter into it: files in the vault keep the icon off SAFE however
        clean the last scan was.
        """
        if self.unresolved_threats > 0:
            return TrayState.THREAT
        if not self.watching:
            return TrayState.DISABLED
        if self.scanning:
            return TrayState.SCANNING
        if self.needs_attention:
            return TrayState.ATTENTION
        return TrayState.SAFE

    # -- words ---------------------------------------------------------

    @property
    def headline(self) -> str:
        """The one line at the top of the flyout.

        Written the way somebody would say it out loud. No "quarantine", no
        "signature database", no "real-time protection".
        """
        if self.unresolved_threats > 0:
            return (
                f"{human_count(self.unresolved_threats, 'thing')} "
                f"{'needs' if self.unresolved_threats == 1 else 'need'} your attention"
            )
        if not self.watching:
            return "Not watching for threats"
        if self.scanning:
            return "Looking through your files"
        if self.in_vault > 0:
            return f"{human_count(self.in_vault, 'file')} moved somewhere safe"
        if self.threat_list_is_stale:
            return "Your threat list is out of date"
        return "You're protected"

    @property
    def detail(self) -> str:
        """The line under the headline.

        Tested in the same order as :attr:`headline`, so the two always
        describe the same thing. Ordering them differently produced a threat
        headline sitting above a sentence about counting files, which reads
        as though the app has lost track of what it is telling you.
        """
        if self.unresolved_threats > 0:
            return "Nothing has been deleted. You can undo anything."
        if not self.watching:
            return "Sentinel is installed but is not checking anything."
        if self.scanning:
            return self._scan_detail()
        if self.in_vault > 0:
            return "They can't run. Nothing was deleted."
        if self.threat_list_is_stale:
            return self._staleness()
        return self._last_scan()

    def _scan_detail(self) -> str:
        from sentinel.engine.progress import format_eta

        if self.scan_fraction is None:
            return "Counting your files first, so the time left is accurate."
        return f"{format_eta(self.scan_eta_seconds)} left"

    def _staleness(self) -> str:
        if self.threat_list_age_days is None:
            return "Sentinel hasn't downloaded it yet."
        days = int(self.threat_list_age_days)
        return f"Last updated {human_count(days, 'day')} ago."

    def _last_scan(self) -> str:
        if self.last_scan_at is None:
            return "Sentinel hasn't looked through your files yet."
        return f"Last checked {describe_age(time.time() - self.last_scan_at)}."

    def tooltip(self) -> str:
        """Hover text, carrying every truth the icon could not.

        The icon shows one state. This shows all of them, because the whole
        reason the priority list exists is that more than one thing is true,
        and the ones that lost still matter.
        """
        lines = [self.headline]

        # Facts the chosen icon may have hidden, in the order a person would
        # want them.
        if self.scanning and self.state is not TrayState.SCANNING:
            lines.append("A scan is running.")
        if self.in_vault > 0 and self.state is not TrayState.ATTENTION:
            lines.append(
                f"{human_count(self.in_vault, 'file')} moved somewhere safe."
            )
        if self.threat_list_is_stale and self.headline != "Your threat list is out of date":
            lines.append(self._staleness().replace("Last updated", "Threat list updated"))
        if not self.watching and self.state is not TrayState.DISABLED:
            lines.append("Not watching for threats.")

        detail = self.detail
        if detail and detail not in lines:
            lines.append(detail)

        return "\n".join(lines)


def describe_age(seconds: float) -> str:
    """A duration the way somebody would say it.

    >>> describe_age(30)
    'just now'
    >>> describe_age(7200)
    '2 hours ago'
    """
    if seconds < JUST_NOW_SECONDS:
        return "just now"

    minutes = seconds / 60
    if minutes < 60:
        return f"{human_count(round(minutes), 'minute')} ago"

    hours = minutes / 60
    if hours < 24:
        return f"{human_count(round(hours), 'hour')} ago"

    days = round(hours / 24)
    if days == 1:
        return "yesterday"
    if days < 30:
        return f"{human_count(days, 'day')} ago"

    months = round(days / 30)
    return f"{human_count(months, 'month')} ago"


# ----------------------------------------------------------------------
# how often the tray is allowed to speak
# ----------------------------------------------------------------------

#: Toasts allowed per rolling hour before they coalesce into one.
MAX_TOASTS_PER_HOUR = 3


class NotificationBudget:
    """Rate limits toasts over a rolling window.

    Here rather than in ``ui/tray.py`` for the same reason the rest of this
    module is: the limit is a rule, not a side effect of some Qt behaviour,
    and a rule should be testable without a desktop session.

    It used to say that while living in the module that imports PySide6, so
    it was not true — and importing it to test it dragged in Qt, which on a
    machine without the GUI extra installed is an ImportError at collection
    time. That took the whole test run down, including the tests in this
    module that have nothing to do with a tray icon at all.
    """

    def __init__(self, limit: int = MAX_TOASTS_PER_HOUR, window: float = 3600.0) -> None:
        self.limit = limit
        self.window = window
        self._sent: deque[float] = deque()
        self._suppressed = 0

    def allow(self, now: float | None = None) -> bool:
        """Whether a toast may be shown, recording it if so."""
        moment = time.time() if now is None else now
        while self._sent and moment - self._sent[0] > self.window:
            self._sent.popleft()

        if len(self._sent) >= self.limit:
            self._suppressed += 1
            return False

        self._sent.append(moment)
        return True

    @property
    def suppressed(self) -> int:
        """How many toasts have been withheld since the last summary."""
        return self._suppressed

    def take_suppressed(self) -> int:
        count = self._suppressed
        self._suppressed = 0
        return count
