"""The system tray icon and its menu.

Owns three things: the icon (which state it shows), the tooltip (which
carries the states it could not), and the flyout (which opens on a
left-click).

Notification policy lives here too, because the tray is where it is felt.
The tiers, from the design rules:

=========  =========================  =======================================
Silent     Log only                   Scan started, scan clean, list updated
Ambient    The tray icon changes      Unwanted programs, stale threat list
Toast      OS notification            Something was moved somewhere safe
Modal      Steals focus               Could not move a file; protection off
=========  =========================  =======================================

At most :data:`~sentinel.ui.tray_state.MAX_TOASTS_PER_HOUR` toasts, then
they coalesce. Ten threats
in one scan produce one notification, not ten. And nothing is announced for a
scan that found nothing — silence is the feature. An application that is
quiet for weeks is one you believe when it finally speaks.
"""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import QObject, QPoint, Signal, SignalInstance
from PySide6.QtWidgets import QMenu, QSystemTrayIcon

from sentinel.core.logger import get_logger
from sentinel.ui.icons import all_icons
from sentinel.ui.tray_state import (
    NotificationBudget,
    TrayState,
    TrayStatus,
)
from sentinel.ui.windows.flyout import Flyout

log = get_logger(__name__)

TOAST_TIMEOUT_MS = 6000


class SentinelTray(QObject):
    """The tray icon, its tooltip, its menu and its flyout."""

    scan_requested = Signal()
    open_requested = Signal()
    review_requested = Signal()
    quit_requested = Signal()

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._icons = all_icons()
        self._status = TrayStatus()
        self._budget = NotificationBudget()

        self.tray = QSystemTrayIcon(self._icons[TrayState.SAFE], self)
        self.tray.activated.connect(self._on_activated)

        self.flyout = Flyout()
        self.flyout.scan_requested.connect(self._from_flyout(self.scan_requested))
        self.flyout.open_requested.connect(self._from_flyout(self.open_requested))
        self.flyout.review_requested.connect(self._from_flyout(self.review_requested))

        self.tray.setContextMenu(self._build_menu())
        self.set_status(self._status)

    @staticmethod
    def available() -> bool:
        """Whether this desktop has a usable tray.

        Several Linux sessions do not. The caller falls back to the main
        window rather than starting an application with no way to reach it.
        """
        return bool(QSystemTrayIcon.isSystemTrayAvailable())

    def _build_menu(self) -> QMenu:
        menu = QMenu()
        # Wording follows the vocabulary rules: no "quarantine", no "scan".
        check = menu.addAction("Check my computer")
        check.triggered.connect(self.scan_requested)
        show = menu.addAction("Open Sentinel")
        show.triggered.connect(self.open_requested)
        menu.addSeparator()
        quit_action = menu.addAction("Quit")
        quit_action.triggered.connect(self.quit_requested)
        return menu

    def _from_flyout(self, signal: SignalInstance) -> Any:
        """Re-emit a flyout signal, closing the panel first.

        The panel is meant to be gone in three seconds; leaving it open
        behind the window it just launched is the opposite of that.
        """
        def relay() -> None:
            self.flyout.hide()
            signal.emit()

        return relay

    # -- state ---------------------------------------------------------

    def set_status(self, status: TrayStatus) -> None:
        """Recompute the icon and tooltip from every current fact.

        Called with a whole status rather than nudged by individual events,
        which is what stops a finished scan turning the icon green while
        files are still waiting in the vault.
        """
        previous = self._status
        self._status = status

        self.tray.setIcon(self._icons[status.state])
        self.tray.setToolTip(f"Sentinel Scan\n{status.tooltip()}")
        self.flyout.set_status(status)

        self._maybe_toast(previous, status)

    def _maybe_toast(self, before: TrayStatus, after: TrayStatus) -> None:
        """Announce only what a person would want interrupting for."""
        moved = after.in_vault - before.in_vault
        if moved > 0:
            self.toast(
                "Moved somewhere safe",
                f"{moved} file{'s' if moved > 1 else ''} can't run now. "
                f"Nothing was deleted, and you can undo this.",
            )

        if before.watching and not after.watching:
            # Losing protection is the one thing worth being loud about.
            self.toast(
                "Not watching for threats",
                "Sentinel has stopped checking. Open it to start again.",
                QSystemTrayIcon.MessageIcon.Warning,
            )

        # Deliberately nothing for: a scan starting, a scan finishing clean,
        # or the threat list updating. Those all went right.

    def toast(
        self,
        title: str,
        body: str,
        icon: QSystemTrayIcon.MessageIcon = QSystemTrayIcon.MessageIcon.Information,
    ) -> bool:
        """Show an OS notification, subject to the budget. True if shown."""
        if not self._budget.allow():
            log.debug("toast suppressed by the hourly budget: %s", title)
            return False

        withheld = self._budget.take_suppressed()
        if withheld:
            body = f"{body}\n(and {withheld} other update{'s' if withheld > 1 else ''})"

        self.tray.showMessage(title, body, icon, TOAST_TIMEOUT_MS)
        return True

    # -- interaction ---------------------------------------------------

    def _on_activated(self, reason: QSystemTrayIcon.ActivationReason) -> None:
        if reason == QSystemTrayIcon.ActivationReason.Context:
            return  # the menu handles itself
        if reason == QSystemTrayIcon.ActivationReason.DoubleClick:
            self.flyout.hide()
            self.open_requested.emit()
            return
        self.toggle_flyout()

    def toggle_flyout(self) -> None:
        if self.flyout.isVisible():
            self.flyout.hide()
            return
        self.flyout.popup_at(self._anchor())

    def _anchor(self) -> QPoint:
        """Where the flyout should point.

        ``QSystemTrayIcon.geometry`` is empty on several Linux desktops and
        unreliable on Wayland, so fall back to the cursor, which is on the
        icon the user just clicked.
        """
        geometry = self.tray.geometry()
        if not geometry.isNull() and geometry.width() > 0:
            return geometry.center()
        from PySide6.QtGui import QCursor

        return QCursor.pos()

    def show(self) -> None:
        self.tray.show()

    def hide(self) -> None:
        self.flyout.hide()
        self.tray.hide()


def status_from_world(
    config: Any,
    db: Any,
    *,
    scanning: bool = False,
    scan_fraction: float | None = None,
    scan_eta_seconds: float | None = None,
    unresolved_threats: int = 0,
) -> TrayStatus:
    """Assemble a :class:`TrayStatus` from what is actually on disk.

    Reads the vault count and the threat-list age from the real sources
    rather than tracking them incrementally, because a counter that drifts
    is exactly how the vault appears empty when it is not.
    """
    in_vault = 0
    last_scan_at = None
    last_scan_was_clean = True
    try:
        in_vault = len(db.list_quarantine())
        recent = db.recent_scans(limit=1)
        if recent:
            last_scan_at = recent[0].started_at
            last_scan_was_clean = recent[0].threats == 0
    except Exception as exc:
        log.debug("cannot read scan state for the tray: %s", exc)

    age_days: float | None = None
    try:
        from datetime import datetime, timezone

        from sentinel.signatures.loader import SignatureStore

        updated = str(SignatureStore(config).summary().get("updated", ""))
        if updated and updated != "never":
            stamp = datetime.fromisoformat(updated)
            if stamp.tzinfo is None:
                stamp = stamp.replace(tzinfo=timezone.utc)
            age_days = (datetime.now(tz=timezone.utc) - stamp).total_seconds() / 86400
    except Exception as exc:
        log.debug("cannot read the threat list age: %s", exc)

    return TrayStatus(
        watching=True,
        scanning=scanning,
        scan_fraction=scan_fraction,
        scan_eta_seconds=scan_eta_seconds,
        unresolved_threats=unresolved_threats,
        in_vault=in_vault,
        threat_list_age_days=age_days,
        last_scan_at=last_scan_at,
        last_scan_was_clean=last_scan_was_clean,
    )
