"""The flyout: the 360x428 panel that answers "am I okay?".

Most of the time this *is* the application. Someone half-remembers a warning
they clicked past, glances at the tray, left-clicks, reads one line, and gets
on with their day. Three seconds, no window, no navigation.

Forcing a full window on that interaction is a tax people pay once and then
stop paying — they stop checking, which means they stop knowing, which is the
failure mode the whole product exists to prevent.

So the panel has exactly four things in it, in this order:

1. **A status dot and one plain-English line.** The answer.
2. **One line of detail.** Why, or what happens next.
3. **One button.** The only thing worth doing from here.
4. **The resource line.** Permanent. See :mod:`sentinel.system.resources`.

Anything else belongs in the main window, which is one click away and which
most people will never need.
"""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import QEvent, QPoint, Qt, QTimer, Signal
from PySide6.QtGui import QColor, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import (
    QApplication,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from sentinel.system.resources import ResourceMeter, default_meter
from sentinel.ui.tray_state import TrayState, TrayStatus

#: Fixed, because the content is fixed. A panel that resizes with its content
#: makes the thing you are looking for move between visits.
FLYOUT_WIDTH = 360
FLYOUT_HEIGHT = 428

#: How often the resource line refreshes while the panel is open. Fast enough
#: to look live, slow enough that reading it is not a chore.
RESOURCE_INTERVAL_MS = 1500

#: Gap between the panel and the screen edge it is anchored to.
_MARGIN = 8


class StatusDot(QWidget):
    """A filled circle in the state colour, with a soft halo.

    A dot rather than a copy of the tray icon: at this size the icon's
    silhouette work is wasted, and a large flat colour field reads faster
    than a detailed glyph.
    """

    def __init__(self, diameter: int = 14) -> None:
        super().__init__()
        self._colour = QColor(TrayState.SAFE.colour)
        self._diameter = diameter
        self.setFixedSize(diameter * 2, diameter * 2)

    def set_state(self, state: TrayState) -> None:
        self._colour = QColor(state.colour)
        self.update()

    def paintEvent(self, event: Any) -> None:  # noqa: N802 - Qt override
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)

        centre = self.rect().center()
        halo = QColor(self._colour)
        halo.setAlpha(48)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(halo)
        painter.drawEllipse(centre, self._diameter, self._diameter)

        painter.setBrush(self._colour)
        painter.drawEllipse(centre, self._diameter // 2, self._diameter // 2)
        painter.end()


class Flyout(QWidget):
    """The tray panel."""

    scan_requested = Signal()
    open_requested = Signal()
    review_requested = Signal()

    def __init__(self, meter: ResourceMeter | None = None) -> None:
        super().__init__(None)
        self.setWindowFlags(
            Qt.WindowType.Popup
            | Qt.WindowType.FramelessWindowHint
            | Qt.WindowType.NoDropShadowWindowHint
        )
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setFixedSize(FLYOUT_WIDTH, FLYOUT_HEIGHT)
        self.setObjectName("flyout")

        self._meter = meter if meter is not None else default_meter()
        self._status = TrayStatus()
        self._build()

        # Only ticks while the panel is visible. A timer running against a
        # hidden widget for eight hours is exactly the kind of idle cost this
        # product promises not to have.
        self._timer = QTimer(self)
        self._timer.setInterval(RESOURCE_INTERVAL_MS)
        self._timer.timeout.connect(self._refresh_resources)

    # -- construction --------------------------------------------------

    def _build(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)

        card = QFrame()
        card.setObjectName("flyoutCard")
        outer.addWidget(card)

        layout = QVBoxLayout(card)
        layout.setContentsMargins(22, 22, 22, 18)
        layout.setSpacing(0)

        header = QHBoxLayout()
        header.setSpacing(12)
        self.dot = StatusDot()
        header.addWidget(self.dot, alignment=Qt.AlignmentFlag.AlignTop)

        headline_column = QVBoxLayout()
        headline_column.setSpacing(4)
        self.headline = QLabel("You're protected")
        self.headline.setObjectName("flyoutHeadline")
        self.headline.setWordWrap(True)
        headline_column.addWidget(self.headline)

        self.detail = QLabel("")
        self.detail.setObjectName("flyoutDetail")
        self.detail.setWordWrap(True)
        self.detail.setSizePolicy(
            QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Minimum
        )
        headline_column.addWidget(self.detail)
        header.addLayout(headline_column, stretch=1)
        layout.addLayout(header)

        layout.addSpacing(18)
        self.progress = _ProgressStrip()
        layout.addWidget(self.progress)
        self.progress.setVisible(False)

        layout.addStretch(1)

        self.action = QPushButton("Check my computer")
        self.action.setObjectName("flyoutPrimary")
        self.action.setMinimumHeight(40)
        self.action.clicked.connect(self._on_action)
        layout.addWidget(self.action)

        layout.addSpacing(10)

        footer = QHBoxLayout()
        footer.setSpacing(0)
        self.resource_label = QLabel("")
        self.resource_label.setObjectName("flyoutResources")
        self.resource_label.setToolTip(
            "What Sentinel is costing your computer right now. "
            "This is always shown and is never rounded in our favour."
        )
        footer.addWidget(self.resource_label)
        footer.addStretch(1)

        self.open_button = QPushButton("Open Sentinel")
        self.open_button.setObjectName("flyoutLink")
        self.open_button.setFlat(True)
        self.open_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.open_button.clicked.connect(self.open_requested)
        footer.addWidget(self.open_button)
        layout.addLayout(footer)

    def paintEvent(self, event: Any) -> None:  # noqa: N802 - Qt override
        # Rounded card with a hairline border. Drawn rather than styled so
        # the translucent corners stay transparent on every platform.
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        path = QPainterPath()
        path.addRoundedRect(self.rect().adjusted(0, 0, -1, -1), 12, 12)
        painter.fillPath(path, QColor("#232830"))
        painter.setPen(QPen(QColor("#333a45"), 1))
        painter.drawPath(path)
        painter.end()

    # -- state ---------------------------------------------------------

    def set_status(self, status: TrayStatus) -> None:
        """Show *status*. The single way the panel's content changes."""
        self._status = status
        state = status.state

        self.dot.set_state(state)
        self.headline.setText(status.headline)
        self.detail.setText(status.detail)

        scanning = state is TrayState.SCANNING or status.scanning
        self.progress.setVisible(scanning)
        if scanning:
            self.progress.set_fraction(status.scan_fraction)

        self.action.setText(self._action_label(status))
        self._refresh_resources()

    @staticmethod
    def _action_label(status: TrayStatus) -> str:
        """The one button. Its words follow the state, not the other way."""
        if status.unresolved_threats > 0:
            return "Show me"
        if status.scanning:
            return "Stop checking"
        if not status.watching:
            return "Start watching"
        if status.in_vault > 0:
            return "See what was moved"
        return "Check my computer"

    def _on_action(self) -> None:
        status = self._status
        if status.unresolved_threats > 0 or status.in_vault > 0:
            self.review_requested.emit()
        else:
            self.scan_requested.emit()

    def _refresh_resources(self) -> None:
        self.resource_label.setText(self._meter.describe())

    # -- showing and hiding --------------------------------------------

    def popup_at(self, anchor: QPoint) -> None:
        """Show the panel near *anchor*, kept inside the screen.

        The tray lives in a different corner on every platform and on some
        Linux desktops it moves, so the position is computed from the anchor
        and the available geometry rather than assumed to be bottom-right.
        """
        screen = QApplication.screenAt(anchor) or QApplication.primaryScreen()
        area = screen.availableGeometry()

        x = anchor.x() - self.width() // 2
        x = max(area.left() + _MARGIN, min(x, area.right() - self.width() - _MARGIN))

        # Above the anchor if it is in the lower half of the screen, below if
        # it is in the upper half — which puts the panel on the correct side
        # of a taskbar wherever the user has put theirs.
        if anchor.y() > area.center().y():
            y = anchor.y() - self.height() - _MARGIN
        else:
            y = anchor.y() + _MARGIN
        y = max(area.top() + _MARGIN, min(y, area.bottom() - self.height() - _MARGIN))

        self.move(QPoint(x, y))
        self.show()
        self.raise_()
        self.activateWindow()

    def showEvent(self, event: Any) -> None:  # noqa: N802 - Qt override
        self._refresh_resources()
        self._timer.start()
        super().showEvent(event)

    def hideEvent(self, event: Any) -> None:  # noqa: N802 - Qt override
        self._timer.stop()
        super().hideEvent(event)

    def event(self, event: QEvent) -> bool:
        # Clicking away closes it. A panel meant to be gone in three seconds
        # must not need a close button.
        if event.type() == QEvent.Type.WindowDeactivate:
            self.hide()
        return super().event(event)


class _ProgressStrip(QFrame):
    """A thin progress bar, or a sweeping bar while the total is unknown."""

    def __init__(self) -> None:
        super().__init__()
        self.setFixedHeight(4)
        self._fraction: float | None = None
        self._sweep = 0.0
        self._timer = QTimer(self)
        self._timer.setInterval(40)
        self._timer.timeout.connect(self._advance)

    def set_fraction(self, fraction: float | None) -> None:
        self._fraction = fraction
        if fraction is None:
            if not self._timer.isActive():
                self._timer.start()
        else:
            self._timer.stop()
        self.update()

    def hideEvent(self, event: Any) -> None:  # noqa: N802 - Qt override
        self._timer.stop()
        super().hideEvent(event)

    def _advance(self) -> None:
        self._sweep = (self._sweep + 0.02) % 1.0
        self.update()

    def paintEvent(self, event: Any) -> None:  # noqa: N802 - Qt override
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        painter.setPen(Qt.PenStyle.NoPen)

        painter.setBrush(QColor("#2f3540"))
        painter.drawRoundedRect(self.rect(), 2, 2)

        colour = QColor(TrayState.SCANNING.colour)
        painter.setBrush(colour)
        width = self.width()
        if self._fraction is None:
            # Counting files. A sweep says "working" without implying a
            # position, which a partial bar would.
            bar = width * 0.28
            x = (width + bar) * self._sweep - bar
            painter.drawRoundedRect(
                int(max(x, 0)), 0, int(min(bar, width - max(x, 0))), self.height(), 2, 2
            )
        else:
            painter.drawRoundedRect(
                0, 0, int(width * max(0.0, min(self._fraction, 1.0))),
                self.height(), 2, 2,
            )
        painter.end()
