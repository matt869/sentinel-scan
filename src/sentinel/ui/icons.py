"""Tray icons, drawn at whatever size the system asks for.

Drawn rather than shipped as image files, because a tray icon has to be
correct at 16 pixels on a 100% display and at 44 on a 275% one, and scaling
one bitmap between those looks like a smudge.

Distinguished by silhouette first, colour second, glyph third
-------------------------------------------------------------
At 16 pixels, colour is the *least* reliable signal available. Somewhere
between six and eight percent of men cannot separate the coral from the jade;
a dark taskbar drains apparent saturation; and the user is not looking
directly at it anyway — they are catching it in peripheral vision, which is
close to colourblind by design.

So the five states differ in outline before they differ in hue:

===========  =========================================================
``SAFE``     Solid filled shield
``SCANNING`` Shield with the centre cut out — a ring
``ATTENTION``Filled shield with a badge notched into the lower right
``THREAT``   Filled shield with a badge, cross rather than bang
``DISABLED`` Outline only, no fill
===========  =========================================================

The badge is drawn *overlapping the shield edge* so it changes the outline
rather than sitting inside it.

``THREAT`` and ``ATTENTION`` are the pair most at risk of collapsing into
each other, since both are "filled shield with a badge". Relying on the glyph
to separate them does not survive 16 pixels — at that size the glyph is about
seven pixels across and unreadable — so the **badge outline** differs too: a
circle for ``THREAT``, a triangle for ``ATTENTION``. That is also the
convention people already know from every other piece of software, where a
round badge means stop and a triangle means look. The glyphs then reinforce
it at larger sizes, a diagonal cross against a vertical bang.

``tests/test_tray.py`` renders every pair at 16px in greyscale and fails if
any two are too similar. That test is the reason to trust the paragraph
above.
"""

from __future__ import annotations

from sentinel.ui.tray_state import TrayState

try:
    from PySide6.QtCore import QPointF, QRectF, Qt
    from PySide6.QtGui import (
        QBrush,
        QColor,
        QIcon,
        QPainter,
        QPainterPath,
        QPainterPathStroker,
        QPen,
        QPixmap,
    )

    PYSIDE_AVAILABLE = True
except ImportError:  # pragma: no cover - depends on the environment
    PYSIDE_AVAILABLE = False

#: Sizes baked into every QIcon. Windows asks for 16 and 32 in the tray,
#: macOS for 22 and 44, and Linux desktops vary.
ICON_SIZES = (16, 20, 24, 32, 44, 64)

#: Fraction of the canvas the badge occupies. Large enough to read the glyph
#: at 16px, small enough to leave the shield recognisable.
_BADGE_SCALE = 0.46


def _shield_path(size: float, inset: float) -> QPainterPath:
    """A shield outline inside a *size* square, *inset* from each edge.

    Proportions chosen so that the silhouette still reads as a shield when
    the whole shape is 12 pixels across: a wide flat top, straight shoulders
    for the upper half, then a fast taper to a rounded point.
    """
    left = inset
    right = size - inset
    top = inset
    bottom = size - inset
    width = right - left
    middle = left + width / 2
    shoulder = top + (bottom - top) * 0.52

    path = QPainterPath()
    path.moveTo(middle, top)
    path.lineTo(right, top + (bottom - top) * 0.16)
    path.lineTo(right, shoulder)
    # One curve per side into the point, rather than a spline through it —
    # a symmetric tip survives rounding to a pixel grid, a clever one does not.
    path.quadTo(QPointF(right, bottom - (bottom - top) * 0.12), QPointF(middle, bottom))
    path.quadTo(QPointF(left, bottom - (bottom - top) * 0.12), QPointF(left, shoulder))
    path.lineTo(left, top + (bottom - top) * 0.16)
    path.closeSubpath()
    return path


def _triangle_path(rect: QRectF) -> QPainterPath:
    """A rounded-corner warning triangle filling *rect*."""
    path = QPainterPath()
    top = QPointF(rect.center().x(), rect.top())
    left = QPointF(rect.left(), rect.bottom())
    right = QPointF(rect.right(), rect.bottom())
    # Corners pulled in slightly and joined with quadratics: a sharp-cornered
    # triangle at 16px turns into a spiky mess once antialiased.
    nudge = rect.width() * 0.14
    path.moveTo(top.x() - nudge * 0.6, top.y() + nudge)
    path.quadTo(top, QPointF(top.x() + nudge * 0.6, top.y() + nudge))
    path.lineTo(right.x() - nudge * 0.5, right.y() - nudge * 0.4)
    path.quadTo(right, QPointF(right.x() - nudge, right.y()))
    path.lineTo(left.x() + nudge, left.y())
    path.quadTo(left, QPointF(left.x() + nudge * 0.5, left.y() - nudge * 0.4))
    path.closeSubpath()
    return path


def _draw_bang(painter: QPainter, rect: QRectF, colour: QColor) -> None:
    """An exclamation mark: one vertical stroke and a dot beneath it."""
    painter.setPen(Qt.PenStyle.NoPen)
    painter.setBrush(QBrush(colour))
    stroke_width = rect.width() * 0.16
    x = rect.center().x() - stroke_width / 2
    painter.drawRoundedRect(
        QRectF(x, rect.top() + rect.height() * 0.32, stroke_width, rect.height() * 0.32),
        stroke_width / 2, stroke_width / 2,
    )
    dot = stroke_width * 1.05
    painter.drawEllipse(
        QRectF(rect.center().x() - dot / 2, rect.top() + rect.height() * 0.72, dot, dot)
    )


def _draw_cross(painter: QPainter, rect: QRectF, colour: QColor) -> None:
    """A cross: two diagonal strokes. Deliberately nothing like the bang."""
    pen = QPen(colour)
    pen.setWidthF(rect.width() * 0.20)
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    painter.setPen(pen)
    painter.setBrush(Qt.BrushStyle.NoBrush)
    pad = rect.width() * 0.30
    painter.drawLine(
        QPointF(rect.left() + pad, rect.top() + pad),
        QPointF(rect.right() - pad, rect.bottom() - pad),
    )
    painter.drawLine(
        QPointF(rect.right() - pad, rect.top() + pad),
        QPointF(rect.left() + pad, rect.bottom() - pad),
    )


def render(state: TrayState, size: int, colour: str | None = None) -> QPixmap:
    """Draw *state* at *size* pixels square."""
    if not PYSIDE_AVAILABLE:  # pragma: no cover - guarded by the caller
        raise RuntimeError("PySide6 is required to render tray icons")

    pixmap = QPixmap(size, size)
    pixmap.fill(QColor(0, 0, 0, 0))

    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
    tint = QColor(colour or state.colour)

    # Badged states shrink the shield so the badge has somewhere to go
    # without covering it.
    badged = state in (TrayState.THREAT, TrayState.ATTENTION)
    inset = size * 0.08
    shield_size = size * 0.80 if badged else size
    shield = _shield_path(shield_size, inset)

    if state is TrayState.DISABLED:
        # Outline only. The hollow silhouette is the signal; the grey merely
        # agrees with it.
        pen = QPen(tint)
        pen.setWidthF(max(size * 0.10, 1.2))
        pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
        painter.setPen(pen)
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawPath(shield)
    elif state is TrayState.SCANNING:
        # A ring: filled shield with a hole punched through the middle. Reads
        # as "open, in progress" and is unmistakably not the solid one.
        hole = QPainterPath()
        hole.addEllipse(
            QRectF(size * 0.27, size * 0.27, size * 0.46, size * 0.46)
        )
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QBrush(tint))
        painter.drawPath(shield.subtracted(hole))
    else:
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QBrush(tint))
        painter.drawPath(shield)

    if badged:
        badge_size = size * _BADGE_SCALE
        badge = QRectF(
            size - badge_size - inset * 0.5,
            size - badge_size - inset * 0.5,
            badge_size,
            badge_size,
        )
        # Circle for a threat, triangle for attention — the outlines differ,
        # so the two stay apart at 16px where the glyph inside is too small
        # to read.
        shape = QPainterPath()
        if state is TrayState.THREAT:
            shape.addEllipse(badge)
        else:
            shape = _triangle_path(badge)

        # A ring of transparent pixels around the badge separates it from the
        # shield at 16px, where two touching shapes merge into one blob.
        halo = size * 0.07
        outline = QPainterPathStroker()
        outline.setWidth(halo * 2)
        painter.setCompositionMode(QPainter.CompositionMode.CompositionMode_Clear)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QBrush(QColor(0, 0, 0, 255)))
        painter.drawPath(shape.united(outline.createStroke(shape)))
        painter.setCompositionMode(QPainter.CompositionMode.CompositionMode_SourceOver)

        painter.setBrush(QBrush(tint))
        painter.drawPath(shape)

        glyph = QColor(255, 255, 255)
        if state is TrayState.THREAT:
            _draw_cross(painter, badge, glyph)
        else:
            _draw_bang(painter, badge, glyph)

    painter.end()
    return pixmap


def icon_for(state: TrayState, colour: str | None = None) -> QIcon:
    """A multi-resolution :class:`QIcon` for *state*.

    Every size is drawn rather than scaled, so the 16px version gets its own
    geometry instead of a resampled 64px one.
    """
    icon = QIcon()
    for size in ICON_SIZES:
        icon.addPixmap(render(state, size, colour))
    return icon


def all_icons() -> dict[TrayState, QIcon]:
    """Every state's icon, built once and reused.

    Building a QIcon allocates six pixmaps; doing that on every state change
    of a long-running tray application is a leak with extra steps.
    """
    return {state: icon_for(state) for state in TrayState}
