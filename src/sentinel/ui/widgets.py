"""Small shared widgets, so the four pages look like one application.

The only thing in here is :class:`Section`, and it exists to replace
``QGroupBox``.

A group box draws a titled border around its contents. Put three on a page —
which is what the scan page and the settings page both need — and the result
is a stack of boxes inside a box inside a window, every one of them competing
for the same attention with a 1px line. The border is decoration: nothing on
these pages is ambiguous about which control belongs to which heading, because
they are laid out one under another with space between them. Space groups
things at least as well as a rectangle does, and it does not add a line to
look at.

So a section here is a quiet label and its contents, and the grouping is done
by the gap above it. Borders are kept for the two places they carry meaning:
a field you can type into, and a table of data.
"""

from __future__ import annotations

from PySide6.QtGui import QFont
from PySide6.QtWidgets import QLabel, QVBoxLayout, QWidget


class Section(QWidget):
    """A titled group of controls, drawn with space instead of a border.

    Use it like a ``QGroupBox`` whose layout you were going to make anyway::

        section = Section("What to scan")
        section.body.addWidget(radio)
        section.body.addLayout(row)
    """

    def __init__(self, title: str = "", parent: QWidget | None = None) -> None:
        super().__init__(parent)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(10)

        self.title_label: QLabel | None = None
        if title:
            self.title_label = QLabel(title.upper())
            self.title_label.setObjectName("sectionTitle")
            self.title_label.setFont(_title_font())
            outer.addWidget(self.title_label)

        #: Where callers put their controls.
        self.body = QVBoxLayout()
        self.body.setContentsMargins(0, 0, 0, 0)
        self.body.setSpacing(8)
        outer.addLayout(self.body)

    def set_title(self, title: str) -> None:
        if self.title_label is not None:
            self.title_label.setText(title.upper())


def _title_font() -> QFont:
    """The section-title font.

    Built here rather than in the stylesheet because Qt's QSS subset has
    neither ``text-transform`` nor ``letter-spacing`` — it silently ignores
    both, which is why the first attempt at this rendered as ordinary
    sentence-case body text sitting flush against its own contents, reading
    as the first item in the list rather than the name of it.

    Upper case *and* tracking, not upper case alone: capitals set at body
    tracking are noticeably harder to read, and the whole point of the label
    is to be skimmed.
    """
    font = QFont()
    font.setPointSizeF(8.0)
    font.setWeight(QFont.Weight.Bold)
    font.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, 0.9)
    return font


class Hint(QLabel):
    """A line of explanation under a control.

    The product's whole voice is telling people what it decided and why, in
    words they can check. That needs somewhere to live that is visibly not a
    label and not an error.
    """

    def __init__(self, text: str = "", parent: QWidget | None = None) -> None:
        super().__init__(text, parent)
        self.setObjectName("hint")
        self.setWordWrap(True)
