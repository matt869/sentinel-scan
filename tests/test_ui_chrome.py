"""The window's own presentation: does it come up looking like this app?

These are cheap structural checks, not pixel comparisons. They exist because
the theme was silently absent for the entire life of the GUI and nothing
noticed — a window renders perfectly well unstyled, so every check that only
asked "did it build?" passed.
"""

from __future__ import annotations

import pytest

pytest.importorskip("PySide6", reason="the GUI extra is not installed")

from PySide6.QtWidgets import QApplication, QGroupBox

from sentinel.core.config import Config
from sentinel.ui.app import load_stylesheet
from sentinel.ui.widgets import Section
from sentinel.ui.windows.main_window import MainWindow
from sentinel.ui.windows.scan_view import ScanView


@pytest.fixture(scope="module")
def qt_app() -> QApplication:
    """One QApplication for the module; Qt allows only one per process."""
    import os

    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    return QApplication.instance() or QApplication([])


@pytest.fixture
def window(qt_app: QApplication, config: Config):
    win = MainWindow(config)
    yield win
    win.db.close()
    win.close()
    win.deleteLater()
    qt_app.processEvents()


# ----------------------------------------------------------------------
# the theme
# ----------------------------------------------------------------------

def test_the_stylesheet_is_not_empty() -> None:
    """It is loaded by path, so a rename or a packaging slip empties it."""
    assert len(load_stylesheet()) > 500


def test_the_window_themes_itself(window: MainWindow) -> None:
    """The regression this file exists for.

    ``ui/app.main`` sets the stylesheet on the QApplication, which covers the
    shipping path and nothing else. A window built directly — the CI smoke
    check, any embedding caller — came up in Qt's default palette, and no
    test could tell, because "it built" was the only thing being asked.
    """
    app = QApplication.instance()
    assert app is not None
    assert window.styleSheet() or app.styleSheet(), "the window came up unstyled"


def test_an_application_stylesheet_is_left_alone(
    qt_app: QApplication, config: Config
) -> None:
    """An embedder who has chosen a theme keeps it."""
    qt_app.setStyleSheet("QWidget { color: #123456; }")
    try:
        win = MainWindow(config)
        assert not win.styleSheet(), "the window overrode the application's theme"
        win.db.close()
        win.close()
        win.deleteLater()
    finally:
        qt_app.setStyleSheet("")


# ----------------------------------------------------------------------
# the flat layout
# ----------------------------------------------------------------------

def test_no_page_draws_a_group_box(window: MainWindow) -> None:
    """Grouping is done with space now. A stray box would not match anything.

    See ui/widgets.py: three bordered boxes on one page is a stack of
    rectangles competing for the same attention, and nothing on these pages
    was ambiguous about which control belonged to which heading anyway.
    """
    for index in range(window.pages.count()):
        page = window.pages.widget(index)
        boxes = page.findChildren(QGroupBox)
        assert not boxes, f"page {index} still has {len(boxes)} group box(es)"


def test_section_titles_are_upper_case_and_tracked() -> None:
    """Qt's QSS has neither text-transform nor letter-spacing.

    It ignores both without a word, which is why the first attempt rendered
    as ordinary sentence-case body text flush against its own contents. Both
    have to come from the QFont.
    """
    section = Section("What to scan")
    assert section.title_label is not None
    assert section.title_label.text() == "WHAT TO SCAN"
    assert section.title_label.font().letterSpacing() > 0
    assert section.title_label.font().bold()


def test_set_title_keeps_the_casing() -> None:
    section = Section("Options")
    section.set_title("progress")
    assert section.title_label is not None
    assert section.title_label.text() == "PROGRESS"


# ----------------------------------------------------------------------
# showing only what applies
# ----------------------------------------------------------------------

def test_the_folder_picker_is_hidden_until_custom_is_chosen(
    qt_app: QApplication, config: Config
) -> None:
    """A control you can see but cannot use is a question you have to answer.

    Greyed out, the list and its two buttons were a third of the page spent
    on a mode the user is not in.
    """
    view = ScanView(config)
    view.show()
    qt_app.processEvents()
    assert not view.custom_panel.isVisible()

    view.radio_custom.setChecked(True)
    qt_app.processEvents()
    assert view.custom_panel.isVisible()

    view.radio_quick.setChecked(True)
    qt_app.processEvents()
    assert not view.custom_panel.isVisible()

    view.close()
    view.deleteLater()


def test_progress_is_hidden_until_a_scan_has_run(
    qt_app: QApplication, config: Config
) -> None:
    """Before the first scan it is a title, "Not running", and a black void."""
    view = ScanView(config)
    view.show()
    qt_app.processEvents()
    assert not view.progress_section.isVisible()

    view.set_running(True)
    qt_app.processEvents()
    assert view.progress_section.isVisible()

    # And it stays: the result of the last scan is what somebody comes back
    # to the page to read.
    view.set_running(False)
    qt_app.processEvents()
    assert view.progress_section.isVisible()

    view.close()
    view.deleteLater()
