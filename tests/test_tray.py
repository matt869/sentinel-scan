"""Tests for the tray: state priority, wording, icons, notification budget.

The one this file exists for is
:meth:`TestTrayState.test_clean_scan_does_not_hide_files_in_the_vault`. That
is the classic antivirus bug — a finished scan flips the icon green and the
files waiting in the vault disappear from the user's awareness — and it is
the reason state is derived from every fact at once instead of from the last
event that happened.
"""

from __future__ import annotations

import time
from typing import Any, ClassVar

import pytest

from sentinel.system.resources import ResourceMeter
from sentinel.ui.tray import NotificationBudget
from sentinel.ui.tray_state import TrayState, TrayStatus, describe_age

# ----------------------------------------------------------------------
# which icon
# ----------------------------------------------------------------------

class TestTrayState:
    def test_nothing_wrong_is_safe(self) -> None:
        status = TrayStatus(threat_list_age_days=0.5, last_scan_at=time.time())
        assert status.state is TrayState.SAFE

    def test_clean_scan_does_not_hide_files_in_the_vault(self) -> None:
        # The bug this module exists to prevent. The last scan found nothing,
        # so a system that tracked "last scan result" would go green — while
        # two files sit in the vault that nobody has looked at, and the user
        # concludes they are fine.
        status = TrayStatus(
            last_scan_was_clean=True,
            last_scan_at=time.time(),
            threat_list_age_days=0.0,
            in_vault=2,
        )
        assert status.state is not TrayState.SAFE
        assert status.state is TrayState.ATTENTION
        assert "moved somewhere safe" in status.headline

    def test_threat_outranks_everything(self) -> None:
        status = TrayStatus(
            unresolved_threats=1, scanning=True, watching=False,
            in_vault=5, threat_list_age_days=99,
        )
        assert status.state is TrayState.THREAT

    def test_not_watching_outranks_a_running_scan(self) -> None:
        # A manual scan can run with protection off, and the standing fact
        # that nothing is being watched is the more important one.
        status = TrayStatus(watching=False, scanning=True)
        assert status.state is TrayState.DISABLED

    def test_scanning_outranks_a_stale_list(self) -> None:
        status = TrayStatus(scanning=True, threat_list_age_days=30)
        assert status.state is TrayState.SCANNING

    def test_stale_threat_list_needs_attention(self) -> None:
        assert TrayStatus(threat_list_age_days=8).state is TrayState.ATTENTION
        assert TrayStatus(threat_list_age_days=1).state is TrayState.SAFE

    def test_a_list_never_fetched_counts_as_stale(self) -> None:
        assert TrayStatus(threat_list_age_days=None).threat_list_is_stale

    def test_safe_is_the_lowest_priority(self) -> None:
        # If SAFE ever outranks anything, the icon can claim all-clear while
        # something is wrong. Assert the ordering directly.
        assert TrayState.SAFE.priority == max(s.priority for s in TrayState)

    def test_every_state_has_its_own_colour(self) -> None:
        colours = [s.colour for s in TrayState]
        assert len(set(colours)) == len(colours)


# ----------------------------------------------------------------------
# the tooltip carries what the icon could not
# ----------------------------------------------------------------------

class TestTooltip:
    def test_three_simultaneous_truths_all_appear(self) -> None:
        # A scan running, files in the vault, and a stale list. One icon,
        # three facts; the two that lost the priority contest still have to
        # reach the user.
        status = TrayStatus(scanning=True, in_vault=2, threat_list_age_days=9)
        tooltip = status.tooltip()

        assert status.state is TrayState.SCANNING
        assert "somewhere safe" in tooltip
        assert "9 days" in tooltip or "Threat list" in tooltip

    def test_threat_state_still_mentions_the_running_scan(self) -> None:
        status = TrayStatus(unresolved_threats=1, scanning=True)
        assert "scan is running" in status.tooltip()

    def test_clean_tooltip_is_short(self) -> None:
        status = TrayStatus(threat_list_age_days=0, last_scan_at=time.time())
        assert len(status.tooltip().splitlines()) <= 2

    def test_detail_describes_the_same_thing_as_the_headline(self) -> None:
        # A threat headline over a sentence about counting files reads as
        # though the app has lost track of what it is telling you.
        status = TrayStatus(unresolved_threats=1, scanning=True)
        assert "undo" in status.detail.lower()
        assert "counting" not in status.detail.lower()


# ----------------------------------------------------------------------
# words
# ----------------------------------------------------------------------

class TestVocabulary:
    FORBIDDEN: ClassVar[list[str]] = [
        "quarantine", "heuristic", "false positive", "signature database",
        "real-time protection", "scan aborted", "PUP", "malware definition",
    ]

    @pytest.mark.parametrize(
        "status",
        [
            TrayStatus(),
            TrayStatus(unresolved_threats=3),
            TrayStatus(in_vault=2),
            TrayStatus(scanning=True, scan_fraction=0.4, scan_eta_seconds=600),
            TrayStatus(scanning=True, scan_fraction=None),
            TrayStatus(watching=False),
            TrayStatus(threat_list_age_days=30),
            TrayStatus(threat_list_age_days=None),
            TrayStatus(last_scan_at=None),
        ],
    )
    def test_no_jargon_reaches_the_user(self, status: TrayStatus) -> None:
        text = f"{status.headline} {status.detail} {status.tooltip()}".lower()
        for word in self.FORBIDDEN:
            assert word.lower() not in text, f"{word!r} in {text!r}"

    def test_moving_a_file_says_what_did_not_happen(self) -> None:
        # People assume "moved somewhere safe" means deleted. Say otherwise.
        status = TrayStatus(in_vault=1)
        assert "deleted" in status.detail.lower()

    def test_a_threat_says_it_is_reversible(self) -> None:
        status = TrayStatus(unresolved_threats=1)
        assert "undo" in status.detail.lower()

    def test_singular_and_plural(self) -> None:
        assert "1 file" in TrayStatus(in_vault=1).headline
        assert "2 files" in TrayStatus(in_vault=2).headline
        assert "1 thing needs" in TrayStatus(unresolved_threats=1).headline
        assert "2 things need" in TrayStatus(unresolved_threats=2).headline


class TestDescribeAge:
    @pytest.mark.parametrize(
        ("seconds", "expected"),
        [
            (5, "just now"),
            (60, "just now"),
            (600, "10 minutes ago"),
            (3600, "1 hour ago"),
            (7200, "2 hours ago"),
            (86400, "yesterday"),
            (86400 * 3, "3 days ago"),
            (86400 * 90, "3 months ago"),
        ],
    )
    def test_phrasing(self, seconds: float, expected: str) -> None:
        assert describe_age(seconds) == expected


# ----------------------------------------------------------------------
# notification budget
# ----------------------------------------------------------------------

class TestNotificationBudget:
    def test_allows_up_to_the_limit(self) -> None:
        budget = NotificationBudget(limit=3)
        assert [budget.allow(now=0) for _ in range(3)] == [True, True, True]

    def test_coalesces_beyond_the_limit(self) -> None:
        # Ten threats in one scan produce one notification, not ten.
        budget = NotificationBudget(limit=3)
        results = [budget.allow(now=0) for _ in range(10)]
        assert sum(results) == 3
        assert budget.suppressed == 7

    def test_the_window_rolls(self) -> None:
        budget = NotificationBudget(limit=2, window=3600)
        assert budget.allow(now=0)
        assert budget.allow(now=10)
        assert not budget.allow(now=20)
        # An hour later the budget is available again.
        assert budget.allow(now=3700)

    def test_suppressed_count_is_taken_once(self) -> None:
        budget = NotificationBudget(limit=1)
        budget.allow(now=0)
        budget.allow(now=1)
        budget.allow(now=2)
        assert budget.take_suppressed() == 2
        assert budget.take_suppressed() == 0


# ----------------------------------------------------------------------
# the resource line
# ----------------------------------------------------------------------

class TestResourceMeter:
    def test_reports_this_process(self) -> None:
        meter = ResourceMeter()
        if not meter.available:
            pytest.skip("psutil is not installed")

        memory = meter.memory_bytes()
        assert memory is not None
        assert memory > 1024 * 1024  # a Python process is never this small

    def test_describe_has_both_figures(self) -> None:
        meter = ResourceMeter()
        if not meter.available:
            pytest.skip("psutil is not installed")

        text = meter.describe()
        assert "% CPU" in text
        assert "MB" in text

    def test_cpu_keeps_a_decimal_place(self) -> None:
        # The whole point of the line is that 0.4% shows as 0.4%, not as
        # "<1%" and not rounded up to a whole percent.
        meter = ResourceMeter()
        if not meter.available:
            pytest.skip("psutil is not installed")

        text = meter.describe()
        cpu = text.split("%")[0]
        assert "." in cpu
        assert "<" not in text

    def test_degrades_without_psutil(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import sentinel.system.resources as module

        monkeypatch.setattr(module, "PSUTIL_AVAILABLE", False)
        meter = module.ResourceMeter()
        assert not meter.available
        assert meter.sample() == (None, None)
        assert "unavailable" in meter.describe()


# ----------------------------------------------------------------------
# icons
# ----------------------------------------------------------------------

pytest.importorskip("PySide6", reason="the GUI extra is not installed")


@pytest.fixture(scope="module")
def qt_app() -> Any:
    """One offscreen QApplication for the drawing tests."""
    import os

    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication

    app = QApplication.instance() or QApplication([])
    return app


def _greyscale_pixels(state: TrayState, size: int = 16) -> list[int]:
    """Render *state* and flatten it to greyscale luminance over alpha."""
    from PySide6.QtGui import QImage

    from sentinel.ui.icons import render

    image = render(state, size).toImage().convertToFormat(
        QImage.Format.Format_ARGB32
    )
    values: list[int] = []
    for y in range(size):
        for x in range(size):
            colour = image.pixelColor(x, y)
            # Composite onto black so alpha becomes part of the shape, which
            # is what "silhouette" means here.
            alpha = colour.alpha() / 255
            luminance = (
                0.299 * colour.red() + 0.587 * colour.green() + 0.114 * colour.blue()
            )
            values.append(int(luminance * alpha))
    return values


class TestIcons:
    def test_every_state_renders_at_every_size(self, qt_app: Any) -> None:
        from sentinel.ui.icons import ICON_SIZES, render

        for state in TrayState:
            for size in ICON_SIZES:
                pixmap = render(state, size)
                assert not pixmap.isNull()
                assert pixmap.width() == size

    def test_icons_are_not_blank(self, qt_app: Any) -> None:
        for state in TrayState:
            pixels = _greyscale_pixels(state)
            assert sum(pixels) > 0, f"{state} rendered as nothing"

    @pytest.mark.parametrize(
        ("left", "right"),
        [
            (a, b)
            for i, a in enumerate(TrayState)
            for b in list(TrayState)[i + 1:]
        ],
    )
    def test_states_differ_in_greyscale_at_16px(
        self, qt_app: Any, left: TrayState, right: TrayState
    ) -> None:
        # Colour is the least reliable signal at 16 pixels in peripheral
        # vision, so the shapes have to carry it. Strip the colour and check
        # the silhouettes still disagree.
        a = _greyscale_pixels(left)
        b = _greyscale_pixels(right)
        differing = sum(1 for x, y in zip(a, b, strict=True) if abs(x - y) > 24)
        # 30 of 256 is roughly an eighth of the canvas. The measured minimum
        # is 44 (scanning's hole against safe's solid fill), so this leaves
        # headroom without being decorative — a regression that collapsed two
        # silhouettes together would fail it.
        assert differing >= 30, (
            f"{left.value} and {right.value} are nearly identical without "
            f"colour: only {differing} of {len(a)} pixels differ"
        )

    def test_badged_states_change_the_outline(self, qt_app: Any) -> None:
        # The badge has to break the shield's silhouette rather than sit
        # inside it, or it vanishes when the icon is small.
        plain = _greyscale_pixels(TrayState.SAFE)
        badged = _greyscale_pixels(TrayState.THREAT)
        # Bottom-right quadrant, where the badge lives.
        quadrant = [
            i for i in range(len(plain))
            if (i % 16) >= 8 and (i // 16) >= 8
        ]
        changed = sum(1 for i in quadrant if abs(plain[i] - badged[i]) > 24)
        assert changed >= 10

    def test_icon_for_carries_every_size(self, qt_app: Any) -> None:
        from sentinel.ui.icons import ICON_SIZES, icon_for

        icon = icon_for(TrayState.SAFE)
        assert len(icon.availableSizes()) == len(ICON_SIZES)
