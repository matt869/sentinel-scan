"""Formatting helpers for human-facing output (CLI tables, GUI labels, logs)."""

from __future__ import annotations

import os
from pathlib import Path

_BYTE_UNITS = ("B", "KiB", "MiB", "GiB", "TiB", "PiB")


def human_bytes(size: float, precision: int = 1) -> str:
    """Format a byte count using binary units.

    >>> human_bytes(0)
    '0 B'
    >>> human_bytes(1536)
    '1.5 KiB'
    """
    if size < 0:
        return "-" + human_bytes(-size, precision)
    value = float(size)
    for unit in _BYTE_UNITS:
        if value < 1024.0 or unit == _BYTE_UNITS[-1]:
            if unit == "B":
                return f"{int(value)} B"
            return f"{value:.{precision}f} {unit}"
        value /= 1024.0
    raise AssertionError("unreachable")


def human_duration(seconds: float) -> str:
    """Format a duration compactly.

    >>> human_duration(0.42)
    '420ms'
    >>> human_duration(3672)
    '1h 1m 12s'
    """
    if seconds < 0:
        return "-" + human_duration(-seconds)
    if seconds < 1:
        return f"{seconds * 1000:.0f}ms"
    if seconds < 60:
        return f"{seconds:.1f}s"

    total = int(seconds)
    hours, remainder = divmod(total, 3600)
    minutes, secs = divmod(remainder, 60)
    if hours:
        return f"{hours}h {minutes}m {secs}s"
    return f"{minutes}m {secs}s"


def human_count(value: int, singular: str, plural: str | None = None) -> str:
    """Pluralise a count.

    >>> human_count(1, "file")
    '1 file'
    >>> human_count(3, "file")
    '3 files'
    """
    if value == 1:
        return f"{value:,} {singular}"
    return f"{value:,} {plural or singular + 's'}"


def human_rate(count: float, seconds: float, unit: str = "files") -> str:
    """Format a throughput figure, guarding against a zero-length interval."""
    if seconds <= 0:
        return f"— {unit}/s"
    return f"{count / seconds:,.0f} {unit}/s"


def shorten_path(path: str | os.PathLike[str], max_length: int = 60) -> str:
    """Abbreviate a path for fixed-width display, keeping both ends readable.

    The filename is never truncated — if it alone exceeds *max_length* the
    result is just the filename, since that is the part a user identifies a
    finding by.
    """
    text = str(path)
    if len(text) <= max_length:
        return text

    p = Path(text)
    name = p.name
    if len(name) + 4 >= max_length:
        return name

    # Drop interior components until it fits, keeping the anchor (drive or
    # leading separator) and as many trailing directories as possible.
    parts = list(p.parts)
    anchor = parts[0] if p.anchor else ""
    middle = parts[1:-1] if p.anchor else parts[:-1]

    while middle:
        middle.pop(0)
        candidate = os.path.join(anchor, "...", *middle, name) if anchor else os.path.join(
            "...", *middle, name
        )
        if len(candidate) <= max_length:
            return candidate
    return os.path.join(anchor, "...", name) if anchor else os.path.join("...", name)


def percent(part: float, whole: float, precision: int = 1) -> str:
    """Format a ratio as a percentage, tolerating a zero denominator."""
    if whole <= 0:
        return "—"
    return f"{(part / whole) * 100:.{precision}f}%"


def truncate(text: str, max_length: int = 80, suffix: str = "…") -> str:
    """Clip *text* to *max_length* characters including the ellipsis."""
    if len(text) <= max_length:
        return text
    return text[: max(max_length - len(suffix), 0)] + suffix


def plural_verdict(threats: int) -> str:
    """Headline sentence for the end of a scan."""
    if threats == 0:
        return "No threats found"
    if threats == 1:
        return "1 threat found"
    return f"{threats:,} threats found"
