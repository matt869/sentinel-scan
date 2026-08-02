"""Desktop interface (PySide6).

Importing this package does **not** import PySide6 — the CLI must stay
usable on a machine with no Qt installed. :func:`sentinel.ui.app.main` checks
for it and prints an install hint if it is missing.
"""

from __future__ import annotations

__all__ = ["is_available", "main"]


def is_available() -> bool:
    """True if PySide6 can be imported."""
    try:
        import PySide6  # noqa: F401
    except ImportError:
        return False
    return True


def main(config_file: str | None = None) -> int:
    """Launch the GUI. Returns a process exit code."""
    from sentinel.ui.app import main as _main

    return _main(config_file)
