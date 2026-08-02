"""Logging setup.

Two sinks: a Rich-formatted console handler for humans, and a rotating file
handler that keeps the last few megabytes of history for bug reports.

Log records must never contain file *contents*. Paths are logged, contents
are not — see docs/privacy.md.
"""

from __future__ import annotations

import logging
import logging.handlers
import os
import sys
from pathlib import Path

from rich.console import Console
from rich.logging import RichHandler

from sentinel.version import __version__

LOGGER_NAME = "sentinel"

_configured = False

#: Shared console. The CLI reuses it so progress bars and log lines cannot
#: interleave badly.
console = Console(stderr=True)


class _RedactingFilter(logging.Filter):
    """Strip the user's home directory from messages when redaction is on.

    Bug reports are frequently pasted into public issue trackers, and a full
    path leaks the account name. Enabled by ``SENTINEL_REDACT_PATHS=1``.
    """

    def __init__(self) -> None:
        super().__init__()
        self.home = str(Path.home())

    def filter(self, record: logging.LogRecord) -> bool:
        if self.home and isinstance(record.msg, str) and self.home in record.msg:
            record.msg = record.msg.replace(self.home, "~")
        return True


def setup_logging(
    level: str = "INFO",
    log_file: str | os.PathLike[str] | None = None,
    *,
    quiet: bool = False,
    force: bool = False,
) -> logging.Logger:
    """Configure the ``sentinel`` logger tree.

    Safe to call more than once; subsequent calls are ignored unless *force*
    is set (the GUI calls it again after the user changes the log level).

    Args:
        level: Root level name, e.g. ``"DEBUG"``.
        log_file: Destination for the rotating file handler. None disables it.
        quiet: Suppress console output below WARNING (used with ``--json``,
            where stdout must stay machine-readable).
        force: Tear down existing handlers and reconfigure.
    """
    global _configured

    logger = logging.getLogger(LOGGER_NAME)
    if _configured and not force:
        return logger

    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()

    numeric = getattr(logging, level.upper(), logging.INFO)
    logger.setLevel(numeric)
    # The root logger stays untouched so we never capture third-party noise.
    logger.propagate = False

    console_handler = RichHandler(
        console=console,
        rich_tracebacks=True,
        show_path=False,
        show_time=numeric <= logging.DEBUG,
        markup=False,
        # Paths and rule names contain brackets and backslashes; leave them be.
        highlighter=None,
    )
    console_handler.setLevel(logging.WARNING if quiet else numeric)
    console_handler.setFormatter(logging.Formatter("%(message)s", datefmt="[%X]"))
    logger.addHandler(console_handler)

    if log_file is not None:
        path = Path(log_file)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.handlers.RotatingFileHandler(
                path, maxBytes=2 * 1024 * 1024, backupCount=3, encoding="utf-8"
            )
            file_handler.setLevel(numeric)
            file_handler.setFormatter(
                logging.Formatter(
                    "%(asctime)s %(levelname)-8s %(name)s %(threadName)s: %(message)s"
                )
            )
            logger.addHandler(file_handler)
        except OSError as exc:
            # A read-only data dir must not stop a scan.
            logger.warning("file logging disabled: %s", exc)

    if os.environ.get("SENTINEL_REDACT_PATHS", "").strip().lower() in {"1", "true", "yes"}:
        logger.addFilter(_RedactingFilter())

    _configured = True
    logger.debug("sentinel %s starting on %s (python %s)",
                 __version__, sys.platform, sys.version.split()[0])
    return logger


def get_logger(name: str | None = None) -> logging.Logger:
    """Return a child logger under the ``sentinel`` namespace.

    Pass ``__name__`` from a module inside the package and the redundant
    ``sentinel.`` prefix is stripped automatically.
    """
    if not name or name == LOGGER_NAME:
        return logging.getLogger(LOGGER_NAME)
    suffix = name[len(LOGGER_NAME) + 1 :] if name.startswith(LOGGER_NAME + ".") else name
    return logging.getLogger(f"{LOGGER_NAME}.{suffix}")


def set_level(level: str) -> None:
    """Change the level of the logger and all its handlers at runtime."""
    numeric = getattr(logging, level.upper(), logging.INFO)
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(numeric)
    for handler in logger.handlers:
        handler.setLevel(numeric)


def reset_logging() -> None:
    """Remove all handlers. Used by tests to avoid cross-test leakage."""
    global _configured
    logger = logging.getLogger(LOGGER_NAME)
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()
    for filt in list(logger.filters):
        logger.removeFilter(filt)
    _configured = False
