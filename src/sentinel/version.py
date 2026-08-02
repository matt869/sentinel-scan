"""Single source of truth for the package version.

``pyproject.toml`` reads ``__version__`` from here via setuptools' dynamic
version support, so this file must stay importable without any third-party
dependency at build time.
"""

from __future__ import annotations

__version__ = "0.4.0"

#: Schema version of the local SQLite database. Bump whenever a migration is
#: added in :mod:`sentinel.core.db`.
DB_SCHEMA_VERSION = 3

#: Version of the JSON report format emitted by ``sentinel scan --json`` and
#: accepted by the reporting server. Bump on any breaking field change.
REPORT_FORMAT_VERSION = 2

#: User-Agent sent with every outbound HTTP request.
USER_AGENT = f"sentinel-scan/{__version__}"


def version_tuple() -> tuple[int, ...]:
    """Return the version as a comparable tuple of integers."""
    return tuple(int(part) for part in __version__.split(".") if part.isdigit())
