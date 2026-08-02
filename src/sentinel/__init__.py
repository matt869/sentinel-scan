"""Sentinel Scan — a cross-platform malware scanner.

The package is layered; each layer may only import from the ones above it:

    utils      pure helpers, no internal imports
    core       configuration, logging, events, local database
    signatures signature loading and updating
    engine     detectors, traversal, scheduling, quarantine
    system     OS inspection (processes, autoruns, drives)
    feedback   optional reporting to a server
    cli / ui   user-facing front ends

Typical programmatic use::

    from sentinel import Scanner, load_config

    scanner = Scanner(load_config())
    result = scanner.scan_paths(["C:/Users/me/Downloads"])
    for finding in result.threats:
        print(finding.path, finding.severity, finding.top_detection)
"""

from __future__ import annotations

from sentinel.version import __version__

__all__ = ["Scanner", "Severity", "__version__", "load_config"]


def __getattr__(name: str):
    """Expose the main entry points lazily.

    Importing :mod:`sentinel` should stay cheap — the CLI's ``--help`` must
    not pay for loading YARA, pefile or the detector registry. The heavy
    imports only happen when someone actually touches these names.
    """
    if name == "Scanner":
        from sentinel.engine.scanner import Scanner

        return Scanner
    if name == "load_config":
        from sentinel.core.config import load_config

        return load_config
    if name == "Severity":
        from sentinel.engine.verdict import Severity

        return Severity
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
