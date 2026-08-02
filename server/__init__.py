"""Sentinel Scan reporting server.

An optional companion service. The scanner works completely without it; the
server exists so a deployment can collect false-positive reports, serve hash
reputation and receive anonymous telemetry.

It is a separate top-level package from ``sentinel`` on purpose — the client
never imports it, and it is not installed by ``pip install sentinel-scan``.
"""

__all__: list[str] = []
