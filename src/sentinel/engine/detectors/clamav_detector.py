"""ClamAV integration via the clamd daemon.

We talk to a running ``clamd`` rather than shelling out to ``clamscan``:
loading ClamAV's signature database takes several seconds and hundreds of
megabytes, so spawning it per file is hopeless. The daemon keeps it resident.

Two transports are supported. If the daemon runs on the same machine we send
a path and let it read the file itself (``SCAN``), which avoids copying every
byte through a socket. Otherwise we stream the contents (``INSTREAM``).

Disabled by default: it requires the user to install and run ClamAV.
"""

from __future__ import annotations

import threading
from collections.abc import Sequence
from typing import Any

from sentinel.engine.detectors.base import Detector, ScanTarget, registry
from sentinel.engine.verdict import Detection

try:
    import clamd

    _CLAMD_AVAILABLE = True
except ImportError:  # pragma: no cover - depends on the environment
    clamd = None  # type: ignore[assignment]
    _CLAMD_AVAILABLE = False


#: ClamAV signature name prefixes that indicate something other than malware.
#: These are reported at much lower confidence.
_LOW_CONFIDENCE_PREFIXES = (
    "PUA.",           # potentially unwanted application
    "Heuristics.",    # ClamAV's own heuristics, noisier than its signatures
    "Sanesecurity.",  # third-party spam/phish rules
)


@registry.register
class ClamAVDetector(Detector):
    """Scans files with a ClamAV daemon."""

    name = "clamav"
    description = "Signature scanning via a local or remote clamd daemon"
    priority = 30

    def __init__(self, config: Any = None) -> None:
        super().__init__(config)
        self._local = threading.local()
        self._settings = getattr(config, "detectors", None)
        self._use_path_scan = False
        self._version = ""

    # -- connection ----------------------------------------------------

    def _connect(self) -> Any:
        """Build a clamd client from configuration."""
        socket_path = getattr(self._settings, "clamd_socket", None)
        timeout = getattr(self._settings, "clamd_timeout", 30.0)

        if socket_path:
            return clamd.ClamdUnixSocket(path=socket_path, timeout=timeout)

        host = getattr(self._settings, "clamd_host", "127.0.0.1")
        port = getattr(self._settings, "clamd_port", 3310)
        return clamd.ClamdNetworkSocket(host=host, port=port, timeout=timeout)

    @property
    def client(self) -> Any:
        """Per-thread clamd client. The library's sockets are not shareable."""
        client = getattr(self._local, "client", None)
        if client is None:
            client = self._connect()
            self._local.client = client
        return client

    def available(self) -> bool:
        if not _CLAMD_AVAILABLE:
            self._unavailable_reason = (
                "clamd is not installed (pip install 'sentinel-scan[clamav]')"
            )
            return False
        return True

    def setup(self) -> None:
        try:
            self._version = self.client.version().strip()
        except Exception as exc:
            self._unavailable_reason = f"cannot reach clamd: {exc}"
            raise RuntimeError(self._unavailable_reason) from exc

        # Decide whether the daemon can read our files directly. A unix
        # socket means same machine; a loopback address almost certainly does
        # too. Anything else gets INSTREAM.
        socket_path = getattr(self._settings, "clamd_socket", None)
        host = getattr(self._settings, "clamd_host", "127.0.0.1")
        self._use_path_scan = bool(socket_path) or host in {"127.0.0.1", "::1", "localhost"}

        self.log.debug(
            "connected to %s (path scanning: %s)", self._version, self._use_path_scan
        )

    def teardown(self) -> None:
        self._local = threading.local()

    # -- scanning ------------------------------------------------------

    def interested_in(self, target: ScanTarget) -> bool:
        # ClamAV handles every format including archives, and does it in C.
        # Let it see everything.
        return target.size > 0

    def scan(self, target: ScanTarget) -> Sequence[Detection]:
        try:
            if self._use_path_scan and target.depth == 0:
                raw = self.client.scan(str(target.path.resolve()))
            else:
                data = target.data
                if data is None:
                    return ()
                raw = self.client.instream(_BytesReader(data))
        except Exception as exc:
            # Daemon restarts and permission errors are routine. Drop the
            # cached socket so the next file reconnects.
            self._local.client = None
            self.log.debug("clamd scan failed for %s: %s", target.display_path, exc)
            return ()

        return self._parse(raw, target)

    def _parse(self, raw: Any, target: ScanTarget) -> list[Detection]:
        """Translate clamd's ``{path: (status, signature)}`` reply."""
        if not raw:
            return []

        out: list[Detection] = []
        for status_pair in raw.values():
            if not status_pair or len(status_pair) < 2:
                continue
            status, signature = status_pair[0], status_pair[1]

            if status == "ERROR":
                self.log.debug("clamd error on %s: %s", target.display_path, signature)
                continue
            if status != "FOUND" or not signature:
                continue

            low_confidence = signature.startswith(_LOW_CONFIDENCE_PREFIXES)
            out.append(
                self.detection(
                    signature,
                    45.0 if low_confidence else 95.0,
                    (
                        "ClamAV flagged this as potentially unwanted rather than "
                        "outright malicious."
                        if low_confidence
                        else "Matched a ClamAV malware signature."
                    ),
                    # A real ClamAV signature hit is definitive; its PUA and
                    # heuristic rules are not.
                    conclusive=not low_confidence,
                    signature=signature,
                    engine_version=self._version,
                )
            )
        return out


class _BytesReader:
    """Minimal file-like wrapper so clamd can stream an in-memory buffer."""

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._offset = 0

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            chunk = self._data[self._offset :]
            self._offset = len(self._data)
            return chunk
        chunk = self._data[self._offset : self._offset + size]
        self._offset += len(chunk)
        return chunk
