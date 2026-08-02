"""Exact-hash lookup against the known-sample database.

This is the cheapest and most reliable detector, so it runs first: a hit is
conclusive and lets the engine skip the expensive detectors entirely.

The database is a SQLite file built by ``scripts/build_hash_db.py`` from
public malware hash feeds. Lookups go md5 → sha1 → sha256, because most feeds
are still keyed on md5 and it is the shortest index.
"""

from __future__ import annotations

from collections.abc import Sequence

from sentinel.engine.detectors.base import Detector, ScanTarget, registry
from sentinel.engine.verdict import Detection, Severity
from sentinel.signatures.loader import HashDatabase, SignatureStore

#: The EICAR anti-malware test file. Not malware — a 68-byte string every
#: scanner is expected to flag so users can verify their tooling works.
#: Built in so a fresh install detects it before any signature download.
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
EICAR_MD5 = "44d88612fea8a8f36de82e1278abb02f"

BUILTIN_HASHES: dict[str, tuple[str, Severity]] = {
    EICAR_SHA256: ("EICAR-Test-File", Severity.MEDIUM),
    EICAR_MD5: ("EICAR-Test-File", Severity.MEDIUM),
}

#: Confidence assigned per severity recorded in the signature database.
_CONFIDENCE_BY_SEVERITY = {
    Severity.CRITICAL: 100.0,
    Severity.HIGH: 95.0,
    Severity.MEDIUM: 85.0,
    Severity.LOW: 50.0,
    Severity.CLEAN: 0.0,
}


@registry.register
class HashDetector(Detector):
    """Matches file digests against the known-bad hash database."""

    name = "hash"
    description = "Exact match against the known-malware hash database"
    priority = 10  # cheapest and most decisive: always first
    wants = frozenset()  # every file type

    def __init__(self, config=None) -> None:
        super().__init__(config)
        self._db: HashDatabase | None = None
        self._store: SignatureStore | None = None

    def available(self) -> bool:
        # Always available: the built-in table works with no database at all.
        return True

    def setup(self) -> None:
        self._store = SignatureStore(self.config)
        path = self._store.hash_db_path
        if path is None or not path.is_file():
            self.log.info(
                "no hash database found; using %d built-in signatures only. "
                "Run `sentinel update` to download the full set.",
                len(BUILTIN_HASHES),
            )
            return
        try:
            self._db = HashDatabase(path)
            self.log.debug("loaded %d hash signatures from %s", len(self._db), path)
        except Exception as exc:
            self.log.warning("hash database at %s unusable: %s", path, exc)
            self._db = None

    def teardown(self) -> None:
        if self._db is not None:
            self._db.close()
            self._db = None

    def scan(self, target: ScanTarget) -> Sequence[Detection]:
        hashes = target.hashes
        if not hashes:
            return ()

        # Built-in table first — it is a dict lookup and covers EICAR.
        for algorithm in ("sha256", "md5"):
            digest = hashes.get(algorithm, "")
            hit = BUILTIN_HASHES.get(digest)
            if hit:
                threat_name, severity = hit
                return (
                    self.detection(
                        threat_name,
                        _CONFIDENCE_BY_SEVERITY[severity],
                        "Matches a built-in test signature",
                        # EICAR is deliberately harmless, so it is a definite
                        # identification but not an emergency.
                        conclusive=severity >= Severity.HIGH,
                        algorithm=algorithm,
                        digest=digest,
                        source="builtin",
                    ),
                )

        if self._db is None:
            return ()

        try:
            entry = self._db.lookup(
                md5=hashes.get("md5", ""),
                sha1=hashes.get("sha1", ""),
                sha256=hashes.get("sha256", ""),
            )
        except Exception as exc:
            self.log.debug("hash lookup failed for %s: %s", target.path, exc)
            return ()

        if entry is None:
            return ()

        severity = Severity(entry.severity)
        return (
            self.detection(
                entry.name,
                _CONFIDENCE_BY_SEVERITY.get(severity, 90.0),
                f"Exact {entry.algorithm} match against a known sample",
                conclusive=severity >= Severity.HIGH,
                algorithm=entry.algorithm,
                digest=entry.digest,
                source=entry.source,
                first_seen=entry.first_seen,
            ),
        )
