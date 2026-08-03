"""YARA rule matching.

Rules come from two places: the bundled set under
``src/sentinel/signatures/local/rules`` plus whatever the updater has
downloaded, and an optional user directory
(``detectors.yara_rules_dir``).

Compilation happens once per scan in :meth:`setup`. The compiled
``yara.Rules`` object is safe to call from multiple threads, so all workers
share it.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from sentinel.engine.detectors.base import Detector, ScanTarget, registry
from sentinel.engine.verdict import Detection
from sentinel.signatures.loader import SignatureStore

try:
    import yara

    _YARA_AVAILABLE = True
except ImportError:  # pragma: no cover - depends on the environment
    yara = None  # type: ignore[assignment]
    _YARA_AVAILABLE = False


#: Rule metadata may declare its own confidence; otherwise severity tags map
#: to these values. Rules without either get the default.
_TAG_CONFIDENCE = {
    "critical": 95.0,
    "malware": 90.0,
    "trojan": 90.0,
    "ransomware": 95.0,
    "backdoor": 90.0,
    "exploit": 85.0,
    "packer": 35.0,
    "suspicious": 45.0,
    "pua": 40.0,
    "info": 10.0,
}
_DEFAULT_CONFIDENCE = 70.0

#: Cap on matched strings recorded per rule. Metadata is stored in the
#: database and shipped in reports; unbounded excerpts would leak file
#: contents and bloat the report.
_MAX_STRING_MATCHES = 8
_MAX_EXCERPT_BYTES = 32


@registry.register
class YaraDetector(Detector):
    """Runs the compiled YARA rule set against file contents."""

    name = "yara"
    description = "Pattern matching with YARA rules"
    priority = 40

    def __init__(self, config: Any = None) -> None:
        super().__init__(config)
        self._rules: Any = None
        self._timeout = 20
        self._rule_count = 0

    def available(self) -> bool:
        if not _YARA_AVAILABLE:
            self._unavailable_reason = (
                "yara-python is not installed (pip install 'sentinel-scan[yara]')"
            )
            return False
        return True

    def setup(self) -> None:
        store = SignatureStore(self.config)
        sources = store.yara_rule_files()
        if not sources:
            self._unavailable_reason = "no YARA rules found"
            self.log.info("no YARA rules available; detector idle")
            return

        detectors_cfg = getattr(self.config, "detectors", None)
        if detectors_cfg is not None:
            self._timeout = getattr(detectors_cfg, "yara_timeout", 20)
            budget = int(getattr(detectors_cfg, "yara_file_budget", 0) or 0)
            if budget and len(sources) > budget:
                # Compiling twenty thousand rules costs real memory on a
                # machine that has none to spare. Files are kept in the
                # order the store returns them, which puts the bundled
                # high-value set before anything downloaded in bulk.
                self.log.info(
                    "compiling %d of %d rule files to fit this machine",
                    budget, len(sources),
                )
                sources = sources[:budget]

        # Namespace each file by its stem so rule name collisions between
        # third-party rule sets do not abort the whole compile.
        namespaces = {path.stem: str(path) for path in sources}
        try:
            self._rules = yara.compile(filepaths=namespaces)
        except yara.Error as exc:
            # One malformed file should not cost us the entire rule set.
            self.log.warning("bulk YARA compile failed (%s); compiling one by one", exc)
            self._rules = self._compile_individually(namespaces)

        if self._rules is not None:
            self._rule_count = len(sources)
            self.log.debug("compiled YARA rules from %d file(s)", self._rule_count)

    def _compile_individually(self, namespaces: dict[str, str]) -> Any:
        """Compile file by file, dropping the ones that fail."""
        good: dict[str, str] = {}
        for namespace, path in namespaces.items():
            try:
                yara.compile(filepath=path)
            except yara.Error as exc:
                self.log.warning("skipping unusable rule file %s: %s", path, exc)
                continue
            good[namespace] = path
        if not good:
            return None
        try:
            return yara.compile(filepaths=good)
        except yara.Error as exc:  # pragma: no cover - should not happen
            self.log.error("YARA rules could not be compiled: %s", exc)
            return None

    def teardown(self) -> None:
        self._rules = None

    def interested_in(self, target: ScanTarget) -> bool:
        # Rules can match anything, but there is no point running them on a
        # file we could not buffer.
        return self._rules is not None and target.data is not None

    def scan(self, target: ScanTarget) -> Sequence[Detection]:
        if self._rules is None:
            return ()
        data = target.data
        if data is None:
            return ()

        try:
            matches = self._rules.match(data=data, timeout=self._timeout)
        except Exception as exc:
            # yara.TimeoutError on a pathological file, or yara.Error on a
            # rule that misbehaves. Neither should fail the scan.
            self.log.debug("YARA match failed on %s: %s", target.display_path, exc)
            return ()

        return [self._to_detection(match) for match in matches]

    def _to_detection(self, match: Any) -> Detection:
        meta = dict(getattr(match, "meta", {}) or {})
        tags = list(getattr(match, "tags", []) or [])

        confidence = self._confidence_for(meta, tags)
        description = str(
            meta.get("description") or meta.get("desc") or f"YARA rule {match.rule} matched"
        )

        return self.detection(
            str(meta.get("threat_name") or match.rule),
            confidence,
            description,
            rule=match.rule,
            namespace=getattr(match, "namespace", ""),
            tags=tags,
            author=str(meta.get("author", "")),
            reference=str(meta.get("reference", "")),
            strings=_summarise_strings(match),
        )

    def _confidence_for(self, meta: dict[str, Any], tags: list[str]) -> float:
        """Resolve a confidence from rule metadata, then tags, then default."""
        raw = meta.get("confidence", meta.get("score"))
        if raw is not None:
            try:
                return max(0.0, min(float(raw), 100.0))
            except (TypeError, ValueError):
                self.log.debug("rule declared non-numeric confidence %r", raw)

        for tag in tags:
            if tag.lower() in _TAG_CONFIDENCE:
                return _TAG_CONFIDENCE[tag.lower()]

        severity = str(meta.get("severity", "")).lower()
        if severity in _TAG_CONFIDENCE:
            return _TAG_CONFIDENCE[severity]

        return _DEFAULT_CONFIDENCE


def _summarise_strings(match: Any) -> list[dict[str, Any]]:
    """Extract a bounded, redacted summary of which strings matched.

    yara-python changed this API in 4.3: ``match.strings`` used to be a list
    of ``(offset, identifier, data)`` tuples and is now a list of
    ``StringMatch`` objects. Both shapes are handled.
    """
    out: list[dict[str, Any]] = []
    raw = getattr(match, "strings", None) or []

    for item in raw[:_MAX_STRING_MATCHES]:
        if isinstance(item, tuple) and len(item) == 3:  # yara-python < 4.3
            offset, identifier, data = item
            out.append(
                {
                    "identifier": str(identifier),
                    "offset": int(offset),
                    "excerpt": _excerpt(data),
                }
            )
            continue

        identifier = str(getattr(item, "identifier", "?"))
        instances = list(getattr(item, "instances", []))[:2]
        for instance in instances:
            out.append(
                {
                    "identifier": identifier,
                    "offset": int(getattr(instance, "offset", 0)),
                    "excerpt": _excerpt(getattr(instance, "matched_data", b"")),
                }
            )
        if not instances:
            out.append({"identifier": identifier, "offset": -1, "excerpt": ""})

    return out[:_MAX_STRING_MATCHES]


def _excerpt(data: Any) -> str:
    """Render a short, printable excerpt of matched bytes."""
    if isinstance(data, str):
        data = data.encode("utf-8", errors="replace")
    if not isinstance(data, (bytes, bytearray)):
        return ""
    clipped = bytes(data[:_MAX_EXCERPT_BYTES])
    return clipped.decode("ascii", errors="backslashreplace")
