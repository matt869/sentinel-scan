"""Detector implementations.

Importing this package registers every built-in detector with the shared
:data:`~sentinel.engine.detectors.base.registry`. The engine then asks the
registry to build the enabled subset.

To add your own, subclass :class:`Detector`, decorate it with
``@registry.register`` and import the module. See docs/writing-detectors.md.
"""

# Import for the registration side effect. Order does not matter; the
# registry sorts by the `priority` class attribute.
from sentinel.engine.detectors.archive_detector import ArchiveDetector
from sentinel.engine.detectors.base import (
    Detector,
    DetectorRegistry,
    ScanTarget,
    registry,
)
from sentinel.engine.detectors.clamav_detector import ClamAVDetector
from sentinel.engine.detectors.cloud_detector import CloudDetector
from sentinel.engine.detectors.hash_detector import HashDetector
from sentinel.engine.detectors.pe_heuristic import PEHeuristicDetector
from sentinel.engine.detectors.script_detector import ScriptDetector
from sentinel.engine.detectors.yara_detector import YaraDetector

__all__ = [
    "ArchiveDetector",
    "ClamAVDetector",
    "CloudDetector",
    "Detector",
    "DetectorRegistry",
    "HashDetector",
    "PEHeuristicDetector",
    "ScanTarget",
    "ScriptDetector",
    "YaraDetector",
    "registry",
]
