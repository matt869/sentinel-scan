"""Shannon entropy helpers used by the packing/obfuscation heuristics.

High entropy on its own is *not* evidence of malware — compressed archives,
encrypted containers and media files are all near-maximal. The value here is
used as one weak signal among several, and the callers weight it accordingly.
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass

# Entropy is measured in bits per byte, so the range is [0.0, 8.0].
MAX_ENTROPY = 8.0

# Empirical thresholds, calibrated against the corpus described in
# docs/detection-rates.md. Plain text and source code sit under 5.0; native
# code sits around 6.0-6.8; packed, compressed or encrypted data is above 7.2.
TEXT_CEILING = 5.0
NATIVE_CODE_CEILING = 6.8
PACKED_FLOOR = 7.2
ENCRYPTED_FLOOR = 7.9


@dataclass(frozen=True, slots=True)
class EntropyProfile:
    """Summary of how entropy is distributed across a buffer."""

    overall: float
    chunks: tuple[float, ...]
    peak: float
    mean: float
    #: Fraction of chunks above :data:`PACKED_FLOOR`.
    packed_ratio: float

    @property
    def is_uniformly_high(self) -> bool:
        """True when *every* region is high — typical of a fully packed file."""
        return bool(self.chunks) and min(self.chunks) >= PACKED_FLOOR

    @property
    def has_packed_region(self) -> bool:
        """True when a high-entropy blob sits inside otherwise normal data.

        This is the more interesting shape: an installer or dropper with an
        encrypted payload appended to an ordinary-looking executable.
        """
        return self.packed_ratio > 0.0 and not self.is_uniformly_high


def shannon_entropy(data: bytes) -> float:
    """Return the Shannon entropy of *data* in bits per byte.

    An empty buffer has zero entropy by convention.
    """
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum(
        (count / length) * math.log2(count / length) for count in counts.values()
    )


def chunk_entropy(data: bytes, chunk_size: int = 4096) -> list[float]:
    """Return the entropy of each fixed-size block of *data*.

    A trailing block shorter than ``chunk_size // 4`` is dropped: entropy is
    unreliable on tiny samples (a 16-byte block cannot exceed 4 bits/byte no
    matter how random it is).
    """
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")
    minimum = max(chunk_size // 4, 1)
    out = []
    for offset in range(0, len(data), chunk_size):
        block = data[offset : offset + chunk_size]
        if len(block) < minimum and offset > 0:
            break
        out.append(shannon_entropy(block))
    return out


def profile(data: bytes, chunk_size: int = 4096) -> EntropyProfile:
    """Build an :class:`EntropyProfile` for *data*."""
    chunks = chunk_entropy(data, chunk_size)
    if not chunks:
        overall = shannon_entropy(data)
        return EntropyProfile(overall, (), overall, overall, 0.0)
    packed = sum(1 for c in chunks if c >= PACKED_FLOOR)
    return EntropyProfile(
        overall=shannon_entropy(data),
        chunks=tuple(chunks),
        peak=max(chunks),
        mean=sum(chunks) / len(chunks),
        packed_ratio=packed / len(chunks),
    )


def entropy_verdict(value: float) -> str:
    """Map an entropy value onto a human-readable band."""
    if value >= ENCRYPTED_FLOOR:
        return "encrypted or random"
    if value >= PACKED_FLOOR:
        return "packed or compressed"
    if value >= NATIVE_CODE_CEILING:
        return "native code"
    if value >= TEXT_CEILING:
        return "mixed content"
    return "plain text"


def normalized(value: float) -> float:
    """Scale an entropy value into the 0.0-1.0 range."""
    return max(0.0, min(value / MAX_ENTROPY, 1.0))
