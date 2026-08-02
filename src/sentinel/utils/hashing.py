"""Streaming file hashing.

Hashing dominates the cost of a full-disk scan, so everything here reads in
fixed-size chunks and never loads a whole file into memory. All functions
return lowercase hex digests.
"""

from __future__ import annotations

import hashlib
import os
from collections.abc import Iterable
from pathlib import Path
from typing import BinaryIO

# 1 MiB reads: large enough to amortise syscall overhead, small enough to stay
# out of the large-object allocator on every platform we target.
CHUNK_SIZE = 1024 * 1024

# Algorithms we are willing to compute. md5/sha1 are here because virtually
# every public malware feed is still keyed on them — never for integrity.
SUPPORTED_ALGORITHMS = ("md5", "sha1", "sha256")

DEFAULT_ALGORITHM = "sha256"


class HashError(OSError):
    """Raised when a file could not be hashed."""


def _new(algorithm: str):
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(
            f"unsupported hash algorithm {algorithm!r}; "
            f"expected one of {', '.join(SUPPORTED_ALGORITHMS)}"
        )
    # usedforsecurity=False keeps md5/sha1 working on FIPS-enabled builds,
    # where they are otherwise rejected outright.
    try:
        return hashlib.new(algorithm, usedforsecurity=False)
    except TypeError:  # pragma: no cover - Python < 3.9 fallback
        return hashlib.new(algorithm)


def hash_bytes(data: bytes, algorithm: str = DEFAULT_ALGORITHM) -> str:
    """Return the digest of an in-memory buffer."""
    h = _new(algorithm)
    h.update(data)
    return h.hexdigest()


def hash_stream(stream: BinaryIO, algorithm: str = DEFAULT_ALGORITHM) -> str:
    """Return the digest of everything remaining in an open binary stream."""
    h = _new(algorithm)
    for chunk in iter(lambda: stream.read(CHUNK_SIZE), b""):
        h.update(chunk)
    return h.hexdigest()


def hash_file(path: str | os.PathLike[str], algorithm: str = DEFAULT_ALGORITHM) -> str:
    """Return the digest of a file on disk.

    Raises:
        HashError: the file could not be opened or read.
    """
    return hash_file_multi(path, [algorithm])[algorithm]


def hash_file_multi(
    path: str | os.PathLike[str],
    algorithms: Iterable[str] = SUPPORTED_ALGORITHMS,
) -> dict[str, str]:
    """Compute several digests of a file in a single pass over the bytes.

    Computing md5 + sha1 + sha256 together costs barely more than sha256
    alone, because the read is the expensive part, not the compression
    function.

    Returns:
        Mapping of algorithm name to hex digest.

    Raises:
        HashError: the file could not be opened or read.
    """
    algos = list(algorithms)
    if not algos:
        return {}
    hashers = {name: _new(name) for name in algos}
    try:
        with open(path, "rb", buffering=0) as fh:
            for chunk in iter(lambda: fh.read(CHUNK_SIZE), b""):
                for h in hashers.values():
                    h.update(chunk)
    except OSError as exc:
        raise HashError(f"cannot hash {path}: {exc}") from exc
    return {name: h.hexdigest() for name, h in hashers.items()}


def quick_fingerprint(path: str | os.PathLike[str], sample_size: int = 8192) -> str:
    """Cheap identity token for cache lookups — *not* a security hash.

    Digests the file size plus the head and tail of the file. Two different
    files can collide, so this is only ever used to decide whether a cached
    scan result is still worth trusting, never to decide that a file is clean.
    """
    p = Path(path)
    try:
        size = p.stat().st_size
        h = _new("sha256")
        h.update(str(size).encode("ascii"))
        with open(p, "rb", buffering=0) as fh:
            h.update(fh.read(sample_size))
            if size > sample_size * 2:
                fh.seek(-sample_size, os.SEEK_END)
                h.update(fh.read(sample_size))
    except OSError as exc:
        raise HashError(f"cannot fingerprint {path}: {exc}") from exc
    return h.hexdigest()


def is_hex_digest(value: str, algorithm: str = DEFAULT_ALGORITHM) -> bool:
    """True if *value* looks like a hex digest of the given algorithm."""
    expected = {"md5": 32, "sha1": 40, "sha256": 64}.get(algorithm)
    if expected is None or len(value) != expected:
        return False
    return all(c in "0123456789abcdefABCDEF" for c in value)


def detect_algorithm(digest: str) -> str | None:
    """Infer the algorithm from a digest's length, or None if ambiguous."""
    return {32: "md5", 40: "sha1", 64: "sha256"}.get(len(digest.strip()))
