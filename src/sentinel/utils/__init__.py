"""Small, dependency-free helpers shared across the code base.

Nothing in here may import from :mod:`sentinel.core`, :mod:`sentinel.engine`
or any other sibling package — these are the leaves of the dependency graph
and are safe to import from anywhere.
"""

from sentinel.utils.entropy import chunk_entropy, entropy_verdict, shannon_entropy
from sentinel.utils.file_types import FileType, guess_type, is_executable_type, sniff_magic
from sentinel.utils.hashing import (
    hash_bytes,
    hash_file,
    hash_file_multi,
    quick_fingerprint,
)
from sentinel.utils.humanize import (
    human_bytes,
    human_count,
    human_duration,
    shorten_path,
)

__all__ = [
    "FileType",
    "chunk_entropy",
    "entropy_verdict",
    "guess_type",
    "hash_bytes",
    "hash_file",
    "hash_file_multi",
    "human_bytes",
    "human_count",
    "human_duration",
    "is_executable_type",
    "quick_fingerprint",
    "shannon_entropy",
    "shorten_path",
    "sniff_magic",
]
