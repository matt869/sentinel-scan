"""Signature data: where it lives, how it is loaded, how it is updated."""

from sentinel.signatures.loader import (
    BUNDLED_DIR,
    HashDatabase,
    HashEntry,
    SignatureStore,
)
from sentinel.signatures.updater import SignatureUpdater, UpdateError, UpdateResult

__all__ = [
    "BUNDLED_DIR",
    "HashDatabase",
    "HashEntry",
    "SignatureStore",
    "SignatureUpdater",
    "UpdateError",
    "UpdateResult",
]
