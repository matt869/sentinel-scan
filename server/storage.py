"""Database session management and sample file storage.

Samples are live malware. They are stored with the same keystream
obfuscation the client's quarantine vault uses, for the same reason: so a
misconfigured backup agent, a file indexer or a curious operator cannot
execute one by accident. It is containment, not confidentiality — the key
sits beside the data.
"""

from __future__ import annotations

import hashlib
import os
import secrets
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from server.models import Base

# ----------------------------------------------------------------------
# settings
# ----------------------------------------------------------------------

DATABASE_URL = os.environ.get(
    "SENTINEL_SERVER_DB_URL", "sqlite:///./data/sentinel-server.db"
)
SAMPLE_DIR = Path(os.environ.get("SENTINEL_SERVER_SAMPLE_DIR", "./data/samples"))
MAX_UPLOAD = int(os.environ.get("SENTINEL_SERVER_MAX_UPLOAD", 32 * 1024 * 1024))

#: Tokens accepted by write endpoints. Empty means the server runs open,
#: which is only appropriate behind another auth layer.
API_TOKENS = frozenset(
    token.strip()
    for token in os.environ.get("SENTINEL_SERVER_TOKENS", "").split(",")
    if token.strip()
)

#: Salt for hashing submitter IPs. Regenerated per process when unset, which
#: means rate-limit buckets reset on restart — acceptable, and it guarantees
#: the hashes are not stable identifiers across deployments.
IP_SALT = os.environ.get("SENTINEL_SERVER_IP_SALT", secrets.token_hex(16))

_ENGINE_KWARGS: dict[str, Any] = {"pool_pre_ping": True, "future": True}
if DATABASE_URL.startswith("sqlite"):
    # FastAPI serves requests on a thread pool; SQLite needs this to allow a
    # connection created on one thread to be used on another.
    _ENGINE_KWARGS["connect_args"] = {"check_same_thread": False}

engine = create_engine(DATABASE_URL, **_ENGINE_KWARGS)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def init_db() -> None:
    """Create tables and the sample directory. Safe to call repeatedly."""
    if DATABASE_URL.startswith("sqlite:///"):
        db_path = DATABASE_URL.replace("sqlite:///", "", 1)
        if db_path not in {":memory:", ""}:
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    Base.metadata.create_all(engine)
    SAMPLE_DIR.mkdir(parents=True, exist_ok=True)

    if DATABASE_URL.startswith("sqlite"):
        with engine.connect() as connection:
            connection.execute(text("PRAGMA journal_mode=WAL"))
            connection.commit()


def get_session() -> Iterator[Session]:
    """FastAPI dependency yielding a session that always closes."""
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@contextmanager
def session_scope() -> Iterator[Session]:
    """Transactional scope for use outside a request."""
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def health_check() -> str:
    """Return "ok" if the database answers, otherwise the error."""
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return "ok"
    except Exception as exc:
        return f"error: {exc}"


# ----------------------------------------------------------------------
# submitter hashing
# ----------------------------------------------------------------------

def hash_ip(address: str) -> str:
    """Salted hash of a client address, for rate limiting only.

    Never stored in plain text, never returned by any endpoint. The salt
    makes the value useless outside this deployment.
    """
    if not address:
        return ""
    return hashlib.sha256(f"{IP_SALT}:{address}".encode()).hexdigest()


# ----------------------------------------------------------------------
# sample storage
# ----------------------------------------------------------------------

_VAULT_KEY_FILE = SAMPLE_DIR / ".vault-key"
_CHUNK = 1024 * 1024


def _vault_key() -> bytes:
    """The obfuscation key, generated on first use with 0600 permissions."""
    SAMPLE_DIR.mkdir(parents=True, exist_ok=True)
    if _VAULT_KEY_FILE.is_file():
        return _VAULT_KEY_FILE.read_bytes()

    key = secrets.token_bytes(32)
    fd = os.open(_VAULT_KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, key)
    finally:
        os.close(fd)
    return key


def _keystream_xor(data: bytes, key: bytes, nonce: bytes, offset: int = 0) -> bytes:
    """Counter-mode XOR, matching the client's quarantine format."""
    block_size = hashlib.sha256().digest_size
    start_block, lead = divmod(offset, block_size)
    needed = lead + len(data)

    stream = bytearray()
    block = start_block
    while len(stream) < needed:
        stream += hashlib.sha256(key + nonce + block.to_bytes(8, "little")).digest()
        block += 1

    window = stream[lead : lead + len(data)]
    # strict=True: a mismatch would silently truncate and corrupt the sample.
    return bytes(a ^ b for a, b in zip(data, window, strict=True))


def store_sample(content: bytes, sha256: str) -> tuple[str, int]:
    """Write a sample to disk obfuscated.

    Returns:
        ``(relative_path, size)``. The path is sharded by the first four hex
        characters so a directory never accumulates millions of entries.
    """
    if len(content) > MAX_UPLOAD:
        raise ValueError(f"sample exceeds the {MAX_UPLOAD} byte limit")

    shard = SAMPLE_DIR / sha256[:2] / sha256[2:4]
    shard.mkdir(parents=True, exist_ok=True)

    nonce = secrets.token_bytes(16)
    target = shard / f"{sha256}.bin"
    payload = nonce + _keystream_xor(content, _vault_key(), nonce)

    # Write then rename so a crash cannot leave a half-written sample that
    # looks complete.
    temporary = target.with_suffix(".part")
    temporary.write_bytes(payload)
    os.replace(temporary, target)
    if os.name == "posix":
        os.chmod(target, 0o600)

    return str(target.relative_to(SAMPLE_DIR)), len(content)


def load_sample(relative_path: str) -> bytes:
    """Read a stored sample back into memory, de-obfuscated.

    Raises:
        FileNotFoundError: the sample is not on disk.
    """
    path = SAMPLE_DIR / relative_path
    # Refuse anything that escapes the sample directory.
    resolved = path.resolve()
    try:
        resolved.relative_to(SAMPLE_DIR.resolve())
    except ValueError as exc:
        raise FileNotFoundError(f"{relative_path} is outside the sample store") from exc

    raw = resolved.read_bytes()
    if len(raw) < 16:
        raise ValueError(f"{relative_path} is truncated")
    nonce, payload = raw[:16], raw[16:]
    return _keystream_xor(payload, _vault_key(), nonce)


def sample_exists(sha256: str) -> bool:
    """Whether a sample with this digest is already stored."""
    return (SAMPLE_DIR / sha256[:2] / sha256[2:4] / f"{sha256}.bin").is_file()


def sample_store_size() -> int:
    """Total bytes occupied by stored samples."""
    total = 0
    for path in SAMPLE_DIR.rglob("*.bin"):
        try:
            total += path.stat().st_size
        except OSError:
            continue
    return total


# ----------------------------------------------------------------------
# request dependencies
# ----------------------------------------------------------------------
# These live here rather than in main.py so the routers can depend on them
# without importing the app module, which would be circular. They also need
# the same settings (API_TOKENS, IP_SALT) this module already owns.

import hmac  # noqa: E402
import logging  # noqa: E402
import time  # noqa: E402
from collections import defaultdict  # noqa: E402
from typing import Annotated  # noqa: E402

from fastapi import Header, HTTPException, Request, status  # noqa: E402

log = logging.getLogger("sentinel.server")

#: In-process rate limiting. Adequate for a single instance; front it with a
#: real limiter if you run more than one.
RATE_LIMIT_WINDOW = 3600
RATE_LIMIT_MAX = int(os.environ.get("SENTINEL_SERVER_RATE_LIMIT", "60"))
_request_log: dict[str, list[float]] = defaultdict(list)


async def require_token(
    authorization: Annotated[str | None, Header()] = None,
) -> str:
    """Validate the bearer token on write endpoints.

    When ``SENTINEL_SERVER_TOKENS`` is empty this passes unconditionally —
    the app logs a loud warning about that at startup.
    """
    if not API_TOKENS:
        return "anonymous"

    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="a bearer token is required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = authorization[7:].strip()
    # Constant-time comparison against each configured token, so timing
    # cannot reveal a valid prefix.
    if not any(hmac.compare_digest(token, valid) for valid in API_TOKENS):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="invalid token"
        )
    return token


async def rate_limit(request: Request) -> str:
    """Cap submissions per client per hour. Returns the hashed client id."""
    client = request.client.host if request.client else ""
    identity = hash_ip(client)
    if not identity:
        return identity

    now = time.time()
    window = _request_log[identity]
    window[:] = [t for t in window if now - t < RATE_LIMIT_WINDOW]

    if len(window) >= RATE_LIMIT_MAX:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"rate limit of {RATE_LIMIT_MAX} requests per hour exceeded",
            headers={"Retry-After": str(RATE_LIMIT_WINDOW)},
        )

    window.append(now)
    return identity


def reset_rate_limits() -> None:
    """Clear the rate-limit state. Used by tests."""
    _request_log.clear()
