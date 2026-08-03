"""Downloading and installing signature updates.

Update flow:

1. Fetch ``manifest.json`` from the mirror.
2. Compare its ``version`` against the installed one; stop if unchanged.
3. For each listed bundle whose local copy is missing or stale, download to a
   temporary file in the destination directory.
4. Verify the sha256 against the manifest. **A mismatch aborts that file.**
5. Atomically replace the installed copy.
6. Write the new manifest last, so an interrupted update leaves the old
   version recorded and simply retries next time.

The rule revocation list rides along on the same run but bypasses steps 1-2
entirely; see :mod:`sentinel.signatures.revocations` for why it must land
without waiting for a version bump.

Checksum verification is the load-bearing step. A signature bundle is
data the scanner trusts and loads at high privilege; installing one whose
hash does not match the signed manifest would hand an attacker with mirror
access control over every install. There is deliberately no flag to skip it
beyond ``updates.verify_checksums``, which exists only for local development
against a mirror you built yourself.
"""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sentinel.core.logger import get_logger
from sentinel.utils.hashing import hash_file
from sentinel.version import USER_AGENT

log = get_logger(__name__)

#: Refuse absurdly large downloads regardless of what the manifest claims.
MAX_BUNDLE_SIZE = 512 * 1024 * 1024

#: The revocation list is a few hundred rule names at most. Anything larger
#: is not a revocation list and is not worth reading into memory.
MAX_REVOCATION_SIZE = 1024 * 1024

DOWNLOAD_CHUNK = 256 * 1024

ProgressCallback = Callable[[str, int, int], None]


class UpdateError(RuntimeError):
    """Raised when an update cannot be completed."""


@dataclass
class UpdateResult:
    """Outcome of an update run."""

    updated: bool = False
    from_version: str = ""
    to_version: str = ""
    files_installed: list[str] = field(default_factory=list)
    files_failed: list[str] = field(default_factory=list)
    bytes_downloaded: int = 0
    duration: float = 0.0
    message: str = ""
    #: Rules disabled by the revocation list after this run. -1 means the
    #: list could not be refreshed, so whatever was already installed stands.
    revoked_rules: int = -1

    @property
    def ok(self) -> bool:
        return not self.files_failed

    def summary(self) -> str:
        parts: list[str] = []
        if not self.updated:
            parts.append(self.message or "Signatures are already up to date")
        else:
            parts.append(f"Updated {self.from_version or '(none)'} -> {self.to_version}")
            if self.files_installed:
                parts.append(f"{len(self.files_installed)} file(s) installed")
            if self.files_failed:
                parts.append(f"{len(self.files_failed)} failed")
        if self.revoked_rules > 0:
            parts.append(f"{self.revoked_rules} rule(s) revoked")
        return "; ".join(parts)


class SignatureUpdater:
    """Fetches signature bundles from a mirror and installs them."""

    def __init__(self, config: Any) -> None:
        self.config = config
        self.settings = getattr(config, "updates", None)
        self.mirror = (
            getattr(self.settings, "mirror_url", "") if self.settings else ""
        ).rstrip("/")
        self.verify = getattr(self.settings, "verify_checksums", True) if self.settings else True
        self.honor_revocations = (
            getattr(self.settings, "honor_revocations", True) if self.settings else True
        )
        self.revocation_url = (
            getattr(self.settings, "revocation_url", "") if self.settings else ""
        ).strip()
        self.timeout = getattr(
            getattr(config, "privacy", None), "request_timeout", 30.0
        )

        paths = getattr(config, "paths", None)
        if paths is None:
            raise UpdateError("configuration has no paths; cannot install updates")
        self.destination = Path(paths.signatures_dir)

    # -- public API ----------------------------------------------------

    def check(self) -> tuple[bool, str, str]:
        """Return ``(update_available, local_version, remote_version)``."""
        from sentinel.signatures.loader import SignatureStore

        local = SignatureStore(self.config).version
        try:
            remote_manifest = self._fetch_manifest()
        except UpdateError as exc:
            log.debug("update check failed: %s", exc)
            return False, local, ""

        remote = str(remote_manifest.get("version", ""))
        return (bool(remote) and remote != local), local, remote

    def update(
        self,
        force: bool = False,
        progress: ProgressCallback | None = None,
    ) -> UpdateResult:
        """Download and install any newer signature bundles.

        Args:
            force: Reinstall even when the version is unchanged.
            progress: Called as ``(filename, bytes_done, bytes_total)``.
        """
        started = time.time()
        from sentinel.signatures.loader import SignatureStore

        store = SignatureStore(self.config)
        local_version = store.version

        if not self.mirror and not self.revocation_url:
            return UpdateResult(
                message="No update mirror configured (updates.mirror_url is empty)",
                from_version=local_version,
            )

        # Revocations first, and before the version check below. A rule we
        # know is quarantining people's files has to be switchable off without
        # waiting for a new signature version to be cut — that is the entire
        # point of the kill switch, and putting it after the short-circuit
        # would mean it only ever arrived alongside a release.
        revoked = self.fetch_revocations()

        if not self.mirror:
            return UpdateResult(
                message="No update mirror configured (updates.mirror_url is empty)",
                from_version=local_version,
                revoked_rules=revoked,
            )

        manifest = self._fetch_manifest()
        remote_version = str(manifest.get("version", ""))
        result = UpdateResult(
            from_version=local_version,
            to_version=remote_version,
            revoked_rules=revoked,
        )

        if not force and remote_version and remote_version == local_version:
            result.message = f"Already at signature version {local_version}"
            result.duration = time.time() - started
            return result

        self.destination.mkdir(parents=True, exist_ok=True)
        bundles = manifest.get("bundles", [])
        if not isinstance(bundles, list):
            raise UpdateError("manifest 'bundles' must be a list")

        for bundle in bundles:
            name = str(bundle.get("name", ""))
            if not name or not _safe_bundle_name(name):
                log.warning("skipping bundle with unsafe name %r", name)
                result.files_failed.append(name or "<unnamed>")
                continue

            try:
                downloaded = self._install_bundle(bundle, progress)
            except UpdateError as exc:
                log.error("failed to install %s: %s", name, exc)
                result.files_failed.append(name)
                continue

            if downloaded > 0:
                result.files_installed.append(name)
                result.bytes_downloaded += downloaded

        # Write the manifest last so a crash mid-update is retried, not
        # silently recorded as complete.
        if result.files_installed or force:
            manifest["updated"] = datetime.now(tz=timezone.utc).isoformat()
            _atomic_write(
                self.destination / "manifest.json",
                json.dumps(manifest, indent=2).encode("utf-8"),
            )
            result.updated = True

        result.duration = time.time() - started
        result.message = result.summary()
        return result

    def fetch_revocations(self) -> int:
        """Refresh the rule revocation list. Returns the rules now revoked.

        Returns -1 when the list could not be refreshed, in which case
        whatever was already installed stays in force.

        Deliberately never raises. This runs on a path the user did not ask
        for and cannot act on, and a mirror hiccup must not turn into a failed
        signature update — the rest of the update is still worth doing. It is
        also why nothing here is fatal: the list is only ever able to *remove*
        detections, so not having today's copy costs sensitivity, never
        safety.
        """
        from sentinel.signatures.revocations import (
            REVOCATION_FILENAME,
            RevocationList,
        )

        if not self.honor_revocations:
            log.debug("revocations disabled in configuration; not fetching")
            return -1

        url = self.revocation_url or (
            f"{self.mirror}/{REVOCATION_FILENAME}" if self.mirror else ""
        )
        if not url:
            return -1

        try:
            with self._client() as client:
                response = client.get(url)
                response.raise_for_status()
                body = response.content
        except Exception as exc:
            log.warning("cannot refresh the revocation list from %s: %s", url, exc)
            return -1

        if len(body) > MAX_REVOCATION_SIZE:
            log.error(
                "revocation list at %s is %d bytes, over the %d limit; ignoring it",
                url, len(body), MAX_REVOCATION_SIZE,
            )
            return -1

        # Parse before installing. A list we cannot read would fail open and
        # silently un-revoke every rule the last good copy had disabled, so a
        # corrupt download must leave the installed copy alone.
        try:
            data = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            log.error("revocation list at %s is not valid JSON: %s; keeping the "
                      "installed copy", url, exc)
            return -1

        revocations = RevocationList.from_dict(data)

        try:
            self.destination.mkdir(parents=True, exist_ok=True)
            _atomic_write(self.destination / REVOCATION_FILENAME, body)
        except OSError as exc:
            log.warning("cannot write the revocation list: %s", exc)
            return -1

        count = len(revocations)
        log.info("revocation list refreshed: %d rule(s) disabled", count)
        return count

    # -- internals -----------------------------------------------------

    def _client(self) -> Any:
        import httpx

        return httpx.Client(
            timeout=self.timeout,
            follow_redirects=True,
            headers={"User-Agent": USER_AGENT},
        )

    def _fetch_manifest(self) -> dict[str, Any]:
        if not self.mirror:
            raise UpdateError("no mirror configured")
        url = f"{self.mirror}/manifest.json"
        try:
            with self._client() as client:
                response = client.get(url)
                response.raise_for_status()
                data = response.json()
        except Exception as exc:
            raise UpdateError(f"cannot fetch {url}: {exc}") from exc

        if not isinstance(data, dict):
            raise UpdateError(f"{url} did not return a JSON object")
        return data

    def _install_bundle(
        self, bundle: dict[str, Any], progress: ProgressCallback | None
    ) -> int:
        """Download, verify and install one bundle. Returns bytes downloaded."""
        name = str(bundle["name"])
        expected_sha = str(bundle.get("sha256", "")).lower()
        expected_size = int(bundle.get("size", 0))
        subdirectory = str(bundle.get("directory", "")).strip("/\\")

        if self.verify and not expected_sha:
            raise UpdateError(f"{name}: manifest has no sha256 and verification is on")
        if expected_size > MAX_BUNDLE_SIZE:
            raise UpdateError(
                f"{name}: manifest declares {expected_size} bytes, over the "
                f"{MAX_BUNDLE_SIZE} limit"
            )

        target_dir = self.destination / subdirectory if subdirectory else self.destination
        target_dir.mkdir(parents=True, exist_ok=True)
        target = target_dir / name

        # Already have this exact content?
        if expected_sha and target.is_file():
            try:
                if hash_file(target) == expected_sha:
                    log.debug("%s already current", name)
                    return 0
            except OSError:
                pass

        url = str(bundle.get("url") or f"{self.mirror}/{subdirectory}/{name}".replace(
            "//", "/"
        ).replace(":/", "://"))

        temp_path = self._download(url, target_dir, name, expected_size, progress)

        try:
            if self.verify:
                actual = hash_file(temp_path)
                if actual != expected_sha:
                    raise UpdateError(
                        f"{name}: checksum mismatch (expected {expected_sha[:16]}…, "
                        f"got {actual[:16]}…). The download was corrupted or tampered "
                        f"with; it has not been installed."
                    )
            size = temp_path.stat().st_size
            os.replace(temp_path, target)
            log.info("installed %s (%d bytes)", name, size)
            return size
        except Exception:
            temp_path.unlink(missing_ok=True)
            raise

    def _download(
        self,
        url: str,
        directory: Path,
        name: str,
        expected_size: int,
        progress: ProgressCallback | None,
    ) -> Path:
        """Stream a URL to a temp file in *directory*. Returns its path.

        The temp file is created in the destination directory so the final
        :func:`os.replace` is an atomic same-filesystem rename.
        """
        fd, temp_name = tempfile.mkstemp(prefix=f".{name}.", suffix=".part", dir=directory)
        temp_path = Path(temp_name)
        downloaded = 0

        try:
            with (
                os.fdopen(fd, "wb") as handle,
                self._client() as client,
                client.stream("GET", url) as response,
            ):
                response.raise_for_status()
                total = int(response.headers.get("content-length", expected_size) or 0)
                if total > MAX_BUNDLE_SIZE:
                    raise UpdateError(f"{name}: server declared {total} bytes, too large")

                for chunk in response.iter_bytes(DOWNLOAD_CHUNK):
                    downloaded += len(chunk)
                    if downloaded > MAX_BUNDLE_SIZE:
                        raise UpdateError(f"{name}: exceeded the size limit mid-download")
                    handle.write(chunk)
                    if progress is not None:
                        progress(name, downloaded, total)
        except UpdateError:
            temp_path.unlink(missing_ok=True)
            raise
        except Exception as exc:
            temp_path.unlink(missing_ok=True)
            raise UpdateError(f"{name}: download failed: {exc}") from exc

        return temp_path


def should_check(config: Any, last_check: float | None) -> bool:
    """Whether enough time has passed for an automatic update check."""
    settings = getattr(config, "updates", None)
    if settings is None or not getattr(settings, "auto_update", False):
        return False
    if last_check is None:
        return True
    interval = getattr(settings, "check_interval_hours", 12) * 3600
    return (time.time() - last_check) >= interval


#: kv key holding the unix time of the last automatic revocation check.
LAST_REVOCATION_CHECK = "updates.last_revocation_check"


def refresh_revocations_in_background(config: Any, db: Any) -> threading.Thread | None:
    """Start a background refresh of the revocation list, if one is due.

    Returns the thread, or None when nothing was started. Never raises.

    Deliberately *only* the revocation list, not the signature bundles. The
    list is a few kilobytes and is the one piece of update data that is
    urgent — it is how a rule we already know is quarantining people's files
    stops firing. Signature bundles are hundreds of megabytes and pulling
    them automatically in the background would blow the scan's memory and
    bandwidth budget on exactly the weak, metered machines this is for; those
    stay on the explicit ``sentinel update`` path.

    Runs on a daemon thread so a mirror that hangs delays nothing. The scan
    it accompanies uses whichever list is on disk when it starts — a
    revocation landing mid-scan applies to the next one, which is soon
    enough and avoids changing the rules underneath a run in progress.
    """
    settings = getattr(config, "updates", None)
    if settings is None or not getattr(settings, "honor_revocations", True):
        return None

    try:
        raw = db.get_setting(LAST_REVOCATION_CHECK)
        last = float(raw) if raw else None
    except Exception as exc:
        log.debug("cannot read the last revocation check time: %s", exc)
        last = None

    if not should_check(config, last):
        return None

    def run() -> None:
        try:
            SignatureUpdater(config).fetch_revocations()
            db.set_setting(LAST_REVOCATION_CHECK, str(time.time()))
        except Exception as exc:
            # Nothing here is worth interrupting the user for: the installed
            # list stays in force and we try again next time.
            log.debug("background revocation refresh failed: %s", exc)
        finally:
            # Close this thread's connection; Database opens one per thread.
            with contextlib.suppress(Exception):
                db.close()

    thread = threading.Thread(
        target=run, name="sentinel-revocations", daemon=True
    )
    thread.start()
    return thread


def _safe_bundle_name(name: str) -> bool:
    """Reject names that would escape the signatures directory."""
    if name in {".", ".."} or not name:
        return False
    return not ("/" in name or "\\" in name or name.startswith("."))


def _atomic_write(path: Path, data: bytes) -> None:
    """Write *data* to *path* via a temp file and rename."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        os.replace(temp_name, path)
    except Exception:
        Path(temp_name).unlink(missing_ok=True)
        raise
