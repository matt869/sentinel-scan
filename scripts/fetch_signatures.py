#!/usr/bin/env python3
"""Fetch upstream signature data and assemble a release manifest.

Run by the release pipeline (``.github/workflows/update-signatures.yml``),
and usable by hand to build a local mirror.

What it does:

1. Downloads each configured source to a staging directory.
2. Records the sha256 of every downloaded file.
3. Writes a ``manifest.json`` the client updater can verify against.

Licensing matters here. ClamAV's databases are GPL-2.0 and are *not*
redistributed with this MIT-licensed project — they are fetched from the
upstream mirror at update time, and the manifest records their provenance.
See the note in LICENSE.

Usage::

    python scripts/fetch_signatures.py --output ./mirror
    python scripts/fetch_signatures.py --output ./mirror --only clamav
    python scripts/fetch_signatures.py --output ./mirror --dry-run
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import httpx
except ImportError:  # pragma: no cover
    print("this script needs httpx: pip install httpx", file=sys.stderr)
    raise SystemExit(2) from None

USER_AGENT = "sentinel-scan-signature-fetcher/1.0"
CHUNK = 256 * 1024
MAX_SIZE = 512 * 1024 * 1024


@dataclass
class Source:
    """One upstream signature bundle."""

    key: str
    name: str
    url: str
    directory: str = ""
    license: str = ""
    notice: str = ""
    description: str = ""
    #: Skip by default — large, or licensed such that mirroring needs thought.
    optional: bool = False
    tags: list[str] = field(default_factory=list)


SOURCES: tuple[Source, ...] = (
    Source(
        key="clamav-main",
        name="main.cvd",
        url="https://database.clamav.net/main.cvd",
        license="GPL-2.0",
        notice=(
            "Distributed by Cisco Systems, Inc. under GPL-2.0. Not "
            "redistributed with Sentinel Scan; fetched from upstream."
        ),
        description="ClamAV base signature database.",
        optional=True,
        tags=["clamav"],
    ),
    Source(
        key="clamav-daily",
        name="daily.cvd",
        url="https://database.clamav.net/daily.cvd",
        license="GPL-2.0",
        notice="Distributed by Cisco Systems, Inc. under GPL-2.0.",
        description="ClamAV incremental daily signatures.",
        optional=True,
        tags=["clamav"],
    ),
    Source(
        key="malwarebazaar",
        name="malwarebazaar.csv",
        url="https://bazaar.abuse.ch/export/csv/recent/",
        license="CC0-1.0",
        description="Recent MalwareBazaar samples, for the hash database.",
        tags=["hashes"],
    ),
)


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb", buffering=0) as handle:
        for chunk in iter(lambda: handle.read(CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download(source: Source, destination: Path, timeout: float) -> Path | None:
    """Download one source. Returns the written path, or None on failure."""
    destination.mkdir(parents=True, exist_ok=True)
    target = destination / source.name

    print(f"  {source.key}: {source.url}")
    fd, temp_name = tempfile.mkstemp(prefix=f".{source.name}.", dir=destination)
    temp_path = Path(temp_name)

    try:
        downloaded = 0
        with open(fd, "wb") as handle, httpx.Client(
            timeout=timeout, follow_redirects=True,
            headers={"User-Agent": USER_AGENT},
        ) as client, client.stream("GET", source.url) as response:
            response.raise_for_status()
            for chunk in response.iter_bytes(CHUNK):
                downloaded += len(chunk)
                if downloaded > MAX_SIZE:
                    raise ValueError(
                        f"exceeded the {MAX_SIZE} byte limit"
                    )
                handle.write(chunk)

        if downloaded == 0:
            raise ValueError("the server returned an empty body")

        shutil.move(str(temp_path), target)
        print(f"    {downloaded / 1024 / 1024:.1f} MB -> {target}")
        return target

    except Exception as exc:
        temp_path.unlink(missing_ok=True)
        print(f"    FAILED: {exc}", file=sys.stderr)
        return None


def build_manifest(
    output: Path, results: dict[str, Path], version: str
) -> dict[str, Any]:
    """Assemble the manifest the client updater verifies against."""
    by_key = {source.key: source for source in SOURCES}
    bundles = []

    for key, path in sorted(results.items()):
        source = by_key[key]
        bundles.append(
            {
                "name": source.name,
                "directory": source.directory,
                "type": source.tags[0] if source.tags else "data",
                "description": source.description,
                "sha256": sha256_of(path),
                "size": path.stat().st_size,
                "license": source.license,
                **({"notice": source.notice} if source.notice else {}),
                "sources": [{"name": source.key, "url": source.url,
                             "license": source.license}],
            }
        )

    manifest = {
        "version": version,
        "updated": datetime.now(tz=timezone.utc).isoformat(),
        "format": 1,
        "bundles": bundles,
    }

    path = output / "manifest.json"
    path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"\nwrote {path}")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--output", "-o", type=Path, default=Path("./mirror"),
                        help="staging directory (default: ./mirror)")
    parser.add_argument("--only", action="append", default=[],
                        help="fetch only sources with this key or tag; repeatable")
    parser.add_argument("--include-optional", action="store_true",
                        help="include sources marked optional (the ClamAV bundles)")
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument("--version", default="",
                        help="manifest version (default: today's date)")
    parser.add_argument("--dry-run", action="store_true",
                        help="list what would be fetched and exit")
    parser.add_argument("--list", action="store_true",
                        help="show the configured sources and exit")

    args = parser.parse_args()

    if args.list:
        print(f"{'key':<18} {'license':<12} {'optional':<9} url")
        for source in SOURCES:
            print(f"{source.key:<18} {source.license:<12} "
                  f"{source.optional!s:<9} {source.url}")
        return 0

    selected = []
    for source in SOURCES:
        if args.only:
            if source.key not in args.only and not (set(source.tags) & set(args.only)):
                continue
        elif source.optional and not args.include_optional:
            continue
        selected.append(source)

    if not selected:
        print("no sources selected", file=sys.stderr)
        return 1

    print(f"{len(selected)} source(s) selected:")
    for source in selected:
        marker = " (optional)" if source.optional else ""
        print(f"  {source.key}{marker} — {source.license}")

    if args.dry_run:
        print("\ndry run; nothing downloaded")
        return 0

    print()
    results: dict[str, Path] = {}
    for source in selected:
        destination = args.output / source.directory if source.directory else args.output
        path = download(source, destination, args.timeout)
        if path is not None:
            results[source.key] = path

    if not results:
        print("\nnothing was downloaded", file=sys.stderr)
        return 1

    version = args.version or datetime.now(tz=timezone.utc).strftime("%Y.%m.%d")
    build_manifest(args.output, results, version)

    failed = len(selected) - len(results)
    print(f"\n{len(results)} succeeded, {failed} failed")

    if any(s.license.startswith("GPL") for s in selected if s.key in results):
        print(
            "\nNote: this mirror includes GPL-2.0 licensed ClamAV databases. "
            "They are not covered by Sentinel Scan's MIT licence — keep their "
            "notices intact when redistributing."
        )

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
