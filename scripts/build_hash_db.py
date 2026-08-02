#!/usr/bin/env python3
"""Build the known-malware hash database from public feeds.

The output is a plain SQLite file that :class:`sentinel.signatures.loader.
HashDatabase` opens read-only. It is not committed — the release pipeline
builds it and publishes it alongside a manifest carrying its sha256.

Input formats accepted:

* CSV with a header naming at least a hash column. Column names are matched
  case-insensitively against a set of known aliases.
* Plain text, one hash per line (``#`` comments allowed).

Usage::

    # From a downloaded abuse.ch CSV
    python scripts/build_hash_db.py --csv full.csv --output hashes.db

    # From several sources at once
    python scripts/build_hash_db.py \\
        --csv malwarebazaar.csv --source MalwareBazaar \\
        --txt extra-hashes.txt --source manual \\
        --output hashes.db

    # Verify what was built
    python scripts/build_hash_db.py --output hashes.db --stats
"""

from __future__ import annotations

import argparse
import csv
import sqlite3
import sys
from collections.abc import Iterator
from pathlib import Path

# Column names that hold a digest, lowercased.
HASH_COLUMNS = {
    "sha256": "sha256", "sha256_hash": "sha256", "sha-256": "sha256",
    "sha1": "sha1", "sha1_hash": "sha1", "sha-1": "sha1",
    "md5": "md5", "md5_hash": "md5", "hash": None,  # inferred from length
}

NAME_COLUMNS = ("signature", "malware", "family", "name", "threat", "tag")
SEVERITY_COLUMNS = ("severity", "confidence", "level")
DATE_COLUMNS = ("first_seen", "firstseen", "date_added", "date", "reported")

VALID_SEVERITIES = ("clean", "low", "medium", "high", "critical")

SCHEMA = """
CREATE TABLE IF NOT EXISTS signatures (
    digest     TEXT PRIMARY KEY,
    algorithm  TEXT NOT NULL,
    name       TEXT NOT NULL,
    severity   TEXT NOT NULL DEFAULT 'high',
    source     TEXT NOT NULL DEFAULT '',
    first_seen TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_signatures_algorithm ON signatures(algorithm);
CREATE INDEX IF NOT EXISTS idx_signatures_name ON signatures(name);
"""


def detect_algorithm(digest: str) -> str | None:
    """Infer the hash algorithm from the digest length."""
    return {32: "md5", 40: "sha1", 64: "sha256"}.get(len(digest))


def is_hex(value: str) -> bool:
    return bool(value) and all(c in "0123456789abcdef" for c in value)


def rows_from_csv(path: Path, source: str, default_severity: str) -> Iterator[tuple]:
    """Yield signature rows from a CSV file."""
    with open(path, newline="", encoding="utf-8", errors="replace") as handle:
        # abuse.ch exports start with a block of '#' comment lines.
        lines = (line for line in handle if not line.lstrip().startswith("#"))
        reader = csv.DictReader(lines)

        if not reader.fieldnames:
            print(f"  {path.name}: no header row found", file=sys.stderr)
            return

        headers = {(name or "").strip().strip('"').lower(): name
                   for name in reader.fieldnames}

        hash_field = next(
            (headers[h] for h in HASH_COLUMNS if h in headers), None
        )
        if hash_field is None:
            print(
                f"  {path.name}: no hash column (looked for "
                f"{', '.join(sorted(HASH_COLUMNS))})",
                file=sys.stderr,
            )
            return

        name_field = next((headers[c] for c in NAME_COLUMNS if c in headers), None)
        severity_field = next(
            (headers[c] for c in SEVERITY_COLUMNS if c in headers), None
        )
        date_field = next((headers[c] for c in DATE_COLUMNS if c in headers), None)

        for record in reader:
            raw = (record.get(hash_field) or "").strip().strip('"').lower()
            if not is_hex(raw):
                continue
            algorithm = detect_algorithm(raw)
            if algorithm is None:
                continue

            name = (record.get(name_field) or "").strip().strip('"') if name_field else ""
            severity = default_severity
            if severity_field:
                candidate = (record.get(severity_field) or "").strip().lower()
                if candidate in VALID_SEVERITIES:
                    severity = candidate

            first_seen = ""
            if date_field:
                first_seen = (record.get(date_field) or "").strip().strip('"')[:32]

            yield (raw, algorithm, name or "Malware.Generic", severity, source, first_seen)


def rows_from_text(path: Path, source: str, default_severity: str) -> Iterator[tuple]:
    """Yield signature rows from a newline-delimited hash list."""
    with open(path, encoding="utf-8", errors="replace") as handle:
        for line in handle:
            entry = line.strip().lower()
            if not entry or entry.startswith("#"):
                continue
            # Allow "hash  name" on one line.
            parts = entry.split(None, 1)
            digest = parts[0]
            if not is_hex(digest):
                continue
            algorithm = detect_algorithm(digest)
            if algorithm is None:
                continue
            name = parts[1].strip() if len(parts) > 1 else "Malware.Generic"
            yield (digest, algorithm, name, default_severity, source, "")


def build(
    output: Path,
    csv_files: list[Path],
    text_files: list[Path],
    sources: list[str],
    severity: str,
    replace: bool,
) -> int:
    """Build the database. Returns the number of signatures written."""
    if replace and output.exists():
        output.unlink()

    output.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(output)
    connection.executescript(SCHEMA)

    inputs: list[tuple[Path, str]] = [(p, "csv") for p in csv_files]
    inputs += [(p, "txt") for p in text_files]

    total = 0
    for index, (path, kind) in enumerate(inputs):
        if not path.is_file():
            print(f"skipping missing file {path}", file=sys.stderr)
            continue

        source = sources[index] if index < len(sources) else path.stem
        print(f"reading {path} ({kind}, source={source})")

        generator = (
            rows_from_csv(path, source, severity)
            if kind == "csv"
            else rows_from_text(path, source, severity)
        )

        batch: list[tuple] = []
        count = 0
        for row in generator:
            batch.append(row)
            if len(batch) >= 10_000:
                # INSERT OR IGNORE: the first source to claim a hash wins,
                # so ordering the inputs by trustworthiness matters.
                connection.executemany(
                    "INSERT OR IGNORE INTO signatures VALUES (?,?,?,?,?,?)", batch
                )
                connection.commit()
                count += len(batch)
                batch.clear()

        if batch:
            connection.executemany(
                "INSERT OR IGNORE INTO signatures VALUES (?,?,?,?,?,?)", batch
            )
            connection.commit()
            count += len(batch)

        print(f"  {count:,} rows")
        total += count

    connection.execute("ANALYZE")
    connection.commit()

    stored = connection.execute("SELECT COUNT(*) FROM signatures").fetchone()[0]
    connection.close()

    print(f"\nwrote {stored:,} unique signatures to {output} "
          f"({output.stat().st_size / 1024 / 1024:.1f} MB)")
    if total > stored:
        print(f"({total - stored:,} duplicates were ignored)")
    return stored


def show_stats(path: Path) -> None:
    """Print a summary of an existing database."""
    if not path.is_file():
        print(f"{path} does not exist", file=sys.stderr)
        raise SystemExit(1)

    connection = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
    total = connection.execute("SELECT COUNT(*) FROM signatures").fetchone()[0]
    print(f"{path}: {total:,} signatures, "
          f"{path.stat().st_size / 1024 / 1024:.1f} MB\n")

    for label, query in (
        ("by algorithm", "SELECT algorithm, COUNT(*) c FROM signatures "
                         "GROUP BY algorithm ORDER BY c DESC"),
        ("by severity", "SELECT severity, COUNT(*) c FROM signatures "
                        "GROUP BY severity ORDER BY c DESC"),
        ("by source", "SELECT source, COUNT(*) c FROM signatures "
                      "GROUP BY source ORDER BY c DESC LIMIT 10"),
        ("top families", "SELECT name, COUNT(*) c FROM signatures "
                         "GROUP BY name ORDER BY c DESC LIMIT 10"),
    ):
        print(f"{label}:")
        for key, count in connection.execute(query):
            print(f"  {key or '(none)':<40} {count:>10,}")
        print()

    connection.close()


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--csv", action="append", type=Path, default=[],
                        help="CSV input; repeatable")
    parser.add_argument("--txt", action="append", type=Path, default=[],
                        help="newline-delimited hash list; repeatable")
    parser.add_argument("--source", action="append", default=[],
                        help="label for the preceding input; repeatable")
    parser.add_argument("--output", "-o", type=Path,
                        default=Path("src/sentinel/signatures/local/hashes.db"),
                        help="destination database")
    parser.add_argument("--severity", default="high", choices=VALID_SEVERITIES,
                        help="severity for entries without one (default: high)")
    parser.add_argument("--replace", action="store_true",
                        help="delete an existing database first")
    parser.add_argument("--stats", action="store_true",
                        help="show statistics for --output and exit")

    args = parser.parse_args()

    if args.stats:
        show_stats(args.output)
        return 0

    if not args.csv and not args.txt:
        parser.error("provide at least one --csv or --txt input (or use --stats)")

    written = build(
        args.output, args.csv, args.txt, args.source,
        args.severity, args.replace,
    )
    if written == 0:
        print("no signatures were written", file=sys.stderr)
        return 1

    print(
        "\nNext: record the file's sha256 in the manifest so the updater will "
        "accept it:\n"
        f"  python -c \"import hashlib,pathlib; "
        f"print(hashlib.sha256(pathlib.Path(r'{args.output}').read_bytes()).hexdigest())\""
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
