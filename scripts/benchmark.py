#!/usr/bin/env python3
"""Measure scan throughput and per-detector cost.

Two things worth measuring separately:

* **Throughput** — files and megabytes per second over a realistic tree.
  This is what a user waits for.
* **Per-detector cost** — how long each detector spends per file. This is
  what you optimise, and it is where a badly-written YARA rule shows up.

Usage::

    # Benchmark against a generated corpus
    python scripts/benchmark.py --generate 2000

    # Benchmark a real directory
    python scripts/benchmark.py --path ~/Downloads

    # Compare thread counts
    python scripts/benchmark.py --generate 5000 --threads 1,2,4,8,16
"""

from __future__ import annotations

import argparse
import os
import random
import shutil
import statistics
import sys
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from sentinel.core.config import load_config
from sentinel.engine.detectors.base import ScanTarget
from sentinel.engine.scanner import Scanner
from sentinel.utils.humanize import human_bytes, human_duration


def generate_corpus(directory: Path, count: int, seed: int = 1234) -> Path:
    """Create a synthetic tree with a realistic mix of file types."""
    random.seed(seed)
    directory.mkdir(parents=True, exist_ok=True)

    text_words = [
        "the", "quick", "brown", "fox", "jumps", "over", "lazy", "dog",
        "import", "def", "class", "return", "function", "value", "result",
        "data", "config", "user", "name", "path", "size", "type",
    ]

    print(f"generating {count:,} files in {directory}…")
    for index in range(count):
        # Spread across subdirectories, as a real tree would be.
        subdirectory = directory / f"dir{index // 100:03d}"
        subdirectory.mkdir(exist_ok=True)

        roll = random.random()
        if roll < 0.45:
            # Source or text
            path = subdirectory / f"file{index}.txt"
            body = " ".join(random.choices(text_words, k=random.randint(50, 800)))
            path.write_text(body, encoding="utf-8")
        elif roll < 0.65:
            # Script
            path = subdirectory / f"script{index}.ps1"
            path.write_text(
                f"# script {index}\n"
                f"$value = Get-Item -Path 'C:/temp/{index}'\n"
                f"Write-Output $value\n",
                encoding="utf-8",
            )
        elif roll < 0.85:
            # Binary, PE-shaped
            path = subdirectory / f"binary{index}.exe"
            path.write_bytes(
                b"MZ" + b"\x90\x00" * 32 + os.urandom(random.randint(4096, 200_000))
            )
        elif roll < 0.95:
            # Compressed blob (high entropy)
            path = subdirectory / f"blob{index}.bin"
            path.write_bytes(os.urandom(random.randint(8192, 100_000)))
        else:
            # Archive
            path = subdirectory / f"archive{index}.zip"
            with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
                for member in range(random.randint(1, 5)):
                    archive.writestr(
                        f"member{member}.txt",
                        " ".join(random.choices(text_words, k=200)),
                    )

    total = sum(f.stat().st_size for f in directory.rglob("*") if f.is_file())
    print(f"  {count:,} files, {human_bytes(total)}\n")
    return directory


def benchmark_scan(path: Path, threads: int, repeats: int) -> dict[str, Any]:
    """Run a full scan and report throughput."""
    config = load_config()
    config.scan.threads = threads
    config.paths.ensure()

    durations: list[float] = []
    result = None

    for run in range(repeats):
        scanner = Scanner(config)
        try:
            # Clear the result cache so repeat runs measure real work, not
            # a cache hit on the second pass.
            scanner.db.connection.execute("DELETE FROM scan_cache")
            started = time.perf_counter()
            result = scanner.scan_paths([path], record_history=False)
            durations.append(time.perf_counter() - started)
        finally:
            scanner.close()
        print(f"    run {run + 1}/{repeats}: {durations[-1]:.2f}s")

    assert result is not None
    best = min(durations)
    return {
        "threads": threads,
        "files": result.files_scanned,
        "bytes": result.bytes_scanned,
        "threats": result.threat_count,
        "best": best,
        "median": statistics.median(durations),
        "files_per_second": result.files_scanned / best if best else 0,
        "mb_per_second": (result.bytes_scanned / 1024 / 1024) / best if best else 0,
    }


def benchmark_detectors(path: Path, sample_size: int) -> list[dict[str, Any]]:
    """Time each detector individually over a sample of files."""
    config = load_config()
    config.paths.ensure()

    files = [p for p in path.rglob("*") if p.is_file()][:sample_size]
    if not files:
        print("no files to sample", file=sys.stderr)
        return []

    scanner = Scanner(config)
    rows: list[dict[str, Any]] = []
    try:
        detectors = scanner._build_detectors()
        print(f"\ntiming {len(detectors)} detector(s) over {len(files):,} files\n")

        for detector in detectors:
            considered = 0
            elapsed = 0.0
            detections = 0

            for file_path in files:
                target = ScanTarget(path=file_path)
                try:
                    if not detector.interested_in(target):
                        continue
                    considered += 1
                    started = time.perf_counter()
                    found = detector.scan(target)
                    elapsed += time.perf_counter() - started
                    detections += len(found)
                except Exception:
                    continue
                finally:
                    target.release()

            rows.append(
                {
                    "detector": detector.name,
                    "considered": considered,
                    "total_seconds": elapsed,
                    "per_file_ms": (elapsed / considered * 1000) if considered else 0.0,
                    "detections": detections,
                }
            )
    finally:
        scanner._teardown_detectors()
        scanner.close()

    return sorted(rows, key=lambda r: -r["total_seconds"])


def print_table(rows: list[dict[str, Any]], columns: list[tuple[str, str, str]]) -> None:
    """Render a simple fixed-width table."""
    widths = [max(len(header), 12) for header, _, _ in columns]
    print("  ".join(h.ljust(w) for (h, _, _), w in zip(columns, widths, strict=True)))
    print("  ".join("-" * w for w in widths))
    for row in rows:
        cells = []
        for (_, key, fmt), width in zip(columns, widths, strict=True):
            value = row.get(key, "")
            cells.append(format(value, fmt).ljust(width) if fmt else str(value).ljust(width))
        print("  ".join(cells))


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--path", type=Path, help="directory to scan")
    parser.add_argument("--generate", type=int, metavar="N",
                        help="generate a synthetic corpus of N files instead")
    parser.add_argument("--threads", default="0",
                        help="comma-separated thread counts to compare (0 = auto)")
    parser.add_argument("--repeats", type=int, default=3,
                        help="runs per configuration; the best is reported")
    parser.add_argument("--detectors", action="store_true",
                        help="also time each detector individually")
    parser.add_argument("--sample", type=int, default=300,
                        help="files sampled for per-detector timing")
    parser.add_argument("--keep", action="store_true",
                        help="keep the generated corpus")

    args = parser.parse_args()

    if not args.path and not args.generate:
        parser.error("provide --path or --generate")

    temporary: Path | None = None
    if args.generate:
        temporary = Path(tempfile.mkdtemp(prefix="sentinel-bench-"))
        target = generate_corpus(temporary / "corpus", args.generate)
    else:
        target = args.path.expanduser()
        if not target.is_dir():
            print(f"{target} is not a directory", file=sys.stderr)
            return 1

    # Keep the benchmark's own state out of the user's real data directory.
    if "SENTINEL_DATA_DIR" not in os.environ:
        os.environ["SENTINEL_DATA_DIR"] = str(
            (temporary or Path(tempfile.mkdtemp(prefix="sentinel-bench-"))) / "data"
        )

    try:
        thread_counts = [int(t.strip()) for t in args.threads.split(",") if t.strip()]

        print(f"scanning {target}\n")
        results = []
        for threads in thread_counts:
            label = "auto" if threads == 0 else str(threads)
            print(f"  threads={label}")
            results.append(benchmark_scan(target, threads, args.repeats))
            print()

        print("throughput\n")
        print_table(
            results,
            [
                ("threads", "threads", "d"),
                ("files", "files", ",d"),
                ("best (s)", "best", ".2f"),
                ("files/s", "files_per_second", ",.0f"),
                ("MB/s", "mb_per_second", ",.1f"),
                ("threats", "threats", "d"),
            ],
        )

        best = max(results, key=lambda r: r["files_per_second"])
        print(
            f"\nfastest: {best['threads'] or 'auto'} threads at "
            f"{best['files_per_second']:,.0f} files/s "
            f"({human_bytes(best['bytes'])} in {human_duration(best['best'])})"
        )

        if args.detectors:
            rows = benchmark_detectors(target, args.sample)
            if rows:
                print_table(
                    rows,
                    [
                        ("detector", "detector", ""),
                        ("files seen", "considered", ",d"),
                        ("total (s)", "total_seconds", ".3f"),
                        ("per file (ms)", "per_file_ms", ".3f"),
                        ("detections", "detections", ",d"),
                    ],
                )
                slowest = rows[0]
                print(
                    f"\nslowest: {slowest['detector']} at "
                    f"{slowest['per_file_ms']:.2f} ms/file"
                )
    finally:
        if temporary and not args.keep:
            shutil.rmtree(temporary, ignore_errors=True)
        elif temporary:
            print(f"\ncorpus kept at {temporary}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
