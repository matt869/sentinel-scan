<h1 align="center">Sentinel Scan</h1>

<p align="center">
  An open-source, cross-platform malware scanner with a pluggable detection
  engine.<br>
  Command line, desktop GUI, and a Python API.
</p>

<p align="center">
  <a href="#quick-start">Quick start</a> ·
  <a href="#what-it-does">What it does</a> ·
  <a href="docs/privacy.md">Privacy</a> ·
  <a href="docs/architecture.md">Architecture</a> ·
  <a href="docs/writing-detectors.md">Write a detector</a>
</p>

---

## Two things to know first

**It runs offline.** A default installation makes no network requests at
all — not for updates, telemetry or lookups. Every feature that could send
data is off until you turn it on, and [`docs/privacy.md`](docs/privacy.md)
lists exactly what each one transmits.

**It is not a replacement for real-time protection.** There is no kernel
driver, no on-access scanning and no memory analysis, so anything already
running is out of scope. Use it alongside your platform's built-in
protection, not instead of it. The honest numbers, including where it is
weak, are in [`docs/detection-rates.md`](docs/detection-rates.md).

## Quick start

```bash
pip install sentinel-scan          # core
pip install 'sentinel-scan[all]'   # with YARA, PE analysis and the GUI
```

```bash
sentinel scan ~/Downloads          # scan a folder
sentinel scan                      # quick scan of the high-risk locations
sentinel scan --full               # every fixed drive (slow)
sentinel detectors                 # what is active, and why anything is not
sentinel status                    # versions, vault size, privacy settings
sentinel gui                       # desktop interface
```

Exit codes follow the ClamAV convention — `0` clean, `1` threats found,
`2` errors — so it drops into existing scripts:

```bash
sentinel scan ~/Downloads || notify-send "Sentinel found something"
```

Verify it works with the EICAR test file, a harmless string every scanner is
expected to flag:

```bash
python -c "print('X5O!P%@AP[4\\PZX54(P^)7CC)7}\$' + 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE' + '!\$H+H*', end='')" > eicar.com
sentinel scan eicar.com
```

## What it does

### Seven detectors, scored together

| Detector | Looks for | Needs |
|---|---|---|
| `hash` | Exact matches against known samples | — |
| `yara` | Pattern rules | `yara-python` |
| `pe_heuristic` | Packing, injection imports, entry-point anomalies, masquerading | `pefile` |
| `script` | Obfuscated PowerShell/JS/VBS, download-and-execute, ransomware preparation | — |
| `archive` | Decompression bombs, path traversal, RTL-override names; scans members | — |
| `clamav` | ClamAV signatures | a running `clamd` |
| `cloud` | Hash reputation (opt-in, hashes only) | a server |

A missing optional dependency is a normal state: the detector reports itself
unavailable and the scan continues.

### Signals combine, they do not shout

Each detection carries a confidence. They combine with a noisy-OR, so two
independent 50% signals give 75 rather than 100, and five weak 20% signals
give 67 — the "lots of small smells" case that catches obfuscated droppers.

A score of exactly **100 means a definitive identification**. Heuristics are
capped at 99 no matter how many fire, so a pile of guesses can never imitate
an exact hash match.

```
┌─────────────────────────────────────────────────────────────────┐
│ C:\...\Downloads\invoice_2026.ps1                               │
│   critical  score 95/100  1.2 KiB                               │
│                                                                 │
│   · script Heuristic.Script.Dropper (60%)                       │
│       Downloads a remote script and executes it in memory —     │
│       the standard PowerShell dropper pattern                   │
│   · script Heuristic.Script.ps_bypass (35%)                     │
│       Disables the PowerShell execution policy                  │
│   · script Heuristic.Script.ps_hidden_window (25%)              │
│       Runs with no visible window                               │
└─────────────────────────────────────────────────────────────────┘
```

Every finding explains itself in plain language, because the person deciding
whether to delete a file is usually not a malware analyst.

### Reversible quarantine

Files move into a vault, stored obfuscated so they cannot be run, opened or
indexed by accident. Restores verify the hash recorded at quarantine time
before writing anything back.

```bash
sentinel quarantine list
sentinel quarantine restore <token>
sentinel quarantine purge --older-than 30
```

This is containment, not secrecy — the key sits beside the vault because
restoring must work without a passphrase you never set. Said plainly in
[`docs/privacy.md`](docs/privacy.md).

### System inspection

```bash
sentinel system            # autoruns, processes, drives, hosts file
sentinel system --scan     # scan every file referenced by an autorun entry
```

That last one is the best value-per-second check available: a few dozen
files covering everything configured to run at boot.

Everything here is read-only reporting. Sentinel does not edit your
registry, rewrite your hosts file, or kill processes on its own.

### Desktop GUI

`sentinel gui` — four pages (Scan, Results, Quarantine, Settings) over the
same engine. Scans run on a worker thread; findings stream in live.

## Using it as a library

```python
from sentinel import Scanner, load_config

with Scanner(load_config()) as scanner:
    result = scanner.scan_paths(["/home/me/Downloads"])

    print(f"{result.files_scanned:,} files in {result.duration:.1f}s")
    for finding in result.threats:
        print(f"{finding.severity.value:>8}  {finding.name}  {finding.path}")
        for detection in finding.detections:
            print(f"           {detection.detector}: {detection.description}")
```

Subscribe to `scanner.bus` for live progress. Note that handlers run on the
emitting worker thread, so keep them trivial.

## Configuration

```bash
sentinel config init      # write a config file with the current defaults
sentinel config path      # where it lives
sentinel config show      # what is actually in effect
```

Precedence: CLI flags → `SENTINEL_*` environment variables → `config.toml`
→ built-in defaults. See [`.env.example`](.env.example) for every variable.

```toml
[scan]
threads = 0                # 0 = auto (CPU count, capped at 16)
archive_depth = 2
threat_threshold = 60

[detectors]
yara = true
clamav = false

[privacy]
server_url = ""            # empty = fully offline
telemetry = false
allow_sample_upload = false
```

## Reporting a bad verdict

False positives are the highest-priority bug class in this project. A
scanner that condemns people's own software stops being trusted for
anything.

```bash
sentinel report path/to/file --false-positive -c "this is my own build output"
sentinel report path/to/file --missed -c "this is definitely malware"
```

You see the complete payload before anything is sent. With no server
configured it becomes a pre-filled GitHub issue you review and submit
yourself — nothing is transmitted by us at all.

**Never attach a malware sample to a public issue.** Send a hash.

## Development

```bash
git clone https://github.com/sentinel-scan/sentinel-scan
cd sentinel-scan
python -m venv .venv && source .venv/bin/activate   # .venv\Scripts\activate on Windows
pip install -e ".[all]" -r requirements-dev.txt

pytest                                    # 145 tests
ruff check src server scripts tests
python scripts/benchmark.py --generate 2000 --threads 1,4,8 --detectors
```

The optional reporting server:

```bash
uvicorn server.main:app --reload          # http://127.0.0.1:8000/docs
docker compose -f server/docker-compose.yml up
```

### Layout

```
src/sentinel/
  utils/        pure helpers (no internal imports)
  core/         config, logging, events, SQLite
  signatures/   loading and updating signature data
  engine/       detectors, walker, worker pool, scoring, quarantine
  system/       processes, autoruns, drives, hosts file
  feedback/     optional reporting (all opt-in)
  cli/  ui/     front ends
server/         optional FastAPI reporting service
```

Layers import downward only. [`docs/architecture.md`](docs/architecture.md)
explains why, and documents the two traps that cost real debugging time —
the re-entrant lock in `ScanTarget` and `Severity` needing all four
comparison operators because it subclasses `str`.

### Adding a detector

[`docs/writing-detectors.md`](docs/writing-detectors.md) has the contract, a
confidence calibration table and a worked example. The short version:

```python
@registry.register
class MyDetector(Detector):
    name = "my_detector"
    wants = frozenset({FileType.PE})

    def scan(self, target: ScanTarget) -> list[Detection]:
        return [self.detection("Heuristic.Thing", 45.0, "Plain English.")]
```

Score conservatively, never raise, and test against a corpus of clean files
before proposing it.

## Documentation

| | |
|---|---|
| [Architecture](docs/architecture.md) | How the pipeline fits together |
| [Writing detectors](docs/writing-detectors.md) | The plugin contract and calibration |
| [Privacy](docs/privacy.md) | Exactly what leaves the machine, and when |
| [Detection rates](docs/detection-rates.md) | Measured results, including the weak spots |
| [FAQ](docs/faq.md) | Common questions |
| [Security policy](.github/SECURITY.md) | Reporting vulnerabilities |
| [Contributing](CONTRIBUTING.md) | How to help |

## Licence

MIT — see [LICENSE](LICENSE).

Signature data carries its own terms. ClamAV databases are GPL-2.0 and
distributed by Cisco Systems, Inc.; they are fetched from upstream at update
time rather than redistributed here. Third-party YARA rule sets keep their
authors' licences, recorded in
[`manifest.json`](src/sentinel/signatures/manifest.json).
