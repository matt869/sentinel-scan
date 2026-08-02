# Architecture

## Layering

The package is strictly layered. Each layer may import from the ones above
it, never below. Breaking this is the fastest way to create an import cycle
and a slow `--help`.

```
utils        pure helpers — hashing, entropy, file types, formatting
  ↑
core         config, logging, event bus, local SQLite database
  ↑
signatures   locating and updating signature data
  ↑
engine       detectors, traversal, scheduling, scoring, quarantine
  ↑
system       OS inspection (processes, autoruns, drives, hosts file)
  ↑
feedback     optional reporting to a server
  ↑
cli / ui     user-facing front ends
```

`server/` is a separate top-level package. The client never imports it and
`pip install sentinel-scan` does not install it.

## The scan pipeline

```
   roots
     │
     ▼
┌──────────────┐   FileEntry    ┌──────────────┐
│  FileWalker  │ ─────────────▶ │  WorkerPool  │  bounded queue,
│              │                │  (N threads) │  fixed memory
└──────────────┘                └──────┬───────┘
  os.scandir, skips                    │  ScanTarget
  symlinks, junctions,                 ▼
  cloud placeholders,          ┌───────────────┐
  excluded paths               │   whitelist   │──▶ suppressed
                               └───────┬───────┘
                                       │
                                       ▼
                               ┌───────────────┐
                               │ result cache  │──▶ cached clean verdict
                               └───────┬───────┘
                                       │
                                       ▼
                   ┌───────────────────────────────────┐
                   │  detectors, in priority order     │
                   │   10 hash      cheap, decisive    │
                   │   20 cloud     opt-in             │
                   │   30 clamav                       │
                   │   40 yara                         │
                   │   45 script                       │
                   │   50 pe_heuristic                 │
                   │   60 archive ──┐                  │
                   └────────────────│──────────────────┘
                                    │ extracted members re-enter
                                    └─▶ the pipeline (depth-bounded)
                                       │
                                       ▼
                               ┌───────────────┐
                               │   aggregate   │  noisy-OR
                               └───────┬───────┘
                                       ▼
                                    Verdict ──▶ EventBus ──▶ CLI / GUI
                                       │
                                       ▼
                                  SQLite history
```

### Why a custom worker pool

`ThreadPoolExecutor.map` drains its input eagerly. Pointed at a full-disk
walk it buffers millions of `Future` objects before the first file is
scanned, and the process dies of memory exhaustion long before it runs out
of files.

`engine/queue.py` puts a bounded queue between the walker and the workers,
so traversal proceeds only as fast as scanning consumes it. Memory stays
flat whatever the tree size.

### Short-circuiting

Detectors are ordered by `priority`. The hash detector runs first because it
is a single index probe and its answer is definitive. When any detector
returns a `conclusive` detection, the remaining detectors are skipped for
that file — there is no point running YARA and a PE parse over a file we
have already identified exactly.

### Threading

- The walker runs on one producer thread.
- Detectors run on N worker threads (`scan.threads`, default: CPU count
  capped at 16).
- `ScanTarget` memoises the file's bytes, hashes, type and entropy behind an
  **`RLock`** — re-entrant because the memoised properties call each other
  (`type_info` → `header`, `entropy` → `data`). A plain `Lock` deadlocks the
  worker on the second acquire.
- The database keeps one connection per thread in a `threading.local`, with
  WAL enabled and writes serialised by a lock.
- The event bus copies its handler list under a lock and invokes handlers
  outside it, so a handler may subscribe or unsubscribe without deadlocking.

## Scoring

`engine/verdict.py`. Each detection carries a confidence in 0–100. They
combine with a noisy-OR:

```
combined = 1 − Π (1 − confidence_i)
```

Two independent 50% signals give 75, not 100. Five weak 20% signals give 67
— the "lots of small smells" case that catches obfuscated droppers.

Two properties are load-bearing:

1. **Non-conclusive scores are capped at 99.** Without the cap, twenty
   detections at 30% reach 99.92 and round to 100, making a pile of guesses
   indistinguishable from an exact hash match. Heuristics do not get to
   claim certainty however many of them fire.
2. **`Severity` defines all four comparison operators.** It subclasses
   `str`, so any operator left undefined falls back to lexicographic
   ordering — under which `"critical" >= "medium"` is `False` and every
   threat check silently becomes a no-op.

Severity bands: `<30` clean, `30–49` low, `50–69` medium, `70–89` high,
`90+` critical. A file is a *threat* at medium and above.

## Detectors

The contract is in `engine/detectors/base.py`. Rules:

- **Never raise.** A detector that throws is logged and skipped for that
  file. Return an empty sequence when undecided.
- **Never mutate the target.** Detectors run concurrently on one object.
- **Read through the target**, not the path, so eight detectors do not read
  the same file eight times.
- **Declare `wants`** so the engine can skip you without touching the file.

Registration is by decorator into a module-level registry. The engine builds
the enabled, available subset per scan. A detector whose optional dependency
is missing reports itself unavailable and is skipped — a normal state, not
an error.

See `docs/writing-detectors.md`.

## Quarantine

`engine/quarantine.py`. Files move into a vault under the data directory,
stored with a SHA-256 counter-mode keystream.

What that buys, precisely: the file cannot be executed, double-clicked,
indexed, or re-detected in a loop by another scanner. What it does not buy:
confidentiality against someone holding the vault key, which sits beside the
vault. It cannot be otherwise — restoring has to work without prompting for
a passphrase the user never set.

Format: `magic(4) version(2) nonce(16) size(8) sha256(32)` then the
obfuscated payload. Restores verify the digest before writing anything back,
so a corrupt vault cannot silently restore garbage. Writes go to a temp file
and are renamed, so a crash never leaves a half-written file that looks
restorable.

## Events

`core/events.py` is a small synchronous pub/sub bus. The engine emits;
front ends subscribe. Handlers run on the **emitting** thread — usually a
scan worker — so they must do almost nothing. The CLI increments a counter;
the GUI forwards to a Qt signal, which marshals to the GUI thread.

An exception in a handler is logged and swallowed. A broken progress bar
must never abort a scan.

## Storage

One SQLite file under the data directory:

| Table | Holds |
|---|---|
| `scans` | one row per scan, with totals |
| `findings` | threats and suspicious files per scan |
| `quarantine` | vault index: original path, hash, nonce, metadata |
| `whitelist` | sha256 / path / prefix suppressions |
| `scan_cache` | fingerprint → clean verdict, to skip unchanged files |
| `kv` | last update check and similar |

Migrations are an append-only list in `core/db.py` keyed on
`PRAGMA user_version`. Never edit a released migration.

The cache stores **clean results only**. A finding is always re-derived, so
the user gets the full detection list; the cache exists to skip the millions
of clean files, not the handful of bad ones.

## Front ends

**CLI** (`cli/commands.py`) — Typer plus Rich. Exit codes follow the ClamAV
convention: 0 clean, 1 threats found, 2 errors. `--json` moves all logging
to stderr so stdout stays parseable.

One trap worth knowing: Rich parses `[...]` as markup, so every
data-derived string is passed through `rich.markup.escape`. Without it,
`pip install 'sentinel-scan[all]'` renders as `pip install 'sentinel-scan'`
— telling the user the wrong command.

**GUI** (`ui/`) — PySide6, four pages. `ScanWorker` runs a scan on a
`QThread` and re-publishes engine events as Qt signals; views never touch
engine threads. Importing `sentinel.ui` does not import PySide6, so the CLI
works on a machine with no Qt.

## Server

Optional FastAPI service under `server/`. Collects reports, serves hash
reputation, receives telemetry.

Auth and rate-limit dependencies live in `server/storage.py` rather than
`server/main.py`, so routers can import them without a cycle through the
app module.

Telemetry has no client identifier column, by design. Two submissions from
one machine cannot be linked. That is a real constraint — it means the data
cannot answer "how many unique users" — and it is the intended trade.
