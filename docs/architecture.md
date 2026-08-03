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

### Measuring the machine

`system/hardware.py`, run once on first launch. Nobody is asked to choose a
performance mode — they cannot answer, and asking transfers the blame for a
decision they had no way to make. So Sentinel measures and decides.

The measurement that matters most is also the least obvious: **is the disk
spinning?** Parallel reads on a rotating platter make the head seek between
them and roughly halve throughput, so the right worker count on a hard disk
is one and the core count is irrelevant. Getting it backwards is a
forty-minute scan against a ninety-minute one.

Detection asks the OS first — `IOCTL_STORAGE_QUERY_PROPERTY` on Windows
(opened with no access rights, so it works unelevated),
`/sys/block/…/queue/rotational` on Linux, `diskutil` on macOS — and falls
back to timing twelve random reads, taking the median so one page-cache hit
and one unlucky outlier both fail to move the answer. Anything still unknown
is treated as rotating: conservative on an SSD costs some speed, wrong the
other way makes a hard disk thrash, and only one of those is recoverable by
waiting.

The result is applied *and written to the configuration file*. In-memory only
would mean the setting lasts exactly one run — the next start reloads
`threads = 0`, "decide automatically", which on a hard disk means many
workers on a drive already established to want one. Persisting also makes the
choice visible and editable, which is the point of telling the user at all.

### Two phases, and the time estimate

`engine/progress.py`. A scan on a spinning disk runs for tens of minutes, and
forty minutes with no idea how long is left reads as *frozen* — people kill
it. The estimate is not decoration; it is what makes a slow scan survivable.

The pipeline above runs twice. The first pass is `Scanner._enumerate`: the
same `FileWalker`, counting files and bytes and discarding the entries. Only
then does the real pass start, with totals in hand. Two traversals rather
than one because the alternatives are both worse — buffering a few million
`FileEntry` objects to save a `scandir` pass would cost more memory than the
entire scan is allowed, and showing a percentage derived from a total we do
not have means a bar that jumps backwards. The second walk mostly re-reads
directory metadata the OS has just cached, and costs nothing next to the file
reads that follow. `--no-estimate` skips it.

The estimate itself has three deliberate properties, all of them about being
believed rather than being precise:

- **It measures bytes, not files.** A directory of 2 KB configs and one
  holding a 4 GB disk image are the same "one file" to a counter, and an ETA
  built on file counts lurches every time the mix changes.
- **It rises slowly.** Falling is free; climbing is rationed to
  `MAX_ETA_GROWTH` seconds per second of wall clock. An estimate that jumps
  from five minutes to three hours because the scan hit a slow patch destroys
  confidence in every number the app shows. Below 1.0 the number still counts
  down while it stretches, and it can still recover — an estimate pinned at
  "almost done" forever is its own lie.
- **It says nothing until it knows something.** The opening seconds are
  thread ramp-up and cache warming, so any rate computed from them is wrong.
  Until there is enough evidence `eta_seconds` is `None` and the front ends
  say "estimating".

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

## Rule revocation (the kill switch)

`signatures/revocations.py`. A bad rule is worse than a missing one: it
quarantines something the user needs, on a machine we cannot reach, and the
fix would normally have to wait for the next signature version to be built,
published and pulled — which users who never update never get at all.

`revoked_rules.json` is fetched independently of the signature manifest, on
every update run rather than every version bump, and lists rules that must
not fire. The scanner drops matching detections in `_run_detectors`, before
aggregation — early enough that a revoked detection contributes nothing to
the score and a revoked *conclusive* one does not short-circuit the detectors
queued behind it.

A detection is matched on its name and on any `rule`, `signature`,
`heuristic` or `id` in its metadata, so a YARA rule can be revoked by rule
name even though the detection reports a threat name. Entries may be scoped
to one detector and may carry an ISO-8601 `expires` date.

Three properties are load-bearing:

1. **Revocations only ever remove detections.** The worst a hostile or
   corrupt list can do is make the scanner miss things; it can never cause a
   file to be quarantined. That is why the file needs no manifest checksum —
   anyone able to serve a malicious revocation list can already serve empty
   signature bundles.
2. **It fails open.** Missing, unreachable, oversized or malformed lists
   leave every rule active. A kill switch that disables the scanner when it
   breaks is a worse bug than the one it exists to fix. A download that will
   not parse is discarded rather than installed, so a corrupt fetch cannot
   silently un-revoke what the last good copy had disabled.
3. **No wildcards, and a hard cap on breadth.** "Disable everything matching
   `Trojan.*`" is not a switch anyone should be able to flip remotely, and a
   list arriving with more than 10,000 entries is rejected whole.

## The guard list, and who is allowed to act

`engine/guard.py`. One failure mode ends a project like this: a signature is
wrong, it matches something the operating system needs, the file is
quarantined, and a stranger's machine will not boot. They cannot undo it —
the computer that would run the undo is the one that will not start.

So acting on a file requires passing two independent gates, and a detector
being confident is only one of them.

**Gate one — is this file allowed to be touched at all?** `Guard.check` is
called inside `Quarantine.quarantine()`, not by its callers, so every route
into the vault goes through it and none can forget to. There is no setting to
disable it. Protected: operating-system directories, Sentinel's own install
and data directories, filesystem roots, anything that is not an ordinary
file, and OS-vendor-signed binaries. Application directories such as
`Program Files` are deliberately not protected — malware installs there
routinely, and blanket-protecting application space would blind the scanner
to a whole class of real threats to buy protection the OS directories already
give.

**Gate two — is this finding certain enough to act on?** Only *conclusive*
detections, meaning an exact digest match against a known sample, are acted
on automatically. Heuristics never are, however many fire. Six independent
script heuristics aggregate to 93, which is CRITICAL and clears any severity
threshold, and each one is a guess about what code looks like rather than
knowledge of what it is. Those findings are reported in full and left alone.

The two gates fail differently on purpose. A guarded file is marked
`protected`, not `quarantine-failed`: a refusal that protected the user is
not an error they need to chase.

### Why heuristics are suppressed on vendor-signed binaries

Structural heuristics are near-worthless applied to the operating system's
own components. Windows' App-V subsystem imports the complete
process-injection API set — `VirtualAllocEx`, `WriteProcessMemory`,
`CreateRemoteThread` — because injecting into processes is precisely what it
exists to do. So a non-conclusive finding on a binary signed by the OS vendor
is dropped. Conclusive detections are not: certificates get stolen, but not
the OS vendor's. The check costs about 2ms, and is reached only when
something was already going to be reported, so the overwhelmingly common case
— a clean file — never pays for it.

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

### The tray, and why its state is derived

`ui/tray_state.py` holds no Qt at all, because the interesting part is a
decision rather than a widget.

Several things are true at once. A scan is running, two files are in the
vault from yesterday, and the threat list is nine days old — three truths and
one icon. The classic antivirus bug is to track the *last event* instead: the
scan finishes clean, so the icon goes green, and the two files nobody has
looked at disappear from the user's awareness. They believe they are fine.

So `TrayStatus` is a frozen snapshot of every fact, constructed fresh from
the world by `status_from_world` rather than mutated by events, and
`TrayStatus.state` picks the icon by priority:

```
THREAT  >  DISABLED  >  SCANNING  >  ATTENTION  >  SAFE
```

`SAFE` is last, so it is reachable only when nothing else is true. The
tooltip then carries the facts that lost, because the reason the priority
list exists is that more than one thing is true and the losers still matter.
`headline` and `detail` test their conditions in the same order, so the two
lines always describe the same thing.

### Icons at 16 pixels

`ui/icons.py` draws rather than ships bitmaps: a tray icon has to be correct
at 16px on a 100% display and 44px on a 275% one, and scaling one image
between those looks like a smudge.

They are distinguished by **silhouette first, colour second, glyph third**.
At 16px in peripheral vision colour is the least reliable signal available —
6-8% of men cannot separate the coral from the jade, and a dark taskbar
drains apparent saturation. So: solid shield for `SAFE`, a ring for
`SCANNING`, outline-only for `DISABLED`, and a badge notched into the outline
for the two that need attention.

`THREAT` and `ATTENTION` are the pair at risk of collapsing together, since
both are "filled shield with a badge". The glyph cannot separate them — at
16px it is about seven pixels across — so the **badge outline** differs: a
circle for threat, a triangle for attention, which is also the convention
from every other piece of software. `tests/test_tray.py` renders all ten
pairs in greyscale at 16px and fails if fewer than 30 of 256 pixels differ.

### The resource line

`system/resources.py`, shown permanently in the flyout. Unusual, and
deliberate: the people this is for are on 4 GB and a spinning disk, many have
been burned by security software that ate their computer, and they have no
way to check whether this one does the same. So the number is always visible
and never flattering — no smoothing that hides a spike, no `<1%` floor, and
CPU as a share of one core, which is what the eco-mode budget is written in
and what Task Manager will agree with.

## Server

Optional FastAPI service under `server/`. Collects reports, serves hash
reputation, receives telemetry.

Auth and rate-limit dependencies live in `server/storage.py` rather than
`server/main.py`, so routers can import them without a cycle through the
app module.

Telemetry has no client identifier column, by design. Two submissions from
one machine cannot be linked. That is a real constraint — it means the data
cannot answer "how many unique users" — and it is the intended trade.
