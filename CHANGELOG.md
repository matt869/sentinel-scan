# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Changes to **what leaves the machine** are always breaking changes, however
small, and are called out under their own heading.

## [Unreleased]

### Added

- **Rule revocation — the kill switch.** `revoked_rules.json` is fetched from
  the mirror on every update run and disables named rules locally. Detections
  matching a revoked rule are dropped before scoring, so a rule that turns out
  to quarantine people's files stops firing within hours instead of waiting
  for the next signature release. Revocations can only ever *remove* a
  detection, never add one, and a missing, unreachable or malformed list
  leaves every rule active — a kill switch that fails closed would be worse
  than the bug it exists to switch off. Entries may be scoped to one detector
  and may carry an expiry date; wildcards are refused and a list over 10,000
  entries is rejected outright.
- `updates.honor_revocations` and `updates.revocation_url` settings, and a
  "Revoked rules" row in `sentinel status`.
- The revocation list is refreshed in the background when a scan starts, rate
  limited by `updates.check_interval_hours`. Only the list, never the
  signature bundles: a few kilobytes is worth fetching unasked, hundreds of
  megabytes on a metered connection is not.
- **A time estimate that does not lie.** Scans now run in two phases. The
  first counts the tree and reports a running total, because a percentage
  before that is a guess that jumps backwards the moment a large directory
  turns up. The second shows a real bar and a time remaining. The estimate
  measures *bytes*, not files — a directory of 2 KB configs and one holding a
  4 GB disk image are the same "one file" to a counter — says nothing for the
  first few seconds while the rate is still meaningless, and rises only
  slowly, so hitting a slow patch stretches the estimate instead of making it
  leap from five minutes to three hours. Wording is deliberately vague:
  "about 12 minutes" is a promise that can be kept.
- `sentinel scan --no-estimate` skips the counting pass for anyone who would
  rather start reading files immediately. `--json` skips it automatically.
- `SCAN_ENUMERATING` event, and `SCAN_PROGRESS` payloads gained `phase`,
  `files_total`, `bytes_total`, `fraction` and `eta_seconds`. The existing
  `files_scanned`, `bytes_scanned` and `current` keys are unchanged.

### Changed

- `ScanWorker.progress` (GUI) now carries the whole progress payload as a
  dict instead of `(files, bytes, current)`, and is joined by
  `ScanWorker.enumerating`.

### Fixed

- **A file that could not be read was reported clean, and cached as clean.**
  The read-error check ran before the file had been opened, so it never saw
  anything; the failure actually surfaced one line later, when the digest was
  computed, and nothing rechecked it. Files that were locked, permission-denied
  or removed mid-scan therefore reached every content detector with no
  contents to inspect and came out the far end looking fine. They are now
  reported as errors, excluded from the result cache, and called out in the
  scan summary rather than sitting in a count.
- **The quarantine vault key was written corrupt on roughly one Windows
  install in eight.** `os.open` defaults to text mode on Windows, so every
  `0x0A` byte in the 32-byte random key was written as `0x0D 0x0A`. The
  oversized key then failed its length check on every subsequent run,
  permanently, and nothing already in the vault could be restored.

## [0.4.0] — 2026-08-02

First public beta. The scanner, both front ends, the optional reporting
server and the packaging pipeline are all in place.

### Added

**Detection engine**

- Seven detectors behind a common plugin contract: `hash`, `yara`,
  `pe_heuristic`, `script`, `archive`, `clamav` and `cloud`. A detector
  whose optional dependency is missing reports itself unavailable and is
  skipped rather than failing the scan.
- Noisy-OR score aggregation, so independent weak signals accumulate without
  any one of them having to be alarming on its own.
- Conclusive detections short-circuit the pipeline — an exact hash match
  does not pay for a YARA run and a PE parse.
- Archive members are extracted and re-enter the full pipeline, with hits
  re-attributed to the containing archive.
- Bounded producer/consumer worker pool, so memory stays flat regardless of
  tree size.
- Result cache keyed on a cheap fingerprint, storing clean verdicts only.

**Detectors of note**

- `script` scores *techniques* rather than keywords, with combination rules
  that fire when several appear together — the download-and-execute pattern,
  ransomware recovery destruction, encoded payload plus evaluation.
- `pe_heuristic` covers packer sections, section entropy, writable-executable
  sections, process-injection import sets, entry points outside any section,
  checksum mismatches, large overlays, masquerading extensions and double
  extensions.
- `archive` flags decompression bombs, path traversal, right-to-left
  override filenames, link escapes and encrypted archives containing
  executables.

**Quarantine**

- Reversible vault with a SHA-256 counter-mode keystream, so quarantined
  files cannot be executed, opened or indexed by accident.
- Restores verify the digest recorded at quarantine time before writing
  anything back; a corrupt vault file is refused rather than silently
  restored.
- Atomic writes throughout — a crash never leaves a half-written file that
  looks restorable.
- Refuses to quarantine Sentinel's own database, logs or vault key.

**Front ends**

- `sentinel` CLI with `scan`, `detectors`, `status`, `history`, `update`,
  `quarantine`, `whitelist`, `system`, `report`, `telemetry`, `config` and
  `gui`. Exit codes follow the ClamAV convention.
- `--json` writes a machine-readable report to stdout with all logging
  diverted to stderr.
- PySide6 desktop GUI: Scan, Results, Quarantine and Settings, with scans on
  a worker thread and findings streaming in live.

**System inspection**

- Read-only reporting of autoruns, processes, drives and the hosts file
  across Windows, macOS and Linux.
- `sentinel system --scan` scans every file referenced by an autorun entry.

**Server**

- Optional FastAPI service for reports, hash reputation and telemetry.
- Automatic triage that scores incoming reports, weighting false positives
  above missed detections and explaining each score in plain language.
- Sample uploads gated on consent recorded at report time, with the uploaded
  bytes verified against the hash the report describes.

**Project**

- 145 tests covering scoring, traversal, quarantine round trips, whitelist
  safety and every privacy invariant.
- PyInstaller spec and Inno Setup installer for Windows, plus an
  Authenticode signing script.
- CI across Windows, macOS and Linux on Python 3.10–3.12; CodeQL; automated
  signature bundle builds.
- Documentation: architecture, detector authoring, privacy, measured
  detection rates including the weak spots, and an FAQ.

### Privacy

- **A default installation makes no network requests at all.** Updates,
  telemetry, cloud lookup and sample upload are each independently off.
- Telemetry carries **no installation identifier** — batches cannot be
  linked to each other or to a machine. Counts are bucketed.
- `sentinel telemetry --preview` prints exactly what would be sent, and
  sends nothing.
- Reports exclude the full file path; only the basename, size and hashes go.
- Sample upload requires the setting *and* per-file consent. Credential and
  key files are refused at any setting; documents and images require a
  second confirmation.
- Server-side, submitter IPs are salted-hashed for rate limiting only and
  appear in no schema.

### Fixed

Three defects found by the test suite during development, recorded because
each is a trap worth knowing about:

- **Re-entrant deadlock in `ScanTarget`.** The memoised properties call each
  other (`type_info` → `header`, `entropy` → `data`) while holding the lock.
  With a plain `threading.Lock` the first worker thread deadlocked on the
  second acquire and the scan hung forever. Now an `RLock`.
- **`Severity` comparisons fell through to string ordering.** It subclasses
  `str`, and only `__lt__`/`__le__` were defined, so `>=` used
  lexicographic comparison — under which `"critical" >= "medium"` is
  `False`. Every threat check silently reported zero threats. All four
  operators are now defined in terms of rank.
- **Heuristic scores could reach 100.** Twenty detections at 30% confidence
  reach 99.92 under noisy-OR and round to 100, making a pile of guesses
  indistinguishable from an exact hash match. Non-conclusive aggregation is
  now capped at 99, so a score of exactly 100 always means a definite
  identification.

Also fixed:

- The GitHub issue fallback embedded the full user comment in its
  "too long" path, so an oversized report still produced an oversized URL.
  It now truncates progressively until the URL fits.
- Rich markup escaping in the CLI. Extras like `sentinel-scan[all]` were
  parsed as markup tags and rendered as `sentinel-scan`, telling users the
  wrong install command. All data-derived output is now escaped.

### Known limitations

Stated plainly; see `docs/detection-rates.md` for measurements.

- No Office macro extraction. Macro-bearing documents are only caught by
  hash or a container rule — the largest gap in coverage.
- .NET assemblies largely bypass `pe_heuristic`, which reads native PE
  structure.
- No real-time, on-access or memory scanning. Anything already running is
  out of scope. Use alongside your platform's built-in protection.
- RAR, 7z and CAB archives are identified but not opened.
- `pe_heuristic` produces roughly 86% of observed false positives while
  contributing 38% of detection. Calibration work is ongoing.

[Unreleased]: https://github.com/sentinel-scan/sentinel-scan/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/sentinel-scan/sentinel-scan/releases/tag/v0.4.0
