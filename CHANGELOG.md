# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Changes to **what leaves the machine** are always breaking changes, however
small, and are called out under their own heading.

## [Unreleased]

Nothing yet.

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
