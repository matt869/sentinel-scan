# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Changes to **what leaves the machine** are always breaking changes, however
small, and are called out under their own heading.

## [Unreleased]

### Changed — the window, simplified

- **The stylesheet was never reaching the window.** `ui/app.main` sets it on
  the QApplication, which covers `sentinel gui` and nothing else — so a window
  built directly, which is what the CI smoke check and any embedding caller
  do, came up in Qt's default palette. Nothing caught it, because a window
  renders perfectly well unstyled and "did it build?" was the only question
  being asked. The window now applies the theme itself when the application
  has not, and there are tests for the theme rather than only for the build.
- **Group boxes are gone.** Three bordered boxes on the scan page and five on
  settings is a stack of rectangles competing for the same attention with a
  1px line each. Nothing on those pages was ambiguous about which control
  belonged to which heading — they are laid out one under another — so the
  border was decoration. Grouping is done with space now, via a small
  `Section` widget, and borders are kept for the two places they mean
  something: a field you can type into, and a table of data.
- **Section titles are small, capitalised and letter-spaced**, set on the
  QFont rather than in the stylesheet — Qt's QSS subset has neither
  `text-transform` nor `letter-spacing` and ignores both silently, which is
  why the first attempt rendered as body text sitting flush against its own
  contents, reading as the first item in the list rather than the name of it.
- **The folder picker is hidden until Custom is chosen**, rather than greyed
  out. A disabled list box and two dead buttons, shown to everybody who picked
  Quick, was a third of the page spent on a mode they are not in — and a
  control you can see but cannot use is a question you have to stop and
  answer.
- **Progress is hidden until there is any.** Before the first scan that
  section was a title, the words "Not running", and a large empty rectangle.
  It stays once a scan has run, because last time's result is what somebody
  comes back to the page to read.
- **One accent colour**, spent only on the primary action and the selected
  page. On a page where one button starts a forty-minute job it needs to be
  obvious which one that is. The selected-page marker is on every sidebar row
  and transparent until selected, so switching pages no longer shifts the
  labels 3px sideways.
- Numeric settings fields are one fixed width instead of stretching to the
  window; a 700-pixel box holding "8" promises something long and puts the
  value miles from its label.

### Added — background scanning that gets out of the way

The full-disk scan takes tens of minutes on the hardware this is built for,
and sometimes ninety on a spinning disk. It has to happen, because a scanner
that runs only when the user remembers to click it runs twice. It must also
never be the reason somebody's computer is slow. New `daemon/` package,
holding those two problems separately.

- **A throttle governor decides how hard the scan may work**, sampling what
  the machine is doing and pacing the workers between files. The pause is
  derived from how long each file took, so one duty cycle is right for a 2 KB
  config and a 400 MB installer alike. Every decision carries a reason in
  plain English, shown in the flyout, so *why is my computer slow* is never
  an unanswered question.
- **On Windows the process also drops into background I/O priority** while
  throttled. Sleeping between files gives the disk back only in the gaps —
  while one of our reads is queued it competes with the user's on equal
  terms, and the read that makes them wait is the one already in flight.
  Priority is what fixes that; the duty cycle is what stops us taking the
  whole disk when nobody is there. Neither replaces the other.
- **The governor subtracts its own CPU use before deciding the machine is
  busy.** Without that it reads 60% system-wide, backs off, discovers the 55
  points that were its own have gone, speeds up, and oscillates — a feedback
  loop from measuring our own output as somebody else's input, not noise to
  be smoothed away.
- **Backing off is immediate; recovering waits for sustained calm.** The
  costs are not symmetric: a slow back-off is felt as a computer that
  stutters when you sit down at it, a slow recovery costs only throughput
  while nobody is watching. A pace the user chose themselves bypasses the
  delay, because a Resume button that takes thirty seconds reads as broken.
- **An idle scheduler runs the scan when nobody is at the machine**, and
  checkpoints it so an interrupted one resumes rather than restarting. On a
  machine used every day, restarting from zero means the first fifth of the
  disk is scanned forever and the rest never looked at. Only completed runs
  reset the interval, so a machine that is never idle for long cannot report
  itself scanned without having been.
- **Not a nightly 3 a.m. scan.** That runs on machines awake at 3 a.m., which
  describes servers, not the desktop switched off at the wall. The trigger is
  idleness; the clock only enforces a minimum gap, at 20 hours rather than 24
  so the window re-anchors instead of drifting later each day until it starts
  skipping.
- **The threshold widens when the user keeps coming back.** Somebody who
  steps away for six minutes at a time would otherwise be interrupted by a
  starting scan over and over, which is how a program becomes the thing you
  disable.
- **Idle detection** via `GetLastInputInfo`, `XScreenSaverQueryInfo` and
  `ioreg`, in the new `system/idle.py`. It measures time since the last
  keyboard or mouse input rather than CPU, because a machine compiling
  overnight with nobody in the room is busy but idle. A platform that cannot
  tell reports so, and unknown counts as *the user is present*.

Five bugs found and fixed while writing the tests, all of the kind that
produce no error and no log line:

- `GetTickCount` wraps every 49.7 days, and the value `GetLastInputInfo`
  returns lives in that space. Subtracting in Python's unbounded integers
  gives a *negative* idle time for the 49.7 days after each wrap, which reads
  as "the user is here" — so a machine with long uptime would quietly never
  run a background scan again.
- The scan attempt was launched inline from the scheduler's poll loop, which
  blocked the very loop whose job is noticing that the user has come back.
  The scan would have run to completion under somebody who had sat back down
  — precisely the thing the scheduler exists to prevent.
- Parked workers each forced their own sample of the machine. Eight workers
  meant eight reads per interval, and `cpu_percent` diffs against its own
  previous call — so seven of them returned near-zero, and the governor would
  have concluded the machine was idle *because* it was asking too often.
- `close()` broadcast a wakeup, but a parked worker only leaves when the
  budget lets it run again, so closing a paused governor stranded every
  worker in the loop. Shutting down mid-pause is exactly when somebody is
  waiting for the app to exit.
- One worker clearing the shared wakeup event could swallow a wakeup meant
  for the others, who then slept out the full pause after the reason for it
  had gone. Replaced with a `Condition` and `notify_all`, which has no such
  window.

### Changed — idle memory: 107 MB → 66 MB

The only performance budget the project was breaching. Profiled rather than
guessed at, by measuring each layer in its own interpreter:

| | |
|---|---|
| Python interpreter | 17.6 MB |
| Qt | +23.8 |
| stylesheet | +8.1 |
| database | +1.4 |
| the four window pages | +12.2 |
| tray + flyout | +2.8 |

- **The main window is now built on first request, not at startup.** The
  design already said the flyout *is* the application and the window is one
  click away for the rare occasion somebody needs it — but it was constructed
  and shown on every launch anyway, spending ~18 MB on everybody to save a
  moment for the few. `SentinelApp` owns the tray and the database; the window
  is created the first time it is opened, a scan is started, or a desktop
  turns out to have no tray at all. Idle is **66 MB**; even with the window
  open and shown it is 89.7 MB, inside the budget.
- **`PRAGMA cache_size` cut from 8 MiB to 2 MiB.** The number is per
  *connection* and this class opens one per thread, so a sixteen-worker scan
  was reserving 128 MiB of page cache against a 250 MiB peak budget. The hot
  query during a scan is an indexed `scan_cache` lookup that needs index pages
  and little else. Measured peak on a 253 MB tree is now 39.4 MB.
- Closing the window hides it; the process stays alive on the tray, and
  `setQuitOnLastWindowClosed(False)` stops Qt ending the application when the
  last window goes away.

### Added — auto-configuration

- **Sentinel measures the machine at first launch and picks its own
  settings.** Users cannot answer "what performance mode would you like?" —
  they do not know what a worker thread is, and asking makes them responsible
  for a decision they will get wrong and then blame the software for.
- **But it says what it chose**, in words that can be checked against what
  somebody knows about their own computer:

      Your drive is a hard disk, so Sentinel checks one file at a time.
      That is faster on drives like yours — reading several at once makes
      the drive jump back and forth.

  Shown once at the end of the first scan, in `sentinel status`, and at the
  top of the GUI settings page.
- **Rotational storage detection**, which is the measurement that matters
  most and the least obvious. `IOCTL_STORAGE_QUERY_PROPERTY` on Windows —
  opened with no access rights, so no administrator prompt —
  `/sys/block/…/queue/rotational` on Linux, `diskutil` on macOS. If none of
  those answer, a seek-timing probe: twelve random reads, median latency, and
  a rotating platter cannot hide a seek. Still unresolved is treated as
  rotating, because being conservative on an SSD costs some speed while being
  wrong the other way makes a hard disk thrash.
- On a hard disk, or an undetermined one, exactly **one worker** regardless of
  core count. On a 4 GB machine, a **400-file rule budget** and a smaller
  buffer cap (`detectors.yara_file_budget`).
- Measured once and persisted, not re-derived per launch: the probe is not
  free on the machines it matters for, and a value that can change between
  starts means a user who read "checks one file at a time" can later catch the
  software contradicting itself.

### Fixed

- `--config` loaded from the file it was given but saved to the platform
  default, so a setting written on one run was invisible on the next.

### Added — the tray and the flyout

- **The tray icon**, with additive state. A scan running, two files in the
  vault and a nine-day-old threat list are three simultaneous truths and one
  icon: priority picks what is shown, and the tooltip carries the rest. State
  is derived from every fact at once rather than nudged by the last event,
  which is what stops the classic antivirus bug — a finished scan flipping the
  icon green while quarantined files nobody has looked at vanish from
  awareness. `SAFE` is the lowest priority in the list and is reachable only
  when nothing else is true.
- **The flyout**: a 360x428 panel on left-click. One status line, one detail
  line, one button, and the resource line. Forcing a full window on "am I
  okay?" is a tax people pay once and then stop paying.
- **Tray icons drawn rather than shipped**, at six sizes, distinguished by
  silhouette first and colour second — colour is the least reliable signal at
  16 pixels in peripheral vision. Filled shield for safe, a ring for
  scanning, outline only for disabled, and badged for the two that need you:
  a *circle* badge for a threat, a *triangle* for attention, because the
  glyph inside is unreadable at 16px and the badge outline is not.
  `tests/test_tray.py` renders every pair in greyscale at 16px and fails if
  any two are too similar.
- **The resource line**: `0.4% CPU · 84 MB`, permanent, in the flyout. Never
  rounded up, never floored at "<1%", never smoothed to hide a spike. The
  people this is built for have been burned by security software that ate
  their computer and have no way to check whether this one does the same.
- **Notification tiers.** Silent for anything that went right — a scan
  starting, a scan finishing clean, the threat list updating. Toasts are
  capped at three per rolling hour and then coalesce, so ten threats in one
  scan produce one notification. Silence is the feature: an application quiet
  for weeks is one you believe when it finally speaks.
- Closing the window now hides it to the tray rather than quitting. Quit is
  explicit, from the tray menu.

### Known

- Idle memory measures ~107 MB with the GUI open, against a budget of 90 MB.
  Surfaced by the resource line, which is the point of it.

### Security

Three of the four defenses the project requires before it has users were
missing or broken. This completes them.

- **The guard list.** Nothing previously stopped quarantine moving
  `C:\Windows\System32\kernel32.dll` — only Sentinel's own data directory was
  protected, and not even its install directory. `engine/guard.py` now refuses
  to touch operating-system directories, Sentinel's own files, filesystem
  roots, anything that is not an ordinary file, and binaries signed by the OS
  vendor. It is checked inside `Quarantine.quarantine()`, so every path
  through the vault is covered, and there is deliberately no setting to switch
  it off. Verified against real system files: zero leaks, zero over-blocks.
  Application directories such as `Program Files` are deliberately *not*
  protected — malware installs there routinely.
- **Confidence tiers.** Heuristic findings could auto-quarantine. Six
  independent `script` heuristics, not one of them conclusive, aggregate to
  93.6 — CRITICAL, clearing any severity threshold. Automatic action now
  additionally requires a *conclusive* detection, meaning an exact digest
  match against a known sample. Heuristic findings are reported in full and
  marked `reported`; the user decides. Findings blocked by the guard are
  marked `protected` rather than `quarantine-failed`, because a refusal that
  protected the user is not an error they need to chase.
- **The benign corpus, and a CI gate.** `tests/test_benign_corpus.py` scans
  ordinary files of the shapes that trip naive heuristics, plus real binaries
  sampled from the host operating system. Nothing is committed — the corpus is
  generated at runtime and sampled from what the OS already installed. A pull
  request that makes any detector flag one fails the build.

### Fixed

- **False positives on Windows system binaries: 252 per 1,000 → 0.** The
  benign corpus found the PE heuristics flagging one in four `System32` DLLs,
  two of them at HIGH severity. Four causes, all now fixed:
  - `Heuristic.AntiDebug` counted `IsDebuggerPresent`,
    `QueryPerformanceCounter`, `GetTickCount` and `OutputDebugStringA` — APIs
    the MSVC runtime and any code that measures time or logs will import. It
    fired on 19% of `System32`. The import set is now restricted to APIs with
    no comfortable innocent explanation. (`getickcount` was also a typo for
    `gettickcount` and had never matched anything.)
  - `Heuristic.NoImportTable` fired on resource-only DLLs and .NET assemblies,
    both of which import nothing for entirely ordinary reasons. It now
    requires the binary to actually contain code.
  - `Heuristic.EntryPointOutsideSections` read an `AddressOfEntryPoint` of
    zero as an address pointing somewhere strange. Zero is the documented way
    of saying there is no entry point, which is standard for resource-only
    DLLs.
  - `Heuristic.HighEntropySection` measured `.rsrc`, where compressed icons
    and manifests live by design.
- Purely heuristic findings on OS-vendor-signed binaries are now suppressed.
  Windows' App-V subsystem imports the complete process-injection API set
  because that is its job. Conclusive detections are never suppressed —
  signing certificates get stolen, but not the OS vendor's. The check costs
  ~2ms and is only reached when something was going to be reported anyway, so
  a clean file never pays for it. Configurable via
  `detectors.trust_os_vendor_signatures`.

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
