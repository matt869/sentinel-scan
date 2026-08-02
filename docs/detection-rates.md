# Detection rates

## Read this first

**This project does not publish a headline detection percentage, and you
should be sceptical of tools that do.**

A single number like "99.7% detection" is meaningless without the corpus it
was measured against, and the corpus is where all the honesty lives. Test
against samples your rules were written from and you will score whatever you
like. The numbers below are therefore reported per detector, per corpus,
with the false-positive rate alongside — because a detection rate without a
false-positive rate is not a measurement, it is marketing.

## What Sentinel is and is not

Be realistic about where this sits:

**It is** a good second opinion, an on-demand scanner, a triage tool, and a
way to check a specific file or a downloads folder. The heuristics catch
categories of behaviour — script droppers, ransomware preparation, archive
tricks, masquerading executables — rather than individual samples, so they
generalise to variants that no signature covers yet.

**It is not** a replacement for a platform's built-in real-time protection.
There is no on-access scanning, no kernel driver, no behavioural monitoring
of running processes, and no memory scanning. Something that has already
executed is out of scope. Use this alongside Defender, not instead of it.

## Methodology

Three corpora, all measured with the same build.

**Clean corpus (`clean-desktop`)** — 184,000 files, 41 GB: a stock Windows
11 install plus commonly-installed developer and consumer software (Python,
Node, Visual Studio Code, Chrome, Steam, Office), a Debian 12 install with a
desktop environment, and a macOS 14 `/Applications` tree. This is the corpus
that matters most: everything it flags is a false positive.

**Malicious corpus (`mal-recent`)** — 12,400 samples from public feeds,
first seen within the previous 90 days, deduplicated by SHA-256. Mixed
Windows PE, scripts, Office documents and archives.

**Held-out corpus (`mal-holdout`)** — 2,100 samples deliberately excluded
while the rules were written, to measure generalisation rather than
memorisation. This is the number to trust.

Signature set: the hash database plus the bundled YARA rules. ClamAV and
cloud lookup are **disabled** — with ClamAV enabled the figures mostly
measure ClamAV.

Threshold: default (`threat_threshold = 60`).

## Results

### By detector, on `mal-recent`

| Detector | Detected | Rate | FPs on `clean-desktop` | FP rate |
|---|---:|---:|---:|---:|
| hash | 8,910 | 71.9% | 0 | 0.000% |
| script | 2,180 | 17.6% | 31 | 0.017% |
| yara | 3,340 | 26.9% | 12 | 0.007% |
| pe_heuristic | 4,720 | 38.1% | 214 | 0.116% |
| archive | 640 | 5.2% | 8 | 0.004% |
| **combined** | **11,190** | **90.2%** | **248** | **0.135%** |

Detector rates overlap and do not sum.

### Generalisation: `mal-holdout`

| Detector | Rate |
|---|---:|
| hash | 4.1% |
| script | 19.8% |
| yara | 11.2% |
| pe_heuristic | 39.6% |
| archive | 6.0% |
| **combined** | **58.7%** |

This is the honest number. Hash matching collapses from 72% to 4% — of
course it does, these samples are not in the database. What remains is the
heuristics doing real work on files they have never seen, and 59% is a
respectable result for structural analysis with no execution and no cloud.

It is also nowhere near enough on its own. Hence the advice to run this
alongside a real-time product.

### By file type, combined, `mal-recent`

| Type | Samples | Rate | Note |
|---|---:|---:|---|
| PowerShell / batch / VBS | 2,410 | 94.1% | Strongest area — the technique combinations are distinctive |
| Windows PE | 6,830 | 91.7% | Mostly hash; heuristics carry the unknown ones |
| Archives | 1,290 | 86.4% | Depends on being able to open them |
| JS / HTA | 980 | 81.2% | Obfuscation variety is high |
| Office documents | 890 | 41.6% | **Weak.** No macro extraction — see below |

### False positives, by cause

All 248 on `clean-desktop`:

| Cause | Count | Status |
|---|---:|---|
| Packed installers flagged by `pe_heuristic` | 156 | Expected. Confidence lowered to 30 and the description says so |
| Legitimate admin scripts (`vssadmin`, `schtasks`) | 38 | Mitigated by requiring combinations |
| Build output with high-entropy sections | 31 | Inherent to entropy analysis |
| Self-extracting archives | 15 | Structurally identical to droppers |
| Other | 8 | Individually triaged |

**0.135% overall.** On a 184,000-file scan that is 248 files to look
through. That is a lot to ask of a user, which is why the default scan
targets high-risk locations rather than the whole disk.

Note that `pe_heuristic` produces 86% of the false positives while adding
38% detection. That trade is defensible but it is the first thing to
reconsider if the number rises.

## Known weaknesses

Stated plainly, because you should know where the holes are:

- **Office macros.** We do not extract or analyse VBA. A macro-bearing
  document is only caught if a hash or a YARA rule matches the container.
  This is the largest gap; `oletools` integration is the obvious fix.
- **.NET assemblies.** `pe_heuristic` reads native PE structure. Managed
  binaries have almost no imports and IL is not inspected, so most of the
  heuristics simply do not fire.
- **Anything already running.** No memory scanning, no process inspection
  beyond listing. Fileless and living-off-the-land techniques that never
  touch disk are invisible.
- **Encrypted archives.** We report the shape (password-protected archive
  containing executables, 55% confidence) but cannot see inside.
- **Rare archive formats.** RAR, 7z and CAB are identified but not opened —
  they need external libraries this project does not depend on.
- **Targeted malware.** Heuristics catch commodity patterns. Something
  written for one target, once, will not match them.

## Reproducing this

```bash
# Against your own clean corpus — the most useful thing you can measure.
sentinel scan /path/to/clean/corpus --json > clean.json
python -c "
import json; d = json.load(open('clean.json'))
print(f\"{len(d['threats'])} FPs in {d['files_scanned']:,} files\")
"

# One detector at a time, to attribute the cost.
for d in hash script yara pe_heuristic archive; do
  echo -n "$d: "
  sentinel scan /path/to/corpus --detectors $d --json | \
    python -c "import json,sys; print(len(json.load(sys.stdin)['threats']))"
done
```

If you build a corpus and get materially different numbers, please open an
issue — that is more valuable than most bug reports.

## When these numbers change

Any pull request that changes detection logic should report its effect on
both corpora. The PR template asks for it. A change that raises detection by
2% and false positives by 0.5% will be rejected: at these ratios that trade
costs users far more than it gains them.
