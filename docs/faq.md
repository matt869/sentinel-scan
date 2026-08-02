# FAQ

## Using it

### Should I use this instead of Windows Defender?

No. Use it *alongside*.

Sentinel is an on-demand scanner: it looks at files when you ask it to. It
has no real-time protection, no kernel driver and no memory scanning, so
anything that has already executed is invisible to it. Defender (or your
platform's equivalent) covers that; this covers "what is actually in this
folder", "is this download safe", and "what runs at startup on this
machine".

### It found nothing. Is that right?

Probably, yes. Most files on most machines are fine. Verify the scanner
works with the EICAR test file — a harmless 68-byte string every scanner is
expected to flag:

```bash
python -c "print('X5O!P%@AP[4\\PZX54(P^)7CC)7}\$' + 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE' + '!\$H+H*', end='')" > eicar.com
sentinel scan eicar.com
```

Your real antivirus will probably delete it first. That is also a useful
result.

### It flagged a file I know is safe

That is a false positive, and we want to hear about it — they are the
highest-priority bug class in this project.

```bash
sentinel report path/to/file --false-positive -c "why you believe it is safe"
```

To stop it being flagged meanwhile:

```bash
sentinel whitelist add <sha256>     # survives the file moving
```

Prefer the hash over the path. A whitelisted *path* trusts whatever ends up
there, which is a hole if an attacker can write to it.

### Why is scanning slow?

Usually because your real-time antivirus is scanning every file we read,
doubling the work. Excluding the directory you are scanning from Defender
speeds things up dramatically — do that only if you understand what you are
turning off.

Otherwise:

```bash
sentinel scan <path> --threads 8      # default is CPU count, capped at 16
sentinel scan <path> --no-archives    # archive extraction is the expensive part
```

`python scripts/benchmark.py --generate 2000 --threads 1,4,8 --detectors`
shows where the time goes.

### Do I need to run it as administrator?

Only for a full system scan. Unprivileged, you can scan everything you can
read — which is all of your own files. Elevation adds other users' profiles
and some system directories, and lets autorun inspection see machine-wide
registry keys.

`sentinel status` says which you are running as and what that costs.

### What do the exit codes mean?

The ClamAV convention, so it drops into existing scripts:

| Code | Meaning |
|---|---|
| 0 | Clean |
| 1 | Threats found |
| 2 | Errors occurred |
| 130 | Interrupted |

```bash
sentinel scan ~/Downloads || echo "something was found"
```

## Detections

### What does the score mean?

An aggregate of every detector's confidence, 0–100. Bands: under 30 clean,
30–49 low, 50–69 medium, 70–89 high, 90+ critical. Medium and above is
reported as a threat.

Signals combine with a noisy-OR, so two 50% detections give 75, not 100.
A score of exactly **100 means a definitive identification** — an exact hash
match against a known sample. Heuristics are capped at 99 however many of
them fire, precisely so a pile of guesses cannot imitate certainty.

### `Heuristic.*` — what is that?

A behavioural or structural pattern rather than a known sample. These
generalise to malware nobody has seen yet, and they are also where false
positives come from. Each one explains itself in the output; read the
description before acting.

### Why was my installer flagged as packed?

Because it is packed, and so is a lot of malware. This is a deliberately
weak signal (30% confidence) and the description says so: *"Legitimate
software uses packers too — this is a weak signal."* On its own it will not
push a file past the threat threshold. If it did, something else fired too.

### It says "conclusive". What does that mean?

The file's hash exactly matches a known malware sample, or ClamAV matched a
signature. Not a guess. When a conclusive detection fires, the remaining
detectors are skipped — there is nothing left to establish.

## Quarantine

### Where do quarantined files go?

Into a vault under your data directory, stored obfuscated so they cannot be
run, opened or indexed by accident. The original is removed. Everything is
reversible:

```bash
sentinel quarantine list
sentinel quarantine restore <token>
```

### Is quarantine encryption?

Not in the sense that matters for secrecy. It is a keystream cipher and the
key sits in `quarantine/vault.key`, right beside the data — it has to,
because restoring must work without a passphrase you never set.

It stops accidental execution and stops other scanners re-flagging the file
in a loop. It does not protect the contents from anyone who can read your
data directory. This is stated in the module docstring and in the security
policy, and it is out of scope as a vulnerability report.

### Uninstalling did not delete my quarantined files

Deliberately. The vault may hold the only copy of something you want back,
and destroying it silently during an uninstall would be indefensible. Delete
it yourself when you are sure.

### Can I get a file back after `quarantine delete`?

No. `delete` is permanent. `restore` is the reversible one.

## Privacy

### Does it phone home?

No. A default installation makes **no network requests at all** — not for
updates, telemetry or lookups. Every such feature is off until you turn it
on.

`docs/privacy.md` lists each one and exactly what it transmits. You can
verify it: `grep -rn "httpx\|urllib\|requests" src/sentinel/` finds every
outbound path.

### What does telemetry send?

Counts. Which detectors fired, which built-in heuristic names matched, how
many files were scanned (bucketed, so `"100-999"` rather than `847`), plus
version and OS family.

Never file names, paths, hashes, contents, your hostname or your username.
There is **no installation identifier** — two submissions from one machine
cannot be linked. See it yourself with `sentinel telemetry --preview`.

### Will it upload my files?

Only if you set `allow_sample_upload`, *and* consent for that specific file
in that specific report. Files that look like keys, credentials or password
stores are refused at any setting. Documents and images require a second
confirmation, because someone reporting a false positive on `tax-return.pdf`
almost certainly does not mean to send us their tax return.

## Configuration

### Where is the config file?

```bash
sentinel config path
sentinel config init      # write one with the current defaults
sentinel config show      # see what is actually in effect
```

Precedence: command-line flags, then `SENTINEL_*` environment variables,
then `config.toml`, then built-in defaults.

### A detector says "unavailable"

It needs an optional dependency:

```bash
pip install 'sentinel-scan[all]'      # everything
pip install 'sentinel-scan[yara]'     # just YARA
```

`sentinel detectors` lists what is active and why anything is not. Missing
optional back-ends are a normal state, not an error — the scanner degrades
rather than failing.

### Can I use it as a library?

Yes.

```python
from sentinel import Scanner, load_config

with Scanner(load_config()) as scanner:
    result = scanner.scan_paths(["/home/me/Downloads"])
    for finding in result.threats:
        print(finding.path, finding.severity.value, finding.name)
```

Subscribe to `scanner.bus` for progress events. See `docs/architecture.md`.

## Contributing

### How do I add a detector?

`docs/writing-detectors.md` has the contract, the confidence calibration
guide and a worked example. The short version: subclass `Detector`, register
it, score conservatively, and test against a corpus of clean files before
proposing it.

### My rule catches more malware but adds false positives

Then it probably will not be merged. At the current ratios a change adding
2% detection and 0.5% false positives costs users far more than it gains
them. Try expressing it as a low-confidence signal that combines with
existing ones instead of a standalone high-confidence rule.

### I found a security vulnerability

Do not open a public issue. See `.github/SECURITY.md` for private reporting.
And never attach a malware sample to a public issue — send a hash.
