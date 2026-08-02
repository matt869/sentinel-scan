# Bundled signature data

This directory holds the signature data shipped with the package. Most of it
is **not committed** — it is downloaded at build or update time — so a fresh
clone will show only this file and `rules/`.

## What lives here

| Path | Committed? | What it is |
|---|---|---|
| `rules/example.yar` | Yes | Worked example rules, always loaded |
| `rules/*.yar` | No | Downloaded rule sets |
| `hashes.db` | No | SQLite database of known-malware digests |
| `main.cvd` | No | ClamAV base database |
| `daily.cvd` | No | ClamAV incremental database |

The uncommitted entries are listed in `.gitignore`. Nothing breaks when they
are absent: `SignatureStore` treats a missing or zero-length file as "not
present", and the hash detector falls back to its built-in table (which
covers EICAR, so a fresh install can still be verified).

## Where the scanner actually looks

Two directories, with the user's copy winning file by file:

1. **This directory** — shipped with the package. Often read-only, and
   always read-only inside a PyInstaller bundle.
2. **`<data_dir>/signatures/`** — written by the updater. On Windows that is
   `%LOCALAPPDATA%\sentinel-scan\signatures`.

Plus an optional third for rules only, from `detectors.yara_rules_dir`.

This is why updates never need write access to the installation directory.

## Getting the real data

```bash
sentinel update            # normal path: download from the configured mirror
sentinel update --check    # is anything newer available?
sentinel status            # what is currently installed
```

Every downloaded file is verified against the sha256 recorded in
`manifest.json` before installation. A mismatch aborts that file — it is
never installed, and there is no flag to skip the check. A signature bundle
is data the scanner trusts and loads at high privilege; installing an
unverified one would hand anyone with mirror access control over every
install.

## Building it yourself

```bash
# Fetch upstream feeds into ./mirror
python scripts/fetch_signatures.py --output ./mirror

# Build the hash database from what was downloaded
python scripts/build_hash_db.py \
    --csv ./mirror/malwarebazaar.csv --source MalwareBazaar \
    --output src/sentinel/signatures/local/hashes.db --replace

# Check what you built
python scripts/build_hash_db.py \
    --output src/sentinel/signatures/local/hashes.db --stats
```

`.github/workflows/update-signatures.yml` does this twice daily, validates
that the result actually loads and reports clean on a clean file, then
publishes it.

## Licensing

The code in this project is MIT. **Signature data is not.**

- **ClamAV databases** (`main.cvd`, `daily.cvd`) are GPL-2.0, distributed by
  Cisco Systems, Inc. They are *not* redistributed with this package — the
  updater fetches them from the upstream mirror. Keep their notices intact
  if you mirror them yourself.
- **Third-party YARA rules** keep whatever licence their authors chose. The
  provenance and licence of each source is recorded in
  `../manifest.json`.
- **`rules/example.yar`** is ours, and MIT like the rest of the code.

Check `manifest.json` before redistributing a bundle you have built.

## Adding your own rules

For local rules that survive updates, use a separate directory rather than
dropping files here — the updater overwrites this one.

```toml
[detectors]
yara_rules_dir = "/home/me/my-yara-rules"
```

Files there are loaded on top of everything else, and a rule file with the
same name replaces the bundled one rather than colliding with it.

See `docs/writing-detectors.md` for the metadata fields this project reads
(`confidence`, `severity`, `threat_name`, `description`).
