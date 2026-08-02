# Privacy

## The short version

**A default installation of Sentinel Scan makes no network requests at
all.** Not for updates, not for telemetry, not for reputation lookups.
Install it, run it, and nothing leaves your machine.

Every feature that could send data is off until you turn it on, and each one
is listed below with exactly what it transmits.

## What is stored locally

Under your platform's data directory:

| Windows | `%LOCALAPPDATA%\sentinel-scan` |
| Linux | `~/.local/share/sentinel-scan` |
| macOS | `~/Library/Application Support/sentinel-scan` |

Override with `SENTINEL_DATA_DIR`.

Contents:

- `sentinel.db` — scan history, findings (paths and hashes), the quarantine
  index, your whitelist, and a cache of clean-file fingerprints.
- `quarantine/` — obfuscated copies of quarantined files, plus `vault.key`.
- `logs/` — rotating logs, capped at about 8 MB total.
- `signatures/` — downloaded signature data.

None of this is transmitted anywhere. Delete the directory to erase
everything Sentinel knows, but read the note about quarantine below first.

### Logs

Logs record file **paths**, never file **contents**. Paths contain your
username and often project or client names, so before pasting a log into a
public issue set:

```bash
SENTINEL_REDACT_PATHS=1 sentinel scan ...
```

which replaces your home directory with `~`.

## Optional features, and exactly what each sends

### 1. Signature updates — off unless a mirror is configured

**Sends:** an HTTP GET for `manifest.json` and each bundle. Your IP address
is visible to the mirror, as with any download.

**Does not send:** anything about your machine, your files, or your scans.
It is a plain file download; there is no request body and no identifier.

Controlled by `updates.auto_update` and `updates.mirror_url`.

### 2. Cloud hash lookup — off by default

**Sends:** SHA-256 hashes of files being scanned, in batches.

**Does not send:** file contents, file names, paths, or anything about your
machine.

A hash is not reversible, but it *is* an identifier: if someone already has
a copy of a file, they can confirm you also have it. That is why this is
off by default and needs two settings, not one:

```toml
[privacy]
server_url = "https://your-server.example"
allow_cloud_lookup = true
```

Hashes are batched so the server sees a set per scan rather than a timed
sequence it could correlate with your activity.

### 3. Anonymous telemetry — off by default

**Sends,** exhaustively:

- Counts of detections per detector (`{"script": 12, "yara": 3}`).
- Counts of verdicts per severity.
- Names of built-in heuristics that matched (`Heuristic.Script.Dropper`) —
  these come from our own rule set, never from your files.
- Files scanned and error counts, **bucketed** (`"100-999"`, not `847`).
- Application version, signature version, OS family, Python version.

**Never sends:** file names, paths, hashes, contents, your hostname,
username, IP-derived identifiers, drive labels, or process names.

**There is no installation identifier.** No UUID, no machine hash, no
account. Batches carry nothing that links one submission to another. This is
a deliberate constraint with a real cost — the data cannot answer "how many
people use this" — and it is the trade we chose.

See exactly what would be sent, without sending it:

```bash
sentinel telemetry --preview
```

Enable or disable:

```bash
sentinel telemetry --enable
sentinel telemetry --disable
```

### 4. Sample upload — off by default, and gated per file

This is the only feature that transmits **file contents**, and it has the
strictest gate in the codebase. All of these must hold:

1. `privacy.allow_sample_upload = true` in your configuration.
2. You explicitly consented for that specific file, in that specific report.
   There is no "remember my choice".
3. The file is under 32 MB.
4. The file is not on the never-upload list.

**Never uploaded, at any setting**, by extension or filename:

```
.pem .key .pfx .p12 .jks .keystore .kdbx .kdb .ppk .asc .gpg .pgp
.env .netrc .htpasswd .1pif .agilekeychain
id_rsa id_dsa id_ecdsa id_ed25519 shadow passwd sam ntds.dit
credentials .pgpass
```

**Requires a second confirmation:** PDFs, Office documents, plain text and
images. If you are reporting a false positive on `tax-return.pdf`, you
almost certainly want the *detection* fixed, not to send us your tax return.
One extra dialog prevents a mistake that cannot be undone once the file is
on someone else's server.

### 5. Report submission — you review it first

`sentinel report` shows the complete JSON payload and asks before sending.

**Sends:** the file's name, size, type and hashes; the detections you are
disputing; your comment; and version/OS information.

**Does not send:** the full path. It contains your username and often more.

With no server configured, the report becomes a pre-filled GitHub issue URL
that opens in your browser — you read it, edit it, and submit it yourself.
Nothing is transmitted by us at all.

## Quarantine

Quarantined files are stored in a vault under your data directory, obscured
with a keystream cipher.

Be clear about what this does: it prevents the file being **executed,
double-clicked, indexed by a search tool, or picked up and re-flagged by
another scanner**. It is containment.

It is **not** confidentiality. The key is `quarantine/vault.key`, right next
to the data. It has to be — restoring must work without prompting for a
passphrase you never set. Anyone with read access to your data directory can
recover a quarantined file.

Nothing about quarantine is transmitted anywhere.

Uninstalling does not delete the vault. It may hold the only copy of a file
you want back, and destroying it silently would be indefensible. Remove it
yourself once you are sure:

```bash
sentinel quarantine list          # see what is there
sentinel quarantine purge --older-than 30
```

## The reporting server

If you run `server/`, note what it can and cannot know:

- Submitter IP addresses are **hashed with a salt** and used only for rate
  limiting. The hash is never returned by any endpoint and appears in no
  schema.
- Telemetry rows have no identifier column. Two batches from one machine
  cannot be linked, by construction.
- Uploaded samples are stored obfuscated and served only with an
  authenticated request, as `application/octet-stream` with a `.sample`
  filename so a browser cannot be tricked into running one.
- `/v1/stats` is public and exposes only aggregate counts.

If you operate a server for others, you are the data controller for whatever
they send you. The client's promises constrain what it transmits; they say
nothing about what you do with it afterwards.

## Third parties

Sentinel Scan contacts no third-party service. There is no analytics SDK, no
crash reporter, no CDN, no ad network, no font server.

If you enable updates against the default mirror, or point the client at a
server you do not control, that operator sees your IP and whatever the
feature above says it sends. Nothing more.

## Verifying these claims

You do not have to take our word for it.

```bash
# Every outbound request goes through one module.
grep -rn "httpx\|urllib\|requests" src/sentinel/

# The consent gate for file contents.
cat src/sentinel/feedback/sample_upload.py

# What telemetry collects.
sentinel telemetry --preview

# Watch it make no connections at all.
sudo tcpdump -i any host not 127.0.0.1 &
sentinel scan ~/Documents
```

The tests in `tests/test_feedback.py` assert these properties directly —
that reports exclude the full path, that telemetry contains no hashes or
filenames, that credential files are refused, and that documents require a
second confirmation.

## Changes to this document

Any change to what leaves the machine is a breaking change. It goes in
`CHANGELOG.md`, and pull requests that touch it must tick the privacy box in
the template and explain themselves.
