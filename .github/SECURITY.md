# Security policy

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.**

Use GitHub's private reporting: go to the
[Security tab](https://github.com/sentinel-scan/sentinel-scan/security/advisories/new)
and open a draft advisory. If that is unavailable to you, email
`security@sentinel-scan.example` — and say so in a public issue *without
details* if you get no acknowledgement, so we know to look.

Please include:

- What the flaw is and where in the code it lives.
- How to reproduce it. A proof of concept is welcome; **do not attach live
  malware** — describe it or supply a hash.
- What an attacker gains.
- The version and platform you tested on.

### What to expect

| Stage | Target |
|---|---|
| Acknowledgement | 3 working days |
| Initial assessment | 10 working days |
| Fix for a critical issue | 30 days |
| Fix for other issues | next scheduled release |

We will credit you in the advisory and the changelog unless you would
rather we did not. We will not take legal action against good-faith research
that follows this policy.

## Scope

### In scope

This is a security tool that reads untrusted files, sometimes with elevated
privileges. The following are the things we most want to hear about:

- **Parser flaws.** A crafted file that causes code execution, memory
  exhaustion or an unbounded hang in any detector — the PE parser, the
  archive extractor, the YARA path or the script heuristics.
- **Archive handling.** Path traversal on extraction, decompression bombs
  that defeat the limits, symlink or hardlink escapes.
- **Quarantine vault.** Anything that lets a quarantined file execute, that
  writes outside the vault, or that lets a restore overwrite an arbitrary
  path.
- **Privilege issues.** Anything that gains privileges through Sentinel, or
  that makes an elevated scan act on attacker-controlled input unsafely.
- **Detection bypass by design flaw.** Not "sample X is not detected" —
  that is a missed detection, use the issue template. We mean a structural
  way to make the scanner skip a file it should have opened: a file type
  the walker refuses, a size or depth limit that can be exploited
  deliberately, a whitelist that can be poisoned.
- **The reporting server.** Auth bypass, sample store escape, anything that
  leaks a submitter's identity, injection of any kind.
- **Update channel.** Anything that gets an unverified signature bundle
  installed. Checksum verification against the signed manifest is the
  control that matters here.
- **Privacy violations.** Any path where file contents, paths, hostnames or
  usernames leave the machine without the consent documented in
  `docs/privacy.md`. We treat these as security issues, not bugs.

### Out of scope

- Missed detections and false positives — use the issue templates.
- Vulnerabilities in dependencies with no exploitable path through
  Sentinel. Report those upstream (tell us too, so we can pin around it).
- Attacks needing an already-compromised machine or physical access.
- The quarantine obfuscation being reversible. It is, by design: the key
  sits beside the vault because restoring must work without a passphrase
  the user never set. It stops accidental execution, not a determined
  attacker with local access. See the module docstring in
  `src/sentinel/engine/quarantine.py`.
- A default server deployment with `SENTINEL_SERVER_TOKENS` unset being
  unauthenticated. It logs a warning at startup and is documented.
- Missing hardening that is not exploitable on its own.

## Supported versions

| Version | Supported |
|---|---|
| 0.4.x | Yes |
| < 0.4 | No — please upgrade |

Only the latest minor release gets security fixes until 1.0.

## Handling samples

If a report needs a malware sample, we will arrange a private channel. Never
attach one to a public issue or pull request: it endangers everyone who
clones the repository and violates GitHub's terms.

The one exception is EICAR, which is not malware and which the test suite
generates at runtime rather than committing.

## Our own supply chain

- Releases are built by GitHub Actions from a tagged commit; the workflow
  is in `.github/workflows/build-release.yml`.
- Windows binaries are Authenticode-signed and timestamped.
- SHA-256 checksums are published with every release.
- Signature bundles are verified against the sha256 in the manifest before
  installation. A mismatch aborts the install; there is no override flag.
- Dependencies are reviewed on every pull request, and CodeQL runs weekly.

If you find a way to subvert any of that, it is in scope and we would very
much like to know.
