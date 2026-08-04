# Code signing

## Why this is on the critical path

An unsigned security scanner is, to SmartScreen and to a cautious user,
indistinguishable from the thing it exists to catch. It reads every file on
the disk, it moves some of them somewhere the user cannot get at, and it
asks to run at startup. Shipping that unsigned means a red "Windows
protected your PC" dialog in front of every first-time user, and the people
this product is built for — the ones who have already been burned once — are
exactly the ones who will click *Don't run* and never come back.

Nothing else in the project can unblock this. Certificate issuance is a
calendar-time problem, not an engineering one: identity validation is done by
humans at a certificate authority, and the free OSS route adds a second
review on top. That is why the application goes in before the code that
depends on it.

## Which route

| Route | Cost | Wall clock | Notes |
|---|---|---|---|
| **SignPath Foundation (OSS)** | free | weeks | Free OV certificate + signing service for qualifying open-source projects. Key never leaves their HSM. Requires a public repo, an OSI licence, and CI-based builds. |
| Commercial OV via a reseller | ~$200–400/yr | days | Requires a hardware token or a cloud HSM since the 2023 key-storage rules. No SmartScreen reputation to start with; it accrues over downloads. |
| Commercial EV | ~$300–600/yr | 1–3 weeks | Immediate SmartScreen reputation. Token shipped physically, which is its own delay. |

We are applying to **SignPath Foundation**. The project fits their programme —
public repo, OSI licence (see [LICENSE](../LICENSE)), releases built entirely
in GitHub Actions — and the cost of the commercial routes is real for a
project with no revenue.

The trade being accepted: SignPath's OSS certificates are OV, not EV, so
SmartScreen reputation still has to accrue from download volume. That is a
slow ramp but a finite one, and an OV signature already removes the unknown
publisher warning.

## The application

The answers below are drawn from this repository. Have them ready; submit at
<https://signpath.org/apply>. The form is theirs and changes, so treat this
as the content to paste rather than a field-by-field map.

**Project name** — Sentinel Scan

**Repository** — https://github.com/sentinel-scan/sentinel-scan

**Licence** — MIT ([LICENSE](../LICENSE))

**One-line description** — A cross-platform, open-source malware scanner with
a pluggable detection engine.

**Longer description** (they ask what the software does and who uses it):

> Sentinel Scan is an open-source, on-demand malware scanner for Windows,
> macOS and Linux. It combines exact-hash matching, YARA rules, ClamAV, PE
> structural heuristics and script analysis behind a common detector
> interface, aggregates the results with a noisy-OR score, and quarantines
> only findings that are conclusive — an exact digest match against a known
> sample. Heuristic findings are reported and left alone.
>
> It is built specifically for low-end hardware: the target machine is 4 GB
> of RAM and a spinning disk. It measures the machine at first launch and
> configures itself for it, holds idle memory under 90 MB, and shows its own
> CPU and memory use permanently in the UI so the user can see what it costs
> them.
>
> It ships as a Python package on PyPI, as a CLI, and as a signed Windows
> installer built by GitHub Actions on tag.

**What gets signed** — the PyInstaller bundle (`sentinel.exe` plus the `.dll`
and `.pyd` files it carries) and the Inno Setup installer produced from
[packaging/windows/installer.iss](../packaging/windows/installer.iss).

**Build system** — GitHub Actions,
[.github/workflows/build-release.yml](../.github/workflows/build-release.yml).
Triggered by a `v*` tag. The version in the tag is checked against
`src/sentinel/version.py` before anything is built, so a signed artifact can
always be traced to one commit.

**Maintainers with release rights** — matt869, sole maintainer. Nobody else
can push a tag, so nobody else can trigger a signed build.

The publisher name in
[installer.iss](../packaging/windows/installer.iss) and the `authors` field in
`pyproject.toml` both say `matt869`. Keep them matching whatever subject name
ends up on the certificate — an installer whose declared publisher disagrees
with its signature is a mismatch users are told to treat as tampering.

### Two things worth pre-empting

They review the project, not just the paperwork, and a malware scanner is a
category that attracts scrutiny. Two questions are likely and both have good
answers already in the repo — link them rather than paraphrasing:

- **"Can this software damage a user's machine?"** It is designed so that it
  cannot. [`engine/guard.py`](../src/sentinel/engine/guard.py) makes acting on
  a file require passing two independent gates, the check is inside
  `Quarantine.quarantine()` so no caller can bypass it, and there is no
  setting that disables it. See *The guard list* in
  [architecture.md](architecture.md).
- **"What happens when a signature turns out to be wrong?"** There is a
  remote kill switch —
  [`signatures/revocations.py`](../src/sentinel/signatures/revocations.py) —
  that can only ever *remove* detections, fails open, and takes no wildcards.

## Once approved

The signing job is already wired and inert. It turns on when the four
`SIGNPATH_*` values exist as repository secrets/variables and does nothing
before that, so merging it cannot break a release:

| Name | Kind | Where it comes from |
|---|---|---|
| `SIGNPATH_API_TOKEN` | secret | SignPath → user settings → API tokens |
| `SIGNPATH_ORGANIZATION_ID` | variable | SignPath organisation page |
| `SIGNPATH_PROJECT_SLUG` | variable | the project you create, e.g. `sentinel-scan` |
| `SIGNPATH_POLICY_SLUG` | variable | `test-signing` first, then `release-signing` |

Sign one build with `test-signing` before switching the policy over. A
misconfigured artifact configuration fails *after* the upload, and finding
that out on a release tag means the tag is already public.

The existing PFX path in the workflow stays. It is what signs local
development builds and what a fork with its own certificate would use;
SignPath takes precedence when configured. `sign.ps1 -Verify` checks the
result either way and exits non-zero if anything in the bundle is unsigned —
which is the check that matters, because a bundle where the `.exe` is signed
and a `.pyd` beside it is not is a bundle that still trips SmartScreen.

## Timestamping is not optional

Every signature is timestamped (`/tr` with SHA-256 in
[sign.ps1](../packaging/windows/sign.ps1)). Without a timestamp, every
release ever shipped becomes invalid on the day the certificate expires —
including the installers already sitting on users' disks.
