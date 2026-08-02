# Contributing

Thanks for considering it. This project is most useful when people who have
seen real malware — and real false positives — help shape what it detects.

## The one rule that shapes everything

**A false positive costs more than a missed detection.**

A missed sample is one file a scanner did not catch. A false positive on a
popular application is thousands of people seeing their own software
condemned, and it is the fastest way to lose their trust in *every other
verdict the tool produces*. A scanner nobody believes is worse than no
scanner at all.

Practically, that means a change adding 2% detection and 0.5% false
positives will be rejected. Score conservatively and let the aggregation
combine weak signals — that is what it is for.

## Never attach malware to a public issue or PR

It endangers everyone who clones the repository and breaches GitHub's terms.
Send a SHA-256; a maintainer will arrange a private channel if a sample
turns out to be necessary.

The single exception is EICAR, which is not malware. Even that is generated
at runtime by the test suite rather than committed, because a developer's
own antivirus will quarantine it on clone and break the checkout in a
confusing way.

## Getting set up

```bash
git clone https://github.com/sentinel-scan/sentinel-scan
cd sentinel-scan
python -m venv .venv
source .venv/bin/activate          # .venv\Scripts\activate on Windows
pip install -e ".[all]" -r requirements-dev.txt

pytest
ruff check src server scripts tests
```

Windows users: add your temp directory to Defender's exclusions, or a few
tests will skip when real-time protection eats the EICAR fixture.

## What to work on

Good places to start, roughly in order of value:

- **Office macro analysis.** The biggest gap in coverage — see
  `docs/detection-rates.md`. Extracting and scoring VBA with `oletools`
  would move the document detection rate materially.
- **.NET assembly heuristics.** `pe_heuristic` reads native structure;
  managed binaries mostly slip past it.
- **RAR / 7z / CAB extraction.** Identified but not opened today.
- **False-positive reduction in `pe_heuristic`.** It produces 86% of the
  false positives while contributing 38% of detection. Better calibration
  there helps everyone.
- **Platform coverage.** The macOS and Linux autorun collectors have had far
  less real-world exposure than the Windows one.

## Changing detection

This is the part that needs the most care.

Read [`docs/writing-detectors.md`](docs/writing-detectors.md) first — it has
the contract, a confidence calibration table, and a worked example.

Before opening a pull request, measure your change against a corpus of
**clean** files:

```bash
sentinel scan "C:\Program Files" --detectors your_detector --json > out.json
python -c "import json;print(len(json.load(open('out.json'))['threats']))"
```

If that number is not close to zero, the rule is not ready. Report both
numbers — detection and false positives — in the PR. The template asks for
them.

### Confidence values

| Range | Meaning |
|---|---|
| 5–20 | Worth noting; common in benign files |
| 20–40 | Mildly unusual |
| 40–60 | Suspicious; needs corroboration |
| 60–80 | Strongly suspicious on its own |
| 80–95 | Almost certainly malicious |
| 95–100 + `conclusive` | Definitive identification of a known sample |

`conclusive=True` forces the score to 100 and stops every other detector.
A heuristic never gets it: it can be wrong, and a wrong conclusive verdict
cannot be outvoted.

## Code standards

- **Docstrings explain *why*.** What the code does is usually visible; why
  it does it that way is not. The comments that earn their place here are
  the ones recording a constraint someone hit — see the notes about the
  re-entrant lock in `ScanTarget` or `Severity` needing all four comparison
  operators.
- **Detectors never raise.** Return an empty list when undecided.
- **Bound everything.** You are parsing hostile input: cap sizes, depths,
  match counts and loop iterations.
- **Type hints on public functions.** `mypy` runs in CI, advisory for now.
- **Line length 100.** `ruff` enforces the rest.

Match the surrounding style rather than importing your own.

## Tests

New behaviour needs tests. Test the negative cases hardest — that a rule
does *not* fire on legitimate files matters more than that it fires on a
sample.

Fixtures live in `tests/conftest.py`: `scanner`, `config`, `db`, `corpus`,
`powershell_dropper`, `traversal_zip` and friends. Everything is redirected
to `tmp_path`, so the suite never touches your real configuration, database
or quarantine vault.

```bash
pytest                              # everything
pytest tests/test_scanner.py -v     # one module
pytest -k quarantine                # by name
pytest --cov=sentinel --cov-report=term-missing
```

## Pull requests

1. Branch from `main`.
2. Keep it focused — one concern per PR.
3. Add a `CHANGELOG.md` entry under "Unreleased".
4. Fill in the template, especially the privacy and detection sections.
5. Make sure CI is green.

Commit messages: a short imperative subject, then *why* in the body.

```
Cap heuristic scores below a conclusive match

Twenty detections at 30% reach 99.92 under noisy-OR and round to 100,
making a pile of guesses indistinguishable from an exact hash match.
Cap non-conclusive aggregation at 99 so a score of 100 always means
a definite identification.
```

## Things this project has decided not to do

Proposals here are welcome as discussions but will not be merged as
straightforward features:

- **Real-time on-access scanning.** Needs a kernel driver or filesystem
  filter. Getting it wrong bluescreens machines, and it is not something a
  Python application should attempt.
- **Automatic cleaning or repair of infected files.** Quarantine is
  reversible; surgery on a binary is not.
- **Automatically killing or blocking processes.** System state is
  reported; acting on it is the user's call.
- **Persistent installation identifiers.** Telemetry batches deliberately
  carry nothing linking them, which costs us the ability to count users.
  That is the intended trade.
- **Anything that sends data without explicit, per-action consent.**

## Privacy is not negotiable

Any change to what leaves the machine is a breaking change. It needs a
`CHANGELOG.md` entry, an update to [`docs/privacy.md`](docs/privacy.md), and
an explanation in the PR.

The invariants, asserted directly by `tests/test_feedback.py`:

- Reports exclude the full file path.
- Telemetry contains no file names, paths, hashes or contents.
- Telemetry batches carry no identifier of any kind.
- Credential and key files are never uploaded, at any setting.
- Documents and images require a second explicit confirmation.

## Security vulnerabilities

Do not open a public issue. See [`.github/SECURITY.md`](.github/SECURITY.md)
for private reporting. Good-faith research following that policy is welcome
and will be credited.

## Code of conduct

By participating you agree to the
[Code of Conduct](CODE_OF_CONDUCT.md).
