# Pull request

## What this changes

<!-- One or two sentences. What is different after this merges? -->

## Why

<!-- The problem being solved. Link the issue if there is one: Fixes #123 -->

---

## Detection changes

<!-- Delete this section if you did not touch a detector, rule or threshold. -->

Every change to detection logic trades false positives against missed
detections. Say which way this one goes and how you know.

- **New or changed rules:**
- **Confidence values used, and why:**
- **Tested against how many clean files:**
  <!--
    Please run over a real corpus before proposing a rule. A quick check:
        sentinel scan "C:\Program Files" --json > before.json
    then again with your change, and diff the findings.
  -->
- **False positives observed:**
- **Samples correctly detected:**

> Reminder: a rule that fires on legitimate software costs more than a rule
> that misses a sample. Prefer low confidence and let the aggregation add
> signals together — see `docs/writing-detectors.md`.

---

## Type of change

- [ ] Bug fix (no behaviour change beyond fixing the bug)
- [ ] New feature
- [ ] Detection rule or heuristic change
- [ ] Breaking change (existing configs, output format or API change)
- [ ] Documentation
- [ ] Refactor, tests or tooling only

## Checklist

- [ ] `pytest` passes locally
- [ ] `ruff check src server scripts tests` is clean
- [ ] New behaviour is covered by tests
- [ ] Public functions have docstrings explaining *why*, not just *what*
- [ ] `CHANGELOG.md` has an entry under "Unreleased"

## Privacy and safety

Tick whichever apply, and explain in the notes below.

- [ ] This change sends data off the machine that did not leave it before
- [ ] This change writes to, deletes or moves a user's files
- [ ] This change touches the quarantine vault or its file format
- [ ] This change alters what telemetry collects
- [ ] None of the above

<!--
  If you ticked any of the first four: the project's position is that
  nothing leaves the machine without explicit, per-action consent, and
  nothing destroys a user's file irreversibly. Explain how this change
  holds to that.
-->

## Testing notes

<!--
  How did you verify this? Which OS? If you changed the walker, quarantine
  or the worker pool, say whether you tested against a large tree — those
  are the places where problems only appear at scale.
-->

## Screenshots

<!-- For GUI changes. Delete otherwise. -->
