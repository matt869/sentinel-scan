# Writing detectors

A detector inspects one file and returns zero or more `Detection` objects.
This guide covers the contract, the calibration rules, and a worked example.

## The single most important thing

**A false positive costs more than a missed detection.**

A missed sample is one file a scanner did not catch — bad, but the user is
no worse off than before they installed it. A false positive on a popular
application is thousands of people seeing their own software condemned, and
it is the fastest way to lose their trust in *every other verdict the tool
produces*. A scanner nobody believes is worse than no scanner.

So: score conservatively, prefer low confidences, and let the aggregation
add signals together.

## The contract

```python
from sentinel.engine.detectors.base import Detector, ScanTarget, registry
from sentinel.engine.verdict import Detection
from sentinel.utils.file_types import FileType


@registry.register
class MyDetector(Detector):
    name = "my_detector"                    # stable id, used in config keys
    description = "One line for `sentinel detectors`"
    priority = 55                           # lower runs earlier
    wants = frozenset({FileType.PE})        # empty means "every file type"

    def available(self) -> bool:
        """Can this run at all? Check optional imports here."""
        return True

    def setup(self) -> None:
        """Once per scan: load rules, open sockets, warm caches."""

    def teardown(self) -> None:
        """Always called. Release whatever setup acquired."""

    def scan(self, target: ScanTarget) -> list[Detection]:
        """Inspect the file. Must not raise."""
        return []
```

Register the module in `engine/detectors/__init__.py` so importing the
package registers it, and add it to `DetectorSettings` in `core/config.py`
if it should be toggleable.

### Rules

1. **Never raise.** A detector that throws is logged and skipped for that
   file. Return an empty list when you cannot decide. The engine catches
   exceptions anyway, but relying on that hides bugs.
2. **Never mutate the target.** Detectors run concurrently on one shared
   `ScanTarget`.
3. **Read through the target, not the path.** `target.data`,
   `target.hashes`, `target.header`, `target.entropy` are memoised and
   shared. Opening the file yourself makes every scan read it twice.
4. **Declare `wants`.** It lets the engine skip you without touching the
   file at all.
5. **Bound your work.** Cap how much you parse, how many matches you record,
   how long you loop. You are parsing hostile input.

### `ScanTarget`

| Attribute | Cost | Notes |
|---|---|---|
| `path`, `size`, `extension` | free | |
| `header` | one 4 KiB read | safe on huge files |
| `type_info`, `file_type` | free after `header` | magic bytes, not the extension |
| `hashes`, `sha256`, `md5` | one full read | md5+sha1+sha256 in one pass |
| `data` | full read into memory | `None` above 64 MiB — handle it |
| `text()` | decodes `data` | truncated at 4 MiB |
| `entropy` | needs `data` | chunked profile |
| `depth`, `container`, `member_name` | free | non-zero inside an archive |

Always handle `data is None`.

## Calibrating confidence

Confidence is "how sure is *this detector alone*, in percent". It is not a
severity and not a vote.

| Range | Meaning | Examples |
|---|---|---|
| 5–20 | Worth noting; common in benign files | UPX packing, a long minified line |
| 20–40 | Mildly unusual | High-entropy section, base64 decode call, no import table |
| 40–60 | Suspicious; needs corroboration | Anti-debug imports, encrypted archive holding executables |
| 60–80 | Strongly suspicious on its own | Full process-injection import set, download-and-execute |
| 80–95 | Almost certainly malicious | Credential dumper strings, shadow-copy deletion |
| 95–100 + `conclusive=True` | Definitive identification | Exact hash match, ClamAV signature |

`conclusive=True` forces the aggregate score to exactly 100 **and stops
every remaining detector from running**. Set it only when the match
identifies a specific known sample. A heuristic never gets it — no matter
how confident, it can be wrong, and a wrong conclusive verdict cannot be
outvoted by anything.

### Score combination

```
combined = 1 − Π (1 − confidence_i)
```

- 50 + 50 → 75
- 30 × 5 → 83
- 20 × 5 → 67

Non-conclusive scores are capped at 99, so a pile of guesses can never
imitate a hash match.

This is why individual patterns should be *low*. In `script_detector.py`,
"downloads content" is 30 and "executes a string as code" is 22 — neither is
alarming alone, because neither should be. The combination rule that fires
when both are present adds 60, because *together* they are the standard
dropper shape.

### Prefer combinations to single strong rules

```python
# Weak individually…
if downloads_remote_content(text):
    findings.append(self.detection("Heuristic.Download", 30.0, "..."))
if evaluates_strings(text):
    findings.append(self.detection("Heuristic.Eval", 22.0, "..."))

# …decisive together.
if downloads_remote_content(text) and evaluates_strings(text):
    findings.append(self.detection(
        "Heuristic.Dropper", 60.0,
        "Downloads a remote script and executes it in memory — the "
        "standard dropper pattern",
    ))
```

## Writing the description

The description is shown to a non-specialist who is deciding whether to
delete a file. Write it for them.

```python
# No.
"Suspicious PE characteristics detected"
"Rule PK_MAL_001 matched"

# Yes.
"Sections marked both writable and executable — used by self-modifying "
"code and unpacking stubs."

"This is a Windows executable but is named '.pdf'. There is no legitimate "
"reason to disguise a program as a document."
```

Where a signal is genuinely ambiguous, say so. `pe_heuristic` reports
packers with: *"Legitimate software uses packers too — this is a weak
signal."* That sentence prevents a support issue.

## A worked example

Flagging executables whose digital signature is absent when their metadata
claims a well-known publisher.

```python
"""Detects PE files claiming a known publisher without a valid signature."""

from __future__ import annotations

from typing import Sequence

from sentinel.engine.detectors.base import Detector, ScanTarget, registry
from sentinel.engine.verdict import Detection
from sentinel.utils.file_types import FileType

try:
    import pefile
    _PEFILE_AVAILABLE = True
except ImportError:
    pefile = None
    _PEFILE_AVAILABLE = False

# Publishers whose real binaries are always signed. A file claiming to be
# from one of these without a signature is either corrupt or lying.
ALWAYS_SIGNED = ("microsoft", "google", "mozilla", "adobe", "oracle")


@registry.register
class UnsignedImpostorDetector(Detector):
    name = "unsigned_impostor"
    description = "PE files claiming a major publisher but carrying no signature"
    priority = 55
    wants = frozenset({FileType.PE})

    def available(self) -> bool:
        if not _PEFILE_AVAILABLE:
            self._unavailable_reason = "pefile is not installed"
            return False
        return True

    def scan(self, target: ScanTarget) -> Sequence[Detection]:
        data = target.data
        if data is None:                      # too large to buffer
            return ()

        try:
            pe = pefile.PE(data=data, fast_load=True)
        except Exception:
            return ()                          # not a parseable PE

        try:
            company = self._company_name(pe)
            if not company:
                return ()

            claimed = next(
                (p for p in ALWAYS_SIGNED if p in company.lower()), None
            )
            if claimed is None:
                return ()

            if self._has_signature(pe):
                return ()

            return (
                self.detection(
                    "Heuristic.UnsignedImpostor",
                    65.0,
                    f"This file's metadata says it is from {company}, but it "
                    f"carries no digital signature. Genuine {claimed.title()} "
                    f"software is always signed.",
                    claimed_publisher=company,
                ),
            )
        except Exception as exc:
            self.log.debug("analysis failed for %s: %s", target.display_path, exc)
            return ()
        finally:
            pe.close()

    def _company_name(self, pe) -> str:
        try:
            pe.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]]
            )
            for info in getattr(pe, "FileInfo", []):
                for entry in info:
                    for table in getattr(entry, "StringTable", []):
                        value = table.entries.get(b"CompanyName", b"")
                        if value:
                            return value.decode("utf-8", errors="replace").strip()
        except Exception:
            pass
        return ""

    def _has_signature(self, pe) -> bool:
        """True if a security directory is present.

        Note this checks for *presence*, not validity — verifying a chain
        needs the platform trust store. Presence is enough for this
        heuristic, and the 65% confidence reflects that.
        """
        try:
            entry = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
            ]
            return entry.VirtualAddress != 0 and entry.Size != 0
        except Exception:
            return False
```

Note the shape: bail out early and often, wrap everything, always
`pe.close()`, and let the docstring admit exactly what the check does *not*
prove.

## Testing

Test the negative cases hardest.

```python
class TestUnsignedImpostor:
    def test_flags_an_unsigned_microsoft_claim(self, scanner, tmp_path):
        path = build_pe(tmp_path, company="Microsoft Corporation", signed=False)
        verdict = scanner.scan_file(path)
        assert any(d.name == "Heuristic.UnsignedImpostor" for d in verdict.detections)

    def test_ignores_a_signed_binary(self, scanner, tmp_path):
        path = build_pe(tmp_path, company="Microsoft Corporation", signed=True)
        assert not scanner.scan_file(path).detections

    def test_ignores_an_unknown_publisher(self, scanner, tmp_path):
        path = build_pe(tmp_path, company="Small Indie Studio", signed=False)
        assert not scanner.scan_file(path).detections

    def test_survives_a_corrupt_pe(self, scanner, tmp_path):
        path = tmp_path / "broken.exe"
        path.write_bytes(b"MZ" + b"\x00" * 100)
        scanner.scan_file(path)     # must not raise
```

Then run it over a real corpus before opening the pull request:

```bash
sentinel scan "C:\Program Files" --detectors unsigned_impostor --json > out.json
python -c "import json;print(len(json.load(open('out.json'))['threats']))"
```

If that number is not close to zero, the rule is not ready.

## Performance

`scripts/benchmark.py --detectors` times each detector per file. Rough
budget: under 1 ms/file for the common case; a few ms is acceptable for a
detector that only sees a narrow file type.

- Use `interested_in` to reject cheaply.
- Prefer `target.header` to `target.data` when the header is enough.
- Compile regexes at module level, never per call.
- Cap how much text you scan (`script_detector` stops at 200 KB for its
  statistical checks).

## YARA rules

Rules go in `src/sentinel/signatures/local/rules/`. Metadata this project
reads:

```yara
rule Example_Rule : malware
{
    meta:
        description = "Plain English, written for a non-specialist."
        confidence  = 75          // 0-100; overrides the tag default
        severity    = "high"
        threat_name = "Heuristic.Example"   // shown instead of the rule name
        author      = "you"
        reference   = "https://..."

    strings:
        $a = "indicator one" nocase
        $b = { 4D 5A 90 00 }

    condition:
        uint16(0) == 0x5A4D and all of them
}
```

Always set `confidence` explicitly. Without it the value comes from the tag
(`malware` → 90, `suspicious` → 45, `packer` → 35), which is rarely what you
meant.
