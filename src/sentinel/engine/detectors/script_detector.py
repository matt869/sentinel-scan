"""Heuristics for script-based droppers and loaders.

Targets the delivery stage that actually lands on user machines: a PowerShell
one-liner in an email attachment, an obfuscated JScript file, a shell script
that curls a payload and runs it.

The approach is to score *techniques*, not keywords. ``Invoke-WebRequest`` is
completely ordinary on its own; ``Invoke-WebRequest`` piped into ``IEX`` with
a base64 blob and a hidden window is not. Individual patterns therefore carry
low confidence and the combination rules carry the weight.
"""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Sequence
from dataclasses import dataclass

from sentinel.engine.detectors.base import Detector, ScanTarget, registry
from sentinel.engine.verdict import Detection
from sentinel.utils.file_types import FileType

#: Scripts above this size are almost always legitimate application code;
#: droppers are small. Scanning a 5 MB minified bundle wastes time and
#: produces noise.
MAX_SCRIPT_SIZE = 2 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class Pattern:
    """One weighted indicator."""

    id: str
    regex: re.Pattern[str]
    weight: float
    description: str
    #: Restrict to certain languages; empty means all.
    languages: frozenset[str] = frozenset()


def _p(id_: str, pattern: str, weight: float, description: str, *languages: str) -> Pattern:
    return Pattern(
        id_,
        re.compile(pattern, re.IGNORECASE | re.MULTILINE),
        weight,
        description,
        frozenset(languages),
    )


PATTERNS: tuple[Pattern, ...] = (
    # --- execution of dynamically-built code --------------------------
    _p("eval_string", r"\b(?:IEX|Invoke-Expression)\b", 22.0,
       "Executes a string as code (Invoke-Expression)", "powershell"),
    _p("js_eval", r"\beval\s*\(\s*(?:atob|unescape|String\.fromCharCode|decodeURI)",
       28.0, "Evaluates a decoded string", "javascript"),
    _p("js_function_ctor", r"\bnew\s+Function\s*\(", 18.0,
       "Builds a function from a string at runtime", "javascript"),
    _p("vbs_execute", r"\bExecute(?:Global)?\s*\(", 22.0,
       "Executes a string as code", "vbscript"),
    _p("shell_eval", r"\beval\s+\"?\$", 18.0,
       "Evaluates a variable as a command", "shell"),

    # --- encoded payloads ---------------------------------------------
    _p("ps_encoded_command", r"-[eE](?:nc|ncoded|ncodedCommand)?\s+[A-Za-z0-9+/=]{40,}",
       45.0, "PowerShell -EncodedCommand with a base64 payload", "powershell"),
    _p("from_base64", r"FromBase64String|atob\s*\(|base64\s+-d|b64decode", 20.0,
       "Decodes a base64 blob"),
    _p("char_array", r"(?:\[char\]\s*\d+\s*[,+]\s*){6,}", 30.0,
       "Reconstructs a string from character codes"),
    _p("fromcharcode", r"String\.fromCharCode\s*\((?:\s*\d+\s*,){6,}", 30.0,
       "Reconstructs a string from character codes", "javascript"),
    _p("hex_string_blob", r"(?:\\x[0-9a-f]{2}){20,}", 25.0,
       "Long hex-escaped byte sequence"),

    # --- download and run ---------------------------------------------
    _p("ps_download", r"(?:DownloadString|DownloadFile|DownloadData)\s*\(", 30.0,
       "Downloads content from the network", "powershell"),
    _p("ps_webclient", r"Net\.WebClient|Invoke-WebRequest|Invoke-RestMethod|curl\s+-", 15.0,
       "Makes an outbound HTTP request"),
    _p("shell_pipe_to_shell",
       r"(?:curl|wget)\s[^|;\n]{4,200}\|\s*(?:ba)?sh\b", 55.0,
       "Pipes a downloaded script straight into a shell", "shell"),
    _p("bitsadmin", r"\bbitsadmin\s+/transfer|\bcertutil\s+(?:-urlcache|-decode)", 45.0,
       "Uses a living-off-the-land binary to fetch or decode a payload"),

    # --- hiding -------------------------------------------------------
    _p("ps_hidden_window", r"-W(?:indowStyle)?\s+[Hh]idden|-NonI(?:nteractive)?\b", 25.0,
       "Runs with no visible window", "powershell"),
    _p("ps_bypass", r"-Exec(?:utionPolicy)?\s+(?:Bypass|Unrestricted)", 35.0,
       "Disables the PowerShell execution policy", "powershell"),
    _p("hidden_attrib", r"\battrib\s+\+[hs]", 20.0,
       "Marks files hidden or system"),

    # --- persistence and damage ---------------------------------------
    _p("registry_run_key",
       r"(?:CurrentVersion\\Run|HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run)",
       35.0, "Writes an autostart registry key"),
    _p("scheduled_task", r"\bschtasks\s+/create|Register-ScheduledTask", 30.0,
       "Creates a scheduled task for persistence"),
    _p("shadow_copy_delete", r"vssadmin\s+delete\s+shadows|wbadmin\s+delete\s+catalog",
       85.0, "Deletes volume shadow copies — a hallmark of ransomware"),
    _p("bcdedit_recovery", r"bcdedit\s+/set\s+\{?default\}?\s+recoveryenabled\s+no",
       80.0, "Disables Windows recovery — a hallmark of ransomware"),
    _p("defender_exclusion", r"Add-MpPreference\s+-ExclusionPath|Set-MpPreference\s+-Disable",
       70.0, "Adds an antivirus exclusion or disables real-time protection"),
    _p("rm_rf_root", r"\brm\s+-[rRf]{2,}\s+(?:/|\$HOME|~)(?:\s|$)", 75.0,
       "Recursively deletes a root or home directory", "shell"),

    # --- credential access --------------------------------------------
    _p("mimikatz", r"sekurlsa::|Invoke-Mimikatz|lsadump::", 90.0,
       "Invokes credential-dumping tooling"),
    _p("lsass_dump", r"procdump.{0,40}lsass|MiniDumpWriteDump", 75.0,
       "Dumps the memory of the credential store process"),
)

#: Combinations that mean far more together than apart.
#: (id set, extra confidence, description)
COMBINATIONS: tuple[tuple[frozenset[str], float, str], ...] = (
    (
        frozenset({"ps_download", "eval_string"}),
        60.0,
        "Downloads a remote script and executes it in memory — the standard "
        "PowerShell dropper pattern",
    ),
    (
        frozenset({"from_base64", "eval_string"}),
        55.0,
        "Decodes a base64 payload and executes it",
    ),
    (
        frozenset({"js_eval", "ps_webclient"}),
        50.0,
        "Fetches remote content and evaluates it",
    ),
    (
        frozenset({"ps_bypass", "ps_hidden_window"}),
        40.0,
        "Runs hidden with the execution policy disabled",
    ),
    (
        frozenset({"shadow_copy_delete", "bcdedit_recovery"}),
        95.0,
        "Destroys every local recovery option before encrypting — ransomware",
    ),
)

_LANGUAGE_BY_EXTENSION = {
    ".ps1": "powershell", ".psm1": "powershell", ".psd1": "powershell",
    ".js": "javascript", ".jse": "javascript", ".mjs": "javascript",
    ".vbs": "vbscript", ".vbe": "vbscript", ".wsf": "vbscript", ".hta": "vbscript",
    ".sh": "shell", ".bash": "shell", ".zsh": "shell",
    ".bat": "batch", ".cmd": "batch",
    ".py": "python", ".pyw": "python",
    ".pl": "perl", ".rb": "ruby", ".php": "php",
}

#: Minimum length of a base64 run before we try to decode it.
_B64_MIN = 60
_B64_RE = re.compile(rf"[A-Za-z0-9+/]{{{_B64_MIN},}}={{0,2}}")


@registry.register
class ScriptDetector(Detector):
    """Scores obfuscation and dropper techniques in text-based scripts."""

    name = "script"
    description = "Heuristics for obfuscated scripts and droppers"
    priority = 45
    wants = frozenset({FileType.SCRIPT, FileType.TEXT})

    def interested_in(self, target: ScanTarget) -> bool:
        if not super().interested_in(target):
            return False
        return 0 < target.size <= MAX_SCRIPT_SIZE

    def scan(self, target: ScanTarget) -> Sequence[Detection]:
        text = target.text()
        if not text.strip():
            return ()

        language = _LANGUAGE_BY_EXTENSION.get(target.extension, "")
        if not language:
            language = self._sniff_language(text)

        matched: dict[str, Pattern] = {}
        for pattern in PATTERNS:
            if pattern.languages and language and language not in pattern.languages:
                continue
            if pattern.regex.search(text):
                matched[pattern.id] = pattern

        findings: list[Detection] = [
            self.detection(
                f"Heuristic.Script.{pattern.id}",
                pattern.weight,
                pattern.description,
                language=language or "unknown",
                technique=pattern.id,
            )
            for pattern in matched.values()
        ]

        findings.extend(self._check_combinations(matched, language))
        findings.extend(self._check_obfuscation(text, language))
        findings.extend(self._check_nested_base64(text, language))

        return findings

    # -- individual checks ---------------------------------------------

    def _check_combinations(
        self, matched: dict[str, Pattern], language: str
    ) -> list[Detection]:
        out = []
        for ids, confidence, description in COMBINATIONS:
            if ids <= matched.keys():
                out.append(
                    self.detection(
                        "Heuristic.Script.Dropper",
                        confidence,
                        description,
                        language=language or "unknown",
                        techniques=sorted(ids),
                    )
                )
        return out

    def _check_obfuscation(self, text: str, language: str) -> list[Detection]:
        """Statistical signals that the source has been machine-mangled."""
        out: list[Detection] = []
        sample = text[:200_000]
        if len(sample) < 200:
            return out

        # Very long single lines are the signature of a minified or generated
        # payload. Minified web assets do this too, hence the low weight.
        longest_line = max((len(line) for line in sample.splitlines()), default=0)
        if longest_line > 5000:
            out.append(
                self.detection(
                    "Heuristic.Script.LongLine",
                    20.0,
                    f"Contains a {longest_line:,}-character line, typical of generated "
                    "or minified payloads.",
                    longest_line=longest_line,
                    language=language or "unknown",
                )
            )

        # Escape-heavy source: `\x41\x42\x43...` style string building.
        escapes = sample.count("\\x") + sample.count("%u") + sample.count("chr(")
        if escapes > 40 and escapes / len(sample) > 0.005:
            out.append(
                self.detection(
                    "Heuristic.Script.EscapeHeavy",
                    30.0,
                    f"{escapes} escape sequences — strings are being assembled "
                    "byte by byte to evade keyword matching.",
                    escape_count=escapes,
                    language=language or "unknown",
                )
            )

        # PowerShell string concatenation obfuscation: 'I'+'E'+'X'
        if language == "powershell":
            concat = len(re.findall(r"'\s*\+\s*'", sample))
            if concat > 15:
                out.append(
                    self.detection(
                        "Heuristic.Script.ConcatObfuscation",
                        35.0,
                        f"{concat} string concatenations used to hide keywords.",
                        concat_count=concat,
                        language=language,
                    )
                )

            # Backtick-in-the-middle-of-a-word obfuscation: I`E`X
            ticks = len(re.findall(r"\w`\w", sample))
            if ticks > 8:
                out.append(
                    self.detection(
                        "Heuristic.Script.TickObfuscation",
                        40.0,
                        f"{ticks} escape characters inserted inside identifiers to "
                        "break keyword matching.",
                        tick_count=ticks,
                        language=language,
                    )
                )

        return out

    def _check_nested_base64(self, text: str, language: str) -> list[Detection]:
        """Decode embedded base64 and look for a script hiding inside.

        Only the first few large blobs are examined — a file full of embedded
        images should not cost us a second of CPU.
        """
        out: list[Detection] = []
        for index, match in enumerate(_B64_RE.finditer(text)):
            if index >= 4:
                break
            blob = match.group(0)
            try:
                decoded = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
            except (binascii.Error, ValueError):
                continue

            # PowerShell's -EncodedCommand is UTF-16LE.
            for encoding in ("utf-16-le", "utf-8"):
                try:
                    inner = decoded.decode(encoding)
                except (UnicodeDecodeError, LookupError):
                    continue
                if not inner.isprintable() and "\n" not in inner:
                    continue
                hits = [p for p in PATTERNS if p.regex.search(inner)]
                if hits:
                    out.append(
                        self.detection(
                            "Heuristic.Script.EncodedPayload",
                            75.0,
                            "A base64 blob in this file decodes to a script that "
                            f"{hits[0].description.lower()}.",
                            language=language or "unknown",
                            inner_techniques=[p.id for p in hits[:5]],
                            encoding=encoding,
                        )
                    )
                    return out  # one report is enough
                break

        return out

    @staticmethod
    def _sniff_language(text: str) -> str:
        """Guess the language from a shebang or leading syntax."""
        head = text[:400].lower()
        if head.startswith("#!"):
            first_line = head.splitlines()[0]
            for name in ("python", "bash", "sh", "perl", "ruby", "php", "node"):
                if name in first_line:
                    return {"sh": "shell", "bash": "shell", "node": "javascript"}.get(
                        name, name
                    )
        if "$psversiontable" in head or ("param(" in head and "-object" in head):
            return "powershell"
        if head.lstrip().startswith(("@echo off", "@echo")):
            return "batch"
        if "dim " in head and "wscript" in head:
            return "vbscript"
        return ""
