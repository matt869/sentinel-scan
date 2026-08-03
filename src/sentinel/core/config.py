"""Configuration loading.

Values are resolved from four sources, highest priority first:

1. explicit keyword arguments / CLI flags (applied by the caller)
2. ``SENTINEL_*`` environment variables
3. ``config.toml`` in the platform config directory
4. the defaults declared on the dataclasses below

The whole config is a plain frozen-ish dataclass tree so it can be copied,
compared and serialised without surprises.
"""

from __future__ import annotations

import contextlib
import os
import sys
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Any

from platformdirs import PlatformDirs

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised only on 3.10
    import tomli as tomllib

APP_NAME = "sentinel-scan"
APP_AUTHOR = "sentinel-scan"

_dirs = PlatformDirs(APP_NAME, APP_AUTHOR, roaming=False)

#: Directories excluded from every scan. Scanning these is either pointless
#: (they are volatile kernel state) or actively harmful (recursing into
#: /proc can block forever on a stuck FUSE mount).
DEFAULT_EXCLUDES: tuple[str, ...] = (
    "/proc", "/sys", "/dev", "/run",
    "C:\\Windows\\System32\\config",
    "C:\\Windows\\CSC",
    "C:\\$Recycle.Bin",
    "C:\\System Volume Information",
    "C:\\hiberfil.sys",
    "C:\\pagefile.sys",
    "C:\\swapfile.sys",
)

#: Extensions skipped by default — very large, very common, and essentially
#: never a delivery vector on their own.
DEFAULT_SKIP_EXTENSIONS: tuple[str, ...] = (
    ".iso", ".vmdk", ".vdi", ".vhd", ".vhdx", ".qcow2",
    ".dmp", ".pdb", ".wim", ".swm",
)


class ConfigError(ValueError):
    """Raised when a configuration file or value is invalid."""


@dataclass(slots=True)
class Paths:
    """Filesystem locations the app uses. All are created on demand."""

    data_dir: Path
    config_dir: Path
    cache_dir: Path
    log_dir: Path

    @classmethod
    def default(cls, data_dir: str | os.PathLike[str] | None = None) -> Paths:
        base = Path(data_dir) if data_dir else Path(_dirs.user_data_dir)
        return cls(
            data_dir=base,
            config_dir=Path(_dirs.user_config_dir),
            cache_dir=Path(_dirs.user_cache_dir),
            log_dir=base / "logs",
        )

    @property
    def config_file(self) -> Path:
        return self.config_dir / "config.toml"

    @property
    def db_file(self) -> Path:
        """Local scan history, quarantine index and whitelist."""
        return self.data_dir / "sentinel.db"

    @property
    def quarantine_dir(self) -> Path:
        """Vault holding encrypted copies of quarantined files."""
        return self.data_dir / "quarantine"

    @property
    def signatures_dir(self) -> Path:
        """Where the updater writes downloaded signature bundles."""
        return self.data_dir / "signatures"

    @property
    def log_file(self) -> Path:
        return self.log_dir / "sentinel.log"

    def ensure(self) -> Paths:
        """Create every directory, tightening permissions on POSIX."""
        for directory in (
            self.data_dir, self.config_dir, self.cache_dir,
            self.log_dir, self.quarantine_dir, self.signatures_dir,
        ):
            directory.mkdir(parents=True, exist_ok=True)
        if os.name == "posix":
            # The quarantine vault holds live malware; keep it owner-only.
            with contextlib.suppress(OSError):
                self.quarantine_dir.chmod(0o700)
        return self


@dataclass(slots=True)
class ScanSettings:
    """Traversal and scheduling behaviour."""

    #: Worker threads. 0 means "pick automatically".
    threads: int = 0
    #: Files larger than this skip the content detectors (they are still
    #: hashed, so a known-bad large file is still caught).
    max_file_size: int = 256 * 1024 * 1024
    #: How deep to recurse into nested archives. 0 disables archive support.
    archive_depth: int = 2
    #: Aggregate score (0-100) at which a file is reported as a threat.
    threat_threshold: int = 60
    #: Score at which a file is reported as suspicious but not a threat.
    suspicious_threshold: int = 30
    follow_symlinks: bool = False
    skip_network_drives: bool = True
    skip_removable_drives: bool = False
    #: Stop a single file's scan after this many seconds.
    per_file_timeout: float = 30.0
    exclude_paths: list[str] = field(default_factory=lambda: list(DEFAULT_EXCLUDES))
    exclude_extensions: list[str] = field(
        default_factory=lambda: list(DEFAULT_SKIP_EXTENSIONS)
    )

    def resolved_threads(self) -> int:
        """Return the effective worker count."""
        if self.threads > 0:
            return self.threads
        # Scanning is I/O bound with CPU-bound bursts (hashing, YARA). More
        # than 16 threads reliably makes things slower on spinning disks and
        # gains nothing on NVMe.
        return max(2, min(os.cpu_count() or 4, 16))


@dataclass(slots=True)
class DetectorSettings:
    """Per-detector switches and back-end connection details."""

    hash: bool = True
    yara: bool = True
    pe_heuristic: bool = True
    script: bool = True
    archive: bool = True
    clamav: bool = False
    cloud: bool = False

    clamd_socket: str | None = None
    clamd_host: str = "127.0.0.1"
    clamd_port: int = 3310
    clamd_timeout: float = 30.0

    #: Extra rules loaded on top of the bundled set.
    yara_rules_dir: str | None = None
    yara_timeout: int = 20

    #: Suppress purely heuristic findings on binaries signed by the operating
    #: system vendor. Those components legitimately do the unusual things the
    #: structural heuristics look for. Exact hash matches are never
    #: suppressed. Turn off to audit the OS itself.
    trust_os_vendor_signatures: bool = True

    def enabled_names(self) -> list[str]:
        return [
            name
            for name in ("hash", "yara", "pe_heuristic", "script", "archive",
                         "clamav", "cloud")
            if getattr(self, name)
        ]


@dataclass(slots=True)
class PrivacySettings:
    """Everything that could send data off the machine. All default to off."""

    #: Base URL of a reporting server. Empty means fully offline.
    server_url: str = ""
    api_token: str = ""
    #: Anonymous detection counters.
    telemetry: bool = False
    #: Whether a file's *contents* may be uploaded with a report.
    allow_sample_upload: bool = False
    #: Cloud hash reputation lookups (sends hashes, never file contents).
    allow_cloud_lookup: bool = False
    github_repo: str = "sentinel-scan/sentinel-scan"
    request_timeout: float = 15.0

    @property
    def is_offline(self) -> bool:
        """True when no network feature is configured."""
        return not self.server_url


@dataclass(slots=True)
class UpdateSettings:
    """Signature update behaviour."""

    auto_update: bool = True
    #: Minimum hours between automatic update checks.
    check_interval_hours: int = 12
    #: Refuse to install a bundle whose sha256 is not in the manifest.
    verify_checksums: bool = True
    mirror_url: str = "https://updates.sentinel-scan.example/v1"
    #: Honour the remote rule revocation list — the kill switch that stops a
    #: rule known to misfire. Turning this off means a rule we have already
    #: established is wrong keeps quarantining people's files; it exists for
    #: offline installs pinned to an audited signature set.
    honor_revocations: bool = True
    #: Where to fetch the revocation list. Empty derives it from mirror_url.
    revocation_url: str = ""


@dataclass(slots=True)
class Config:
    """Top-level configuration object passed to the engine."""

    paths: Paths = field(default_factory=Paths.default)
    log_level: str = "INFO"
    scan: ScanSettings = field(default_factory=ScanSettings)
    detectors: DetectorSettings = field(default_factory=DetectorSettings)
    privacy: PrivacySettings = field(default_factory=PrivacySettings)
    updates: UpdateSettings = field(default_factory=UpdateSettings)

    def to_dict(self) -> dict[str, Any]:
        """Serialise to plain types, with Paths rendered as strings."""
        data = asdict(self)
        data["paths"] = {k: str(v) for k, v in data["paths"].items()}
        return data

    def with_overrides(self, **kwargs: Any) -> Config:
        """Return a copy with top-level fields replaced."""
        return replace(self, **kwargs)

    def validate(self) -> None:
        """Raise :class:`ConfigError` if any value is out of range."""
        s = self.scan
        if not 0 <= s.threat_threshold <= 100:
            raise ConfigError("scan.threat_threshold must be between 0 and 100")
        if not 0 <= s.suspicious_threshold <= s.threat_threshold:
            raise ConfigError(
                "scan.suspicious_threshold must be between 0 and threat_threshold"
            )
        if s.threads < 0:
            raise ConfigError("scan.threads must be 0 (auto) or positive")
        if s.max_file_size <= 0:
            raise ConfigError("scan.max_file_size must be positive")
        if s.archive_depth < 0:
            raise ConfigError("scan.archive_depth must be 0 or positive")
        if self.log_level.upper() not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ConfigError(f"invalid log_level {self.log_level!r}")
        if self.detectors.cloud and self.privacy.is_offline:
            raise ConfigError(
                "detectors.cloud is enabled but privacy.server_url is not set"
            )


# ----------------------------------------------------------------------
# Loading
# ----------------------------------------------------------------------

def _coerce(raw: str, current: Any) -> Any:
    """Convert an environment string to the type of the existing value."""
    if isinstance(current, bool):
        return raw.strip().lower() in {"1", "true", "yes", "on"}
    if isinstance(current, int):
        return int(raw)
    if isinstance(current, float):
        return float(raw)
    if isinstance(current, list):
        return [item.strip() for item in raw.split(",") if item.strip()]
    return raw


# env var -> (section attribute or None, field name)
_ENV_MAP: dict[str, tuple[str | None, str]] = {
    "SENTINEL_LOG_LEVEL": (None, "log_level"),
    "SENTINEL_THREADS": ("scan", "threads"),
    "SENTINEL_MAX_FILE_SIZE": ("scan", "max_file_size"),
    "SENTINEL_ARCHIVE_DEPTH": ("scan", "archive_depth"),
    "SENTINEL_THREAT_THRESHOLD": ("scan", "threat_threshold"),
    "SENTINEL_CLAMD_SOCKET": ("detectors", "clamd_socket"),
    "SENTINEL_CLAMD_HOST": ("detectors", "clamd_host"),
    "SENTINEL_CLAMD_PORT": ("detectors", "clamd_port"),
    "SENTINEL_YARA_RULES_DIR": ("detectors", "yara_rules_dir"),
    "SENTINEL_SERVER_URL": ("privacy", "server_url"),
    "SENTINEL_API_TOKEN": ("privacy", "api_token"),
    "SENTINEL_TELEMETRY": ("privacy", "telemetry"),
    "SENTINEL_ALLOW_SAMPLE_UPLOAD": ("privacy", "allow_sample_upload"),
    "SENTINEL_GITHUB_REPO": ("privacy", "github_repo"),
}


def _apply_table(section: Any, table: dict[str, Any], where: str) -> None:
    """Copy known keys from a parsed TOML table onto a settings dataclass."""
    valid = set(section.__slots__) if hasattr(section, "__slots__") else set(vars(section))
    for key, value in table.items():
        if key not in valid:
            raise ConfigError(f"unknown setting {where}.{key}")
        setattr(section, key, value)


def load_config(
    config_file: str | os.PathLike[str] | None = None,
    data_dir: str | os.PathLike[str] | None = None,
    use_env: bool = True,
) -> Config:
    """Build a :class:`Config` from file + environment.

    Args:
        config_file: Explicit TOML path. Defaults to the platform config dir.
        data_dir: Overrides where the database, logs and vault live.
        use_env: Set False to ignore ``SENTINEL_*`` variables (used by tests).

    Raises:
        ConfigError: the file is malformed or a value is out of range.
    """
    data_dir = data_dir or (os.environ.get("SENTINEL_DATA_DIR") if use_env else None)
    config = Config(paths=Paths.default(data_dir))

    path = Path(config_file) if config_file else config.paths.config_file
    if path.is_file():
        try:
            with open(path, "rb") as fh:
                table = tomllib.load(fh)
        except tomllib.TOMLDecodeError as exc:
            raise ConfigError(f"{path} is not valid TOML: {exc}") from exc
        except OSError as exc:
            raise ConfigError(f"cannot read {path}: {exc}") from exc

        if "log_level" in table:
            config.log_level = str(table.pop("log_level"))
        for name in ("scan", "detectors", "privacy", "updates"):
            if name in table:
                sub = table.pop(name)
                if not isinstance(sub, dict):
                    raise ConfigError(f"[{name}] must be a table")
                _apply_table(getattr(config, name), sub, name)
        # Anything left is a typo the user will want to hear about.
        for leftover in table:
            if leftover != "paths":
                raise ConfigError(f"unknown section or key {leftover!r} in {path}")

    if use_env:
        for env_name, (section_name, field_name) in _ENV_MAP.items():
            raw = os.environ.get(env_name)
            if raw is None:
                continue
            target = config if section_name is None else getattr(config, section_name)
            try:
                setattr(target, field_name, _coerce(raw, getattr(target, field_name)))
            except ValueError as exc:
                raise ConfigError(f"{env_name}={raw!r} is not valid: {exc}") from exc

    # Cloud lookups are implied by having a server plus consent, but never
    # turned on silently — the user must opt in explicitly.
    config.validate()
    return config


def save_config(config: Config, config_file: str | os.PathLike[str] | None = None) -> Path:
    """Write *config* back to TOML and return the path written.

    ``paths`` is intentionally not serialised: it is derived from the platform
    and the ``SENTINEL_DATA_DIR`` override, not from the file.
    """
    path = Path(config_file) if config_file else config.paths.config_file
    path.parent.mkdir(parents=True, exist_ok=True)

    lines = [
        "# Sentinel Scan configuration.",
        "# Regenerate the defaults at any time with `sentinel config reset`.",
        "",
        f'log_level = "{config.log_level}"',
        "",
    ]
    for name in ("scan", "detectors", "privacy", "updates"):
        section = getattr(config, name)
        lines.append(f"[{name}]")
        for key, value in asdict(section).items():
            lines.append(f"{key} = {_toml_value(value)}")
        lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")
    if os.name == "posix":
        # The file can hold an API token.
        with contextlib.suppress(OSError):
            path.chmod(0o600)
    return path


def _toml_value(value: Any) -> str:
    """Render a Python value as a TOML literal."""
    if value is None:
        return '""'
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(_toml_value(v) for v in value) + "]"
    escaped = str(value).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'
