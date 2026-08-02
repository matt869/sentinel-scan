"""The ``sentinel`` command-line interface.

Design notes:

* **Exit codes follow the ClamAV convention** so this drops into existing
  scripts: 0 clean, 1 threats found, 2 an error occurred.
* ``--json`` writes a machine-readable report to stdout and moves all log
  output to stderr, so ``sentinel scan --json | jq`` works.
* Destructive actions (quarantine, delete, restore) require either an
  interactive confirmation or an explicit ``--yes``.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table

from sentinel.core.config import Config, ConfigError, load_config, save_config
from sentinel.core.db import Database
from sentinel.core.events import Event, EventBus, EventType
from sentinel.core.logger import setup_logging
from sentinel.engine.scanner import Scanner
from sentinel.engine.verdict import SEVERITY_COLORS, ScanResult, Severity, Verdict
from sentinel.utils.humanize import (
    human_bytes,
    human_count,
    human_duration,
    shorten_path,
)
from sentinel.version import __version__

app = typer.Typer(
    name="sentinel",
    help="Sentinel Scan — a cross-platform malware scanner.",
    add_completion=True,
    no_args_is_help=True,
    rich_markup_mode="rich",
)

quarantine_app = typer.Typer(help="Inspect and manage the quarantine vault.", no_args_is_help=True)
whitelist_app = typer.Typer(help="Manage the known-good file list.", no_args_is_help=True)
config_app = typer.Typer(help="Inspect and edit configuration.", no_args_is_help=True)

app.add_typer(quarantine_app, name="quarantine")
app.add_typer(whitelist_app, name="whitelist")
app.add_typer(config_app, name="config")

console = Console()
err_console = Console(stderr=True)

EXIT_CLEAN = 0
EXIT_THREATS = 1
EXIT_ERROR = 2


# ----------------------------------------------------------------------
# shared helpers
# ----------------------------------------------------------------------

def _load(config_file: Path | None = None, log_level: str = "") -> Config:
    """Load configuration, exiting cleanly on a bad config file."""
    try:
        config = load_config(config_file)
    except ConfigError as exc:
        err_console.print(f"[red]Configuration error:[/red] {exc}")
        raise typer.Exit(EXIT_ERROR) from exc
    if log_level:
        config.log_level = log_level.upper()
    config.paths.ensure()
    return config


def _severity_markup(severity: Severity) -> str:
    return f"[{SEVERITY_COLORS[severity]}]{severity.value}[/]"


def _confirm(message: str, yes: bool) -> bool:
    """Ask for confirmation unless --yes was passed or stdin is not a TTY."""
    if yes:
        return True
    if not sys.stdin.isatty():
        err_console.print(
            f"[yellow]Refusing to continue without confirmation:[/yellow] {message}\n"
            f"Pass --yes to proceed non-interactively."
        )
        return False
    return typer.confirm(message)


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"sentinel-scan {__version__}")
        raise typer.Exit()


@app.callback()
def main_callback(
    version: bool = typer.Option(
        False, "--version", "-V", callback=_version_callback, is_eager=True,
        help="Show the version and exit.",
    ),
) -> None:
    """Sentinel Scan — a cross-platform malware scanner."""


# ----------------------------------------------------------------------
# scan
# ----------------------------------------------------------------------

@app.command()
def scan(
    paths: list[Path] = typer.Argument(
        None, help="Files or directories to scan. Defaults to a quick scan."
    ),
    quick: bool = typer.Option(
        False, "--quick", "-q",
        help="Scan the high-risk locations only (Downloads, temp, autostart).",
    ),
    full: bool = typer.Option(
        False, "--full", help="Scan every fixed drive. Slow."
    ),
    quarantine: bool = typer.Option(
        False, "--quarantine",
        help="Move findings at or above --quarantine-level into the vault.",
    ),
    quarantine_level: str = typer.Option(
        "high", "--quarantine-level",
        help="Minimum severity to auto-quarantine: low|medium|high|critical.",
    ),
    as_json: bool = typer.Option(
        False, "--json", help="Write a JSON report to stdout."
    ),
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Write the JSON report to a file."
    ),
    threads: int = typer.Option(
        0, "--threads", "-t", help="Worker threads. 0 picks automatically."
    ),
    detectors: str | None = typer.Option(
        None, "--detectors",
        help="Comma-separated detector names to use instead of the configured set.",
    ),
    max_size: int | None = typer.Option(
        None, "--max-size", help="Skip content detectors above this many bytes."
    ),
    no_archives: bool = typer.Option(
        False, "--no-archives", help="Do not look inside archives."
    ),
    show_all: bool = typer.Option(
        False, "--all", help="List clean files too, not just findings."
    ),
    log_level: str = typer.Option("", "--log-level", help="DEBUG|INFO|WARNING|ERROR."),
    config_file: Path | None = typer.Option(None, "--config", help="Config file."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmations."),
) -> None:
    """Scan files or directories for malware."""
    config = _load(config_file, log_level)

    # With --json, stdout must stay parseable: send everything else to stderr.
    setup_logging(
        config.log_level, config.paths.log_file, quiet=as_json, force=True
    )

    if threads > 0:
        config.scan.threads = threads
    if max_size is not None:
        config.scan.max_file_size = max_size
    if no_archives:
        config.scan.archive_depth = 0

    roots = _resolve_roots(paths, quick, full, config)
    if not roots:
        err_console.print("[red]Nothing to scan.[/red]")
        raise typer.Exit(EXIT_ERROR)

    try:
        level = Severity(quarantine_level.lower())
    except ValueError:
        err_console.print(
            f"[red]Invalid --quarantine-level {quarantine_level!r}.[/red] "
            f"Use one of: low, medium, high, critical."
        )
        raise typer.Exit(EXIT_ERROR) from None

    if quarantine and not _confirm(
        f"Automatically quarantine findings of severity {level.value} or above?", yes
    ):
        raise typer.Exit(EXIT_ERROR)

    detector_names = (
        [d.strip() for d in detectors.split(",") if d.strip()] if detectors else None
    )

    bus = EventBus()
    scanner = Scanner(config, bus=bus, detectors=detector_names)

    if not as_json:
        _print_scan_header(roots, scanner)

    try:
        if as_json:
            result = scanner.scan_paths(roots, quarantine, level)
        else:
            result = _scan_with_progress(scanner, bus, roots, quarantine, level)
    except KeyboardInterrupt:
        scanner.cancel()
        err_console.print("\n[yellow]Cancelled.[/yellow]")
        raise typer.Exit(EXIT_ERROR) from None
    finally:
        scanner.close()

    if as_json or output:
        payload = json.dumps(result.to_dict(), indent=2)
        if output:
            output.write_text(payload, encoding="utf-8")
            if not as_json:
                console.print(f"Report written to [cyan]{output}[/cyan]")
        if as_json:
            console.print_json(payload)
    else:
        _print_results(result, show_all)

    raise typer.Exit(result.exit_code())


def _resolve_roots(
    paths: list[Path] | None, quick: bool, full: bool, config: Config
) -> list[str]:
    """Work out what to scan from the flags given."""
    if paths:
        return [str(p) for p in paths]

    if full:
        from sentinel.system.drives import scannable_roots

        return scannable_roots(
            skip_network=config.scan.skip_network_drives,
            skip_removable=config.scan.skip_removable_drives,
        )

    # Default and --quick are the same thing: the high-value locations.
    from sentinel.system import high_value_scan_paths

    roots = high_value_scan_paths()
    if not quick and not roots:
        return [str(Path.home())]
    return roots


def _print_scan_header(roots: list[str], scanner: Scanner) -> None:
    active = [d.name for d in scanner.detectors] or None
    if active is None:
        # Detectors are built at scan time; show what is configured.
        active = [
            row["name"] for row in scanner.detector_status()
            if row["enabled"] and row["available"]
        ]
    console.print(
        Panel(
            "\n".join(
                [
                    "[bold]Scanning:[/bold] "
                    + ", ".join(escape(shorten_path(r, 50)) for r in roots[:4])
                    + (f" [dim](+{len(roots) - 4} more)[/dim]" if len(roots) > 4 else ""),
                    "[bold]Detectors:[/bold] " + (", ".join(active) or "[red]none[/red]"),
                ]
            ),
            title=f"Sentinel Scan {__version__}",
            border_style="cyan",
        )
    )


def _scan_with_progress(
    scanner: Scanner,
    bus: EventBus,
    roots: list[str],
    quarantine: bool,
    level: Severity,
) -> ScanResult:
    """Run a scan behind a live progress bar."""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=None),
        TextColumn("{task.completed:,} files"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Scanning…", total=None)

        def on_progress(event: Event) -> None:
            progress.update(
                task,
                completed=event.get("files_scanned", 0),
                description=f"Scanning {shorten_path(event.get('current', ''), 44)}",
            )

        def on_threat(event: Event) -> None:
            # Print findings as they happen; a long scan should not stay
            # silent about something it already found.
            severity = Severity(event.get("severity", "medium"))
            progress.console.print(
                f"  {_severity_markup(severity)} "
                f"[bold]{escape(event.get('name', '?'))}[/bold] — "
                f"{escape(shorten_path(event.get('path', ''), 60))}"
            )

        bus.subscribe(EventType.SCAN_PROGRESS, on_progress)
        bus.subscribe(EventType.THREAT_FOUND, on_threat)

        return scanner.scan_paths(roots, quarantine, level)


def _print_results(result: ScanResult, show_all: bool) -> None:
    """Render the human-readable summary."""
    findings = result.threats + result.suspicious

    if findings:
        table = Table(
            title=f"{human_count(len(findings), 'finding')}",
            header_style="bold",
            expand=True,
        )
        table.add_column("Severity", width=10)
        table.add_column("Score", justify="right", width=6)
        table.add_column("Threat", overflow="fold")
        table.add_column("File", overflow="fold")

        for verdict in sorted(findings, key=lambda v: -v.score):
            table.add_row(
                _severity_markup(verdict.severity),
                f"{verdict.score:.0f}",
                escape(verdict.name or "—"),
                escape(shorten_path(verdict.path, 60)),
            )
        console.print(table)

        console.print()
        for verdict in sorted(findings, key=lambda v: -v.score)[:5]:
            _print_detail(verdict)

    summary_style = "red" if result.threat_count else "green"
    summary = (
        f"[bold]{human_count(result.files_scanned, 'file')}[/bold] scanned "
        f"({human_bytes(result.bytes_scanned)}) in "
        f"{human_duration(result.duration)}\n"
        f"[bold {summary_style}]{result.threat_count} threat(s)[/], "
        f"{result.suspicious_count} suspicious, "
        f"{result.files_skipped} skipped, {result.errors} error(s)"
    )
    if result.cancelled:
        summary += "\n[yellow]Scan was cancelled — results are incomplete.[/yellow]"

    console.print(
        Panel(summary, title="Summary", border_style=summary_style)
    )

    if show_all and result.verdicts:
        console.print("\n[dim]Use --json for the complete machine-readable report.[/dim]")


def _print_detail(verdict: Verdict) -> None:
    """Explain one finding: what fired, and why."""
    lines = [f"[bold]{escape(shorten_path(verdict.path, 70))}[/bold]"]
    lines.append(
        f"  {_severity_markup(verdict.severity)}  score {verdict.score:.0f}/100  "
        f"{human_bytes(verdict.size)}"
    )
    if verdict.sha256:
        lines.append(f"  [dim]sha256 {verdict.sha256}[/dim]")
    lines.append("")
    for detection in verdict.detections[:6]:
        marker = "!" if detection.conclusive else "·"
        lines.append(
            f"  {marker} [cyan]{escape(detection.detector)}[/cyan] "
            f"[bold]{escape(detection.name)}[/bold] ({detection.confidence:.0f}%)"
        )
        if detection.description:
            lines.append(f"      [dim]{escape(detection.description)}[/dim]")
    if len(verdict.detections) > 6:
        lines.append(f"  [dim]…and {len(verdict.detections) - 6} more[/dim]")

    console.print(Panel("\n".join(lines), border_style="dim", padding=(0, 1)))


# ----------------------------------------------------------------------
# detectors / status / history
# ----------------------------------------------------------------------

@app.command()
def detectors(
    config_file: Path | None = typer.Option(None, "--config"),
) -> None:
    """List the detectors and whether each one can run."""
    config = _load(config_file)
    setup_logging(config.log_level, quiet=True, force=True)

    scanner = Scanner(config)
    try:
        rows = scanner.detector_status()
    finally:
        scanner.close()

    table = Table(header_style="bold", expand=True)
    table.add_column("Detector", width=14)
    table.add_column("Status", width=14)
    table.add_column("Description", overflow="fold")

    for row in sorted(rows, key=lambda r: r["priority"]):
        if not row["enabled"]:
            status = "[dim]disabled[/dim]"
        elif row["available"]:
            status = "[green]active[/green]"
        else:
            status = "[yellow]unavailable[/yellow]"
        # The reasons name extras like "sentinel-scan[yara]"; without
        # escaping, Rich eats the brackets and prints the wrong command.
        table.add_row(
            row["name"], status, escape(row["reason"] or row["description"])
        )

    console.print(table)
    console.print(
        "\n[dim]Unavailable detectors are missing an optional dependency. "
        "Install everything with: pip install 'sentinel-scan\\[all]'[/dim]"
    )


@app.command()
def status(config_file: Path | None = typer.Option(None, "--config")) -> None:
    """Show signature versions, vault size and privacy settings."""
    config = _load(config_file)
    setup_logging(config.log_level, quiet=True, force=True)

    from sentinel.feedback.sample_upload import describe_gate
    from sentinel.signatures.loader import SignatureStore
    from sentinel.system.privileges import privilege_info

    signatures = SignatureStore(config).summary()
    db = Database(config.paths.db_file)
    try:
        counts = db.stats()
    finally:
        db.close()

    privileges = privilege_info()

    table = Table.grid(padding=(0, 2))
    table.add_column(style="bold")
    table.add_column()

    table.add_row("Version", __version__)
    table.add_row("Running as", f"{privileges.user} ({privileges.label})")
    table.add_row("Data directory", str(config.paths.data_dir))
    table.add_row("", "")
    table.add_row("Signature version", str(signatures["version"]))
    table.add_row("Signatures updated", str(signatures["updated"]))
    table.add_row("Hash signatures", f"{signatures['hash_count']:,}")
    table.add_row("YARA rule files", str(signatures["yara_files"]))
    table.add_row("ClamAV bundles", str(signatures["clamav_bundles"]))
    table.add_row("", "")
    table.add_row("Scans recorded", f"{counts['scans']:,}")
    table.add_row("Findings recorded", f"{counts['findings']:,}")
    table.add_row("Quarantined files", f"{counts['quarantine']:,}")
    table.add_row("Whitelist entries", f"{counts['whitelist']:,}")
    table.add_row("", "")
    table.add_row(
        "Server", config.privacy.server_url or "[dim]none (fully offline)[/dim]"
    )
    table.add_row("Telemetry", "enabled" if config.privacy.telemetry else "disabled")
    table.add_row("Sample upload", describe_gate(config).split(": ", 1)[1])

    console.print(Panel(table, title="Sentinel Scan status", border_style="cyan"))

    if not privileges.elevated:
        console.print(f"\n[dim]{privileges.note}[/dim]")


@app.command()
def history(
    limit: int = typer.Option(10, "--limit", "-n", help="How many scans to show."),
    scan_id: int | None = typer.Option(
        None, "--scan", help="Show the findings from one scan."
    ),
    config_file: Path | None = typer.Option(None, "--config"),
) -> None:
    """Show past scans and their findings."""
    config = _load(config_file)
    setup_logging(config.log_level, quiet=True, force=True)
    db = Database(config.paths.db_file)

    try:
        if scan_id is not None:
            findings = db.findings_for_scan(scan_id)
            if not findings:
                console.print(f"No findings recorded for scan {scan_id}.")
                return
            table = Table(title=f"Scan {scan_id}", header_style="bold", expand=True)
            table.add_column("Severity", width=10)
            table.add_column("Score", justify="right", width=6)
            table.add_column("Threat", overflow="fold")
            table.add_column("File", overflow="fold")
            table.add_column("Action", width=12)
            for row in findings:
                table.add_row(
                    _severity_markup(Severity(row["severity"])),
                    str(row["score"]),
                    escape(row["name"] or "—"),
                    escape(shorten_path(row["path"], 50)),
                    row["action"],
                )
            console.print(table)
            return

        scans = db.recent_scans(limit)
        if not scans:
            console.print("No scans recorded yet. Run [cyan]sentinel scan[/cyan].")
            return

        table = Table(header_style="bold", expand=True)
        table.add_column("ID", justify="right", width=5)
        table.add_column("Started", width=20)
        table.add_column("Status", width=10)
        table.add_column("Files", justify="right", width=9)
        table.add_column("Threats", justify="right", width=8)
        table.add_column("Duration", justify="right", width=10)

        for record in scans:
            threat_style = "red" if record.threats else "green"
            table.add_row(
                str(record.id),
                record.started_display,
                record.status,
                f"{record.files_scanned:,}",
                f"[{threat_style}]{record.threats}[/]",
                human_duration(record.duration),
            )
        console.print(table)
        console.print("\n[dim]Show one scan's findings: sentinel history --scan ID[/dim]")
    finally:
        db.close()


# ----------------------------------------------------------------------
# update
# ----------------------------------------------------------------------

@app.command()
def update(
    check_only: bool = typer.Option(
        False, "--check", help="Report whether an update is available and exit."
    ),
    force: bool = typer.Option(False, "--force", help="Reinstall even if current."),
    config_file: Path | None = typer.Option(None, "--config"),
) -> None:
    """Download the latest signature bundles."""
    config = _load(config_file)
    setup_logging(config.log_level, config.paths.log_file, force=True)

    from sentinel.signatures.updater import SignatureUpdater, UpdateError

    try:
        updater = SignatureUpdater(config)
    except UpdateError as exc:
        err_console.print(f"[red]{exc}[/red]")
        raise typer.Exit(EXIT_ERROR) from exc

    if check_only:
        available, local, remote = updater.check()
        if available:
            console.print(
                f"Update available: [yellow]{local or '(none)'}[/yellow] -> "
                f"[green]{remote}[/green]"
            )
            raise typer.Exit(EXIT_CLEAN)
        console.print(f"Signatures are current (version {local}).")
        raise typer.Exit(EXIT_CLEAN)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Updating signatures…", total=None)

        def on_progress(name: str, done: int, total: int) -> None:
            progress.update(
                task,
                description=f"Downloading {name}",
                completed=done,
                total=total or None,
            )

        try:
            result = updater.update(force=force, progress=on_progress)
        except UpdateError as exc:
            err_console.print(f"[red]Update failed:[/red] {exc}")
            raise typer.Exit(EXIT_ERROR) from exc

    style = "green" if result.ok else "yellow"
    console.print(f"[{style}]{result.summary()}[/]")
    if result.files_failed:
        err_console.print(
            f"[yellow]Failed:[/yellow] {', '.join(result.files_failed)}"
        )
        raise typer.Exit(EXIT_ERROR)


# ----------------------------------------------------------------------
# quarantine
# ----------------------------------------------------------------------

def _quarantine(config: Config) -> tuple[Any, Database]:
    from sentinel.engine.quarantine import Quarantine

    db = Database(config.paths.db_file)
    return Quarantine(config, db), db


@quarantine_app.command("list")
def quarantine_list(
    include_restored: bool = typer.Option(
        False, "--all", help="Include files that were already restored."
    ),
    config_file: Path | None = typer.Option(None, "--config"),
) -> None:
    """List files held in the vault."""
    config = _load(config_file)
    setup_logging(config.log_level, quiet=True, force=True)
    vault, db = _quarantine(config)

    try:
        entries = vault.list_entries(include_restored)
        if not entries:
            console.print("The quarantine vault is empty.")
            return

        table = Table(header_style="bold", expand=True)
        table.add_column("Token", width=16)
        table.add_column("Severity", width=10)
        table.add_column("Threat", overflow="fold")
        table.add_column("Original path", overflow="fold")
        table.add_column("Size", justify="right", width=10)
        table.add_column("Age", justify="right", width=8)

        for entry in entries:
            table.add_row(
                entry.token[:16],
                _severity_markup(Severity(entry.severity)),
                escape(entry.name),
                escape(shorten_path(entry.original_path, 40)),
                human_bytes(entry.size),
                f"{entry.age_days:.0f}d",
            )
        console.print(table)
        console.print(
            f"\n[dim]Vault holds {human_bytes(vault.total_size())}. "
            f"Restore with: sentinel quarantine restore TOKEN[/dim]"
        )
    finally:
        db.close()


@quarantine_app.command("restore")
def quarantine_restore(
    token: str = typer.Argument(..., help="Token from `sentinel quarantine list`."),
    destination: Path | None = typer.Option(
        None, "--to", help="Restore somewhere other than the original path."
    ),
    overwrite: bool = typer.Option(False, "--overwrite", help="Replace an existing file."),
    yes: bool = typer.Option(False, "--yes", "-y"),
    config_file: Path | None = typer.Option(None, "--config"),
) -> None:
    """Put a quarantined file back on disk."""
    config = _load(config_file)
    setup_logging(config.log_level, config.paths.log_file, force=True)
    vault, db = _quarantine(config)

    try:
        entry = vault.get(token)
        if entry is None:
            err_console.print(f"[red]No quarantined file with token {token!r}.[/red]")
            raise typer.Exit(EXIT_ERROR)

        console.print(
            Panel(
                f"[bold]{escape(entry.name)}[/bold]\n"
                f"Original path: {escape(entry.original_path)}\n"
                f"Size: {human_bytes(entry.size)}\n"
                f"Severity: {_severity_markup(Severity(entry.severity))}",
                title="About to restore",
                border_style="yellow",
            )
        )
        if not _confirm(
            "This file was flagged as malicious. Restore it anyway?", yes
        ):
            raise typer.Exit(EXIT_ERROR)

        from sentinel.engine.quarantine import QuarantineError

        try:
            path = vault.restore(token, destination, overwrite)
        except QuarantineError as exc:
            err_console.print(f"[red]Restore failed:[/red] {exc}")
            raise typer.Exit(EXIT_ERROR) from exc

        console.print(f"[green]Restored to[/green] {path}")
    finally:
        db.close()


@quarantine_app.command("delete")
def quarantine_delete(
    token: str = typer.Argument(..., help="Token to destroy permanently."),
    yes: bool = typer.Option(False, "--yes", "-y"),
    config_file: Path | None = typer.Option(None, "--config"),
) -> None:
    """Permanently destroy a quarantined file."""
    config = _load(config_file)
    setup_logging(config.log_level, config.paths.log_file, force=True)
    vault, db = _quarantine(config)

    try:
        entry = vault.get(token)
        if entry is None:
            err_console.print(f"[red]No quarantined file with token {token!r}.[/red]")
            raise typer.Exit(EXIT_ERROR)

        if not _confirm(
            f"Permanently delete '{entry.name}' ({entry.original_path})? "
            f"This cannot be undone.",
            yes,
        ):
            raise typer.Exit(EXIT_ERROR)

        from sentinel.engine.quarantine import QuarantineError

        try:
            vault.delete(token)
        except QuarantineError as exc:
            err_console.print(f"[red]{exc}[/red]")
            raise typer.Exit(EXIT_ERROR) from exc
        console.print("[green]Deleted.[/green]")
    finally:
        db.close()


@quarantine_app.command("purge")
def quarantine_purge(
    older_than: int = typer.Option(30, "--older-than", help="Age in days."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show what would go."),
    yes: bool = typer.Option(False, "--yes", "-y"),
    config_file: Path | None = typer.Option(None, "--config"),
) -> None:
    """Delete vault entries older than a given age."""
    config = _load(config_file)
    setup_logging(config.log_level, config.paths.log_file, force=True)
    vault, db = _quarantine(config)

    try:
        candidates = vault.purge(older_than, dry_run=True)
        if not candidates:
            console.print(f"Nothing in the vault is older than {older_than} days.")
            return

        console.print(f"{human_count(len(candidates), 'file')} older than {older_than} days.")
        if dry_run:
            for token in candidates:
                entry = vault.get(token)
                if entry:
                    console.print(f"  {token[:16]}  {entry.name}  {entry.original_path}")
            return

        if not _confirm(
            f"Permanently delete {len(candidates)} quarantined file(s)?", yes
        ):
            raise typer.Exit(EXIT_ERROR)

        purged = vault.purge(older_than)
        console.print(f"[green]Purged {len(purged)} file(s).[/green]")
    finally:
        db.close()


# ----------------------------------------------------------------------
# whitelist
# ----------------------------------------------------------------------

@whitelist_app.command("list")
def whitelist_list(config_file: Path | None = typer.Option(None, "--config")) -> None:
    """Show every whitelist entry."""
    config = _load(config_file)
    setup_logging(config.log_level, quiet=True, force=True)
    db = Database(config.paths.db_file)

    try:
        entries = db.list_whitelist()
        if not entries:
            console.print("The whitelist is empty.")
            return

        table = Table(header_style="bold", expand=True)
        table.add_column("Kind", width=8)
        table.add_column("Value", overflow="fold")
        table.add_column("Note", overflow="fold")
        for row in entries:
            table.add_row(
                row["kind"], escape(row["value"]), escape(row["note"] or "—")
            )
        console.print(table)
    finally:
        db.close()


@whitelist_app.command("add")
def whitelist_add(
    value: str = typer.Argument(..., help="A sha256 digest, a file path, or a directory."),
    kind: str | None = typer.Option(
        None, "--kind", help="Force the kind: sha256|path|prefix."
    ),
    note: str = typer.Option("", "--note", help="Why this entry exists."),
    config_file: Path | None = typer.Option(None, "--config"),
) -> None:
    """Suppress findings for a known-good file.

    Prefer a sha256 digest: it survives the file moving, and cannot be
    abused by an attacker who can write to a whitelisted path.
    """
    config = _load(config_file)
    setup_logging(config.log_level, quiet=True, force=True)

    from sentinel.engine.whitelist import Whitelist, WhitelistError

    db = Database(config.paths.db_file)
    try:
        whitelist = Whitelist(db)
        try:
            added = whitelist.add(value, kind, note)
        except WhitelistError as exc:
            err_console.print(f"[red]{exc}[/red]")
            raise typer.Exit(EXIT_ERROR) from exc

        if added:
            console.print(f"[green]Added.[/green] The whitelist now has {len(whitelist)} entries.")
        else:
            console.print("[yellow]That entry was already present.[/yellow]")
    finally:
        db.close()


@whitelist_app.command("remove")
def whitelist_remove(
    value: str = typer.Argument(..., help="The value to remove."),
    config_file: Path | None = typer.Option(None, "--config"),
) -> None:
    """Remove a whitelist entry."""
    config = _load(config_file)
    setup_logging(config.log_level, quiet=True, force=True)

    from sentinel.engine.whitelist import Whitelist

    db = Database(config.paths.db_file)
    try:
        if Whitelist(db).remove(value):
            console.print("[green]Removed.[/green]")
        else:
            console.print("[yellow]No such entry.[/yellow]")
            raise typer.Exit(EXIT_ERROR)
    finally:
        db.close()


# ----------------------------------------------------------------------
# system
# ----------------------------------------------------------------------

@app.command()
def system(
    as_json: bool = typer.Option(False, "--json"),
    scan_autoruns: bool = typer.Option(
        False, "--scan", help="Also scan every file referenced by an autorun entry."
    ),
    config_file: Path | None = typer.Option(None, "--config"),
) -> None:
    """Inspect autoruns, processes, drives and the hosts file."""
    config = _load(config_file)
    setup_logging(config.log_level, quiet=as_json, force=True)

    from sentinel.system import system_report
    from sentinel.system.autoruns import collect as collect_autoruns
    from sentinel.system.autoruns import targets_for_scan

    report = system_report()

    if as_json:
        console.print_json(json.dumps(report))
    else:
        _print_system_report(report)

    if scan_autoruns:
        targets = targets_for_scan(collect_autoruns())
        if not targets:
            console.print("\nNo autorun targets to scan.")
            return
        console.print(f"\nScanning {human_count(len(targets), 'autorun target')}…")
        scanner = Scanner(config)
        try:
            result = scanner.scan_paths(targets, record_history=False)
        finally:
            scanner.close()
        _print_results(result, show_all=False)
        raise typer.Exit(result.exit_code())


def _print_system_report(report: dict[str, Any]) -> None:
    privileges = report["privileges"]
    console.print(
        Panel(
            f"{privileges['user']} ({privileges['label']}) on {privileges['platform']}\n"
            f"[dim]{privileges['note']}[/dim]",
            title="Privileges",
            border_style="cyan",
        )
    )

    drives = Table(title="Drives", header_style="bold", expand=True)
    drives.add_column("Path", width=16)
    drives.add_column("Label", overflow="fold")
    drives.add_column("Type", width=10)
    drives.add_column("Filesystem", width=10)
    drives.add_column("Free", justify="right", width=10)
    for drive in report["drives"]:
        drives.add_row(
            escape(drive["path"]), escape(drive["label"]), drive["kind"],
            drive["filesystem"], human_bytes(drive["free"]),
        )
    console.print(drives)

    autoruns = report["autoruns"]
    console.print(
        f"\n[bold]Autoruns:[/bold] {autoruns['total']} total, "
        f"{len(autoruns['flagged'])} worth a look"
    )
    for entry in autoruns["flagged"][:10]:
        console.print(f"  [yellow]•[/yellow] [bold]{escape(entry['name'])}[/bold] "
                      f"[dim]({escape(entry['location'])})[/dim]")
        console.print(f"    {escape(shorten_path(entry['command'], 76))}")
        for flag in entry["flags"][:2]:
            console.print(f"    [dim]{escape(flag)}[/dim]")
    if len(autoruns["flagged"]) > 10:
        console.print(f"  [dim]…and {len(autoruns['flagged']) - 10} more[/dim]")

    processes = report["processes"]["flagged"]
    if processes:
        console.print(f"\n[bold]Processes worth a look:[/bold] {len(processes)}")
        for process in processes[:10]:
            console.print(f"  [yellow]•[/yellow] [bold]{escape(process['name'])}[/bold] "
                          f"(pid {process['pid']})")
            for flag in process["flags"][:2]:
                console.print(f"    [dim]{escape(flag)}[/dim]")

    hosts = report["hosts"]
    console.print(f"\n[bold]Hosts file:[/bold] {hosts['path']}")
    if hosts["error"]:
        console.print(f"  [dim]{hosts['error']}[/dim]")
    elif not hosts["findings"]:
        console.print(f"  [green]No unusual entries[/green] "
                      f"({hosts['custom_entries']} custom)")
    else:
        for finding in hosts["findings"]:
            colour = {"high": "red", "medium": "yellow"}.get(finding["severity"], "dim")
            console.print(
                f"  [{colour}]•[/] line {finding['line']}: {escape(finding['message'])}"
            )
            console.print(f"    [dim]{escape(finding['raw'])}[/dim]")


# ----------------------------------------------------------------------
# report / telemetry
# ----------------------------------------------------------------------

@app.command()
def report(
    path: Path = typer.Argument(..., help="The file the report is about."),
    false_positive: bool = typer.Option(
        False, "--false-positive", "-f", help="You believe this file is clean."
    ),
    missed: bool = typer.Option(
        False, "--missed", "-m", help="You believe this file is malicious."
    ),
    comment: str = typer.Option(
        "", "--comment", "-c", help="Explain what you expected. Required."
    ),
    origin: str = typer.Option("", "--origin", help="Where the file came from."),
    include_sample: bool = typer.Option(
        False, "--include-sample",
        help="Attach the file itself. Requires privacy.allow_sample_upload.",
    ),
    open_browser: bool = typer.Option(
        True, "--open/--no-open", help="Open the GitHub issue in a browser."
    ),
    config_file: Path | None = typer.Option(None, "--config"),
) -> None:
    """Report a false positive or a missed detection."""
    config = _load(config_file)
    setup_logging(config.log_level, config.paths.log_file, force=True)

    if false_positive == missed:
        err_console.print(
            "[red]Choose exactly one of --false-positive or --missed.[/red]"
        )
        raise typer.Exit(EXIT_ERROR)

    if not path.is_file():
        err_console.print(f"[red]{path} is not a file.[/red]")
        raise typer.Exit(EXIT_ERROR)

    if not comment.strip():
        if not sys.stdin.isatty():
            err_console.print("[red]--comment is required.[/red]")
            raise typer.Exit(EXIT_ERROR)
        comment = typer.prompt("Briefly, what did you expect?")

    from sentinel.feedback.report import (
        build_false_positive,
        build_missed_detection,
        submit,
    )

    if false_positive:
        scanner = Scanner(config)
        try:
            verdict = scanner.scan_file(path)
        finally:
            scanner.close()
        if not verdict.detections:
            console.print(
                "[yellow]This file is not currently flagged, so there is no "
                "false positive to report.[/yellow]"
            )
            raise typer.Exit(EXIT_CLEAN)
        item = build_false_positive(verdict, comment, origin, include_sample)
    else:
        item = build_missed_detection(path, comment, origin, include_sample)

    console.print(
        Panel(
            item.to_json(),
            title="This is exactly what will be sent",
            border_style="cyan",
        )
    )
    if include_sample:
        from sentinel.feedback.sample_upload import check_sample

        check = check_sample(path, config)
        style = "yellow" if check.allowed else "red"
        console.print(f"[{style}]Sample: {check.reason or 'will be attached'}[/]")

    if not _confirm("Submit this report?", yes=False):
        raise typer.Exit(EXIT_ERROR)

    try:
        outcome = submit(item, config, path if include_sample else None)
    except ValueError as exc:
        err_console.print(f"[red]{exc}[/red]")
        raise typer.Exit(EXIT_ERROR) from exc

    if outcome["method"] == "server":
        console.print(f"[green]Submitted.[/green] Report id: {outcome['report_id']}")
    else:
        url = outcome["url"]
        console.print(
            "[cyan]No reporting server is configured, so this has been turned "
            "into a GitHub issue you can review and submit yourself:[/cyan]"
        )
        console.print(f"\n{url}\n")
        if open_browser:
            from sentinel.feedback.github_fallback import open_in_browser

            if not open_in_browser(url):
                console.print("[dim]Could not open a browser; copy the link above.[/dim]")


@app.command()
def telemetry(
    preview: bool = typer.Option(
        False, "--preview", help="Print exactly what would be sent, and send nothing."
    ),
    enable: bool = typer.Option(False, "--enable", help="Turn telemetry on."),
    disable: bool = typer.Option(False, "--disable", help="Turn telemetry off."),
    config_file: Path | None = typer.Option(None, "--config"),
) -> None:
    """Inspect or change anonymous telemetry."""
    config = _load(config_file)
    setup_logging(config.log_level, quiet=True, force=True)

    from sentinel.feedback.telemetry import TelemetryCollector, consent_notice

    if enable and disable:
        err_console.print("[red]Choose one of --enable or --disable.[/red]")
        raise typer.Exit(EXIT_ERROR)

    if enable or disable:
        config.privacy.telemetry = enable
        path = save_config(config, config_file)
        state = "enabled" if enable else "disabled"
        console.print(f"[green]Telemetry {state}.[/green] Written to {path}")
        return

    console.print(Panel(consent_notice(), title="Telemetry", border_style="cyan"))
    console.print(
        f"\nCurrently: [bold]"
        f"{'enabled' if config.privacy.telemetry else 'disabled'}[/bold]"
    )

    if preview:
        console.print(
            Panel(
                TelemetryCollector(config).preview(),
                title="What would be sent right now",
                border_style="dim",
            )
        )


# ----------------------------------------------------------------------
# config
# ----------------------------------------------------------------------

@config_app.command("show")
def config_show(
    config_file: Path | None = typer.Option(None, "--config"),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """Print the effective configuration."""
    config = _load(config_file)
    if as_json:
        console.print_json(json.dumps(config.to_dict(), default=str))
        return

    for section in ("scan", "detectors", "privacy", "updates"):
        table = Table(title=f"[{section}]", header_style="bold", expand=True)
        table.add_column("Setting", width=26)
        table.add_column("Value", overflow="fold")
        values = config.to_dict()[section]
        for key, value in values.items():
            shown = str(value)
            if "token" in key and value:
                shown = "[dim]set (hidden)[/dim]"
            table.add_row(key, shown)
        console.print(table)

    console.print(f"\n[dim]Config file: {config.paths.config_file}[/dim]")
    console.print(f"[dim]Data directory: {config.paths.data_dir}[/dim]")


@config_app.command("path")
def config_path(config_file: Path | None = typer.Option(None, "--config")) -> None:
    """Print the path of the configuration file."""
    console.print(str(_load(config_file).paths.config_file))


@config_app.command("init")
def config_init(
    config_file: Path | None = typer.Option(None, "--config"),
    force: bool = typer.Option(False, "--force", help="Overwrite an existing file."),
) -> None:
    """Write a configuration file containing the current defaults."""
    config = _load(config_file)
    target = config_file or config.paths.config_file

    if target.exists() and not force:
        err_console.print(
            f"[yellow]{target} already exists.[/yellow] Pass --force to overwrite."
        )
        raise typer.Exit(EXIT_ERROR)

    written = save_config(config, target)
    console.print(f"[green]Wrote[/green] {written}")


# ----------------------------------------------------------------------
# gui
# ----------------------------------------------------------------------

@app.command()
def gui(config_file: Path | None = typer.Option(None, "--config")) -> None:
    """Launch the desktop interface."""
    try:
        from sentinel.ui.app import main as gui_main
    except ImportError as exc:
        err_console.print(
            f"[red]The GUI needs PySide6:[/red] pip install 'sentinel-scan\\[gui]'\n"
            f"[dim]{escape(str(exc))}[/dim]"
        )
        raise typer.Exit(EXIT_ERROR) from exc

    raise typer.Exit(gui_main(str(config_file) if config_file else None))


def run() -> None:
    """Entry point used by ``sentinel.__main__``."""
    app()


if __name__ == "__main__":  # pragma: no cover
    run()
