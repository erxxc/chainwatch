"""
chainwatch.cli
~~~~~~~~~~~~~~

Click entry point for the chainwatch command-line tool.

Subcommands:
  diff    — analyse a version-to-version package diff (primary command)
  scan    — scan a lockfile, diffing each pinned dependency against its predecessor
  report  — re-render a saved report JSON (no pipeline run, no API key needed)

Global flags:
  --json      emit machine-readable ndjson instead of Rich output
  --verbose   enable debug logging
  --output    write report to a file instead of stdout

Architecture:
  The CLI owns the async event loop.  It creates a shared httpx.AsyncClient,
  runs the pipeline as a single coroutine, then closes the client.

  This means all HTTP connections (feeds + registry calls) share a connection
  pool and benefit from HTTP/2 multiplexing where supported.
"""

from __future__ import annotations

import asyncio
import logging
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.logging import RichHandler

from chainwatch.lockfile import LockedDependency
from chainwatch.models import Ecosystem, RiskReport, ScanEntry

_err_console = Console(stderr=True)


# ── Logging setup ─────────────────────────────────────────────────────────────


def _configure_logging(verbose: bool) -> None:
    """
    Configure the root logger.

    Human mode: Rich handler with coloured levels.
    Verbose mode: DEBUG level — shows all stub warnings and HTTP request traces.

    Logs always go to stderr, never stdout — regardless of mode. RichHandler
    defaults to its own stdout-backed Console when none is given, which would
    otherwise interleave pipeline-stage log lines with the report on stdout
    and corrupt `--json` output (and anything else consuming stdout, e.g.
    `chainwatch diff ... > report.json`). stdout is reserved for the report.
    """
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=_err_console, rich_tracebacks=True, show_path=verbose)],
    )
    # Quieten noisy third-party loggers unless verbose
    if not verbose:
        logging.getLogger("httpx").setLevel(logging.WARNING)
        logging.getLogger("httpcore").setLevel(logging.WARNING)
        logging.getLogger("anthropic").setLevel(logging.WARNING)


# ── Root command group ────────────────────────────────────────────────────────


@click.group()
@click.option("--json", "json_mode", is_flag=True, default=False,
              help="Emit machine-readable ndjson instead of Rich terminal output.")
@click.option("--verbose", "-v", is_flag=True, default=False,
              help="Enable debug logging.")
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None,  # type: ignore[type-var]
              help="Write report to FILE instead of stdout.")
@click.pass_context
def cli(ctx: click.Context, json_mode: bool, verbose: bool, output: Path | None) -> None:
    """
    chainwatch — LLM-assisted supply chain diff analyzer.

    Research tool for detecting malicious package updates by combining
    semantic diff analysis with live threat intelligence feeds.

    https://github.com/erxxc/chainwatch
    """
    ctx.ensure_object(dict)
    ctx.obj["json_mode"] = json_mode
    ctx.obj["verbose"] = verbose
    ctx.obj["output"] = output
    _configure_logging(verbose)


# ── diff subcommand ───────────────────────────────────────────────────────────


@cli.command()
@click.argument("ecosystem", type=click.Choice(["npm", "pypi"], case_sensitive=False))
@click.argument("package")
@click.argument("from_version")
@click.argument("to_version")
@click.option("--no-feeds", is_flag=True, default=False,
              help="Skip threat feed lookups. Faster, offline-friendly.")
@click.option("--threshold", type=int, default=None,
              help="Exit with code 1 if risk score exceeds this value (useful in CI).")
@click.option("--strip-comments", is_flag=True, default=False,
              help="Remove whole-line comments from the diff before the LLM sees it. "
                   "Experimental control for narrative leakage — how much of a score "
                   "comes from prose rather than code (dataset/findings/README.md "
                   "recommendation #8). Recorded in the report.")
@click.option("--split-large-files", is_flag=True, default=False,
              help="Split a file diff larger than one chunk into parts sent as separate "
                   "LLM calls, instead of cutting it head-first at the token budget. "
                   "More calls (capped per file by CHAINWATCH_MAX_SPLIT_PARTS_PER_FILE); "
                   "recorded in the report.")
@click.pass_context
def diff(
    ctx: click.Context,
    ecosystem: str,
    package: str,
    from_version: str,
    to_version: str,
    no_feeds: bool,
    threshold: int | None,
    strip_comments: bool,
    split_large_files: bool,
) -> None:
    """
    Analyse the diff between two versions of a package.

    \b
    Examples:
      chainwatch diff npm event-stream 3.3.4 3.3.5
      chainwatch diff pypi requests 2.31.0 2.32.0
      chainwatch diff npm lodash 4.17.20 4.17.21 --threshold 50
      chainwatch diff npm lodash 4.17.20 4.17.21 --strip-comments
      chainwatch diff npm lodash 4.17.20 4.17.21 --split-large-files

    EXIT CODES:
      0 — Analysis complete, score within threshold (or no threshold set)
      1 — Score exceeds --threshold value
      2 — Pipeline error (network failure, API error, etc.)
    """
    json_mode: bool = ctx.obj["json_mode"]
    output: Path | None = ctx.obj["output"]

    eco = Ecosystem(ecosystem.lower())

    try:
        report = asyncio.run(
            _run_single_diff(
                eco, package, from_version, to_version, no_feeds,
                strip_comments=strip_comments,
                split_large_files=split_large_files,
            )
        )
    except Exception as exc:
        logging.getLogger(__name__).error("Pipeline failed: %s", exc, exc_info=True)
        from chainwatch.output import emit_error
        emit_error(str(exc), json_mode=json_mode)
        sys.exit(2)

    from chainwatch.output import emit_report
    emit_report(report, json_mode=json_mode, output_file=output)

    if threshold is not None and report.risk_score > threshold:
        _err_console.print(
            f"[bold red]THRESHOLD EXCEEDED[/bold red] "
            f"risk_score={report.risk_score:.1f} > threshold={threshold}"
        )
        sys.exit(1)


# ── scan subcommand ────────────────────────────────────────────────────────────


@cli.command()
@click.argument("lockfile", type=click.Path(exists=True, path_type=Path))  # type: ignore[type-var]
@click.option("--no-feeds", is_flag=True, default=False,
              help="Skip threat feed lookups. Faster, offline-friendly.")
@click.option("--threshold", type=int, default=None,
              help="Exit with code 1 if any scanned package's risk score exceeds "
                   "this value (useful in CI).")
@click.option("--limit", type=int, default=25, show_default=True,
              help="Maximum dependencies to scan — each one is a real registry "
                   "fetch + LLM call. 0 = no limit.")
@click.option("--strip-comments", is_flag=True, default=False,
              help="Remove whole-line comments from the diff before the LLM sees it. "
                   "Experimental control for narrative leakage — how much of a score "
                   "comes from prose rather than code (dataset/findings/README.md "
                   "recommendation #8). Recorded in the report.")
@click.option("--split-large-files", is_flag=True, default=False,
              help="Split a file diff larger than one chunk into parts sent as separate "
                   "LLM calls, instead of cutting it head-first at the token budget. "
                   "More calls (capped per file by CHAINWATCH_MAX_SPLIT_PARTS_PER_FILE); "
                   "recorded in the report.")
@click.pass_context
def scan(
    ctx: click.Context,
    lockfile: Path,
    no_feeds: bool,
    threshold: int | None,
    limit: int,
    strip_comments: bool,
    split_large_files: bool,
) -> None:
    """
    Scan a lockfile: diff every pinned dependency against its predecessor.

    For each dependency a lockfile pins, finds the version published
    immediately before the locked one and runs the same pipeline `diff`
    does — answering "was the bump that put this exact version in my
    lockfile itself suspicious?" A lockfile alone has no baseline of its
    own to diff against; the previous published version is the only one
    chainwatch can derive without a second lockfile to compare.

    Supports package-lock.json and yarn.lock (npm; classic v1 and Berry)
    and requirements.txt (PyPI, exact `==` pins only).

    \b
    Examples:
      chainwatch scan package-lock.json
      chainwatch scan yarn.lock
      chainwatch scan requirements.txt --limit 0
      chainwatch scan package-lock.json --threshold 50 --no-feeds

    EXIT CODES:
      0 — Scan complete, nothing exceeded --threshold (or none was set)
      1 — At least one dependency's risk_score exceeded --threshold
      2 — Lockfile could not be parsed
    """
    json_mode: bool = ctx.obj["json_mode"]
    output: Path | None = ctx.obj["output"]
    log = logging.getLogger(__name__)

    from chainwatch.lockfile import parse_lockfile
    from chainwatch.output import emit_error, emit_scan_results

    try:
        ecosystem, dependencies = parse_lockfile(lockfile)
    except ValueError as exc:
        emit_error(str(exc), json_mode=json_mode)
        sys.exit(2)

    if not dependencies:
        _err_console.print(f"[yellow]No pinned dependencies found in {lockfile}.[/yellow]")
        return

    total_found = len(dependencies)
    if limit and total_found > limit:
        _err_console.print(
            f"[dim]{total_found} dependencies found — scanning the first {limit} "
            f"(alphabetical). Use --limit to change this, or --limit 0 for no "
            f"limit.[/dim]"
        )
        dependencies = dependencies[:limit]

    log.info("scan: %d %s dependencies from %s", len(dependencies), ecosystem.value, lockfile)
    entries = asyncio.run(
        _run_scan(
            ecosystem, dependencies, no_feeds,
            strip_comments=strip_comments,
            split_large_files=split_large_files,
        )
    )
    emit_scan_results(entries, json_mode=json_mode, output_file=output)

    if threshold is not None:
        exceeded = [
            e for e in entries
            if e.report is not None and e.report.risk_score > threshold
        ]
        if exceeded:
            names = ", ".join(
                f"{e.package}@{e.to_version} ({e.report.risk_score:.1f})"  # type: ignore[union-attr]
                for e in exceeded
            )
            _err_console.print(f"[bold red]THRESHOLD EXCEEDED[/bold red] for: {names}")
            sys.exit(1)


# ── report subcommand ─────────────────────────────────────────────────────────


@cli.command()
@click.argument("report_file", type=click.Path(exists=True, path_type=Path))  # type: ignore[type-var]
@click.pass_context
def report(ctx: click.Context, report_file: Path) -> None:
    """
    Re-render a saved report JSON in human-readable (or --json) format.

    Loads and validates a report against the current schema, then renders it
    with the same output path as `diff`. Handy for reviewing dataset reports
    without re-running the pipeline (and no API key required).

    EXIT CODES:
      0 — Report loaded and rendered
      2 — File could not be read or did not validate against the schema
    """
    json_mode: bool = ctx.obj["json_mode"]
    output: Path | None = ctx.obj["output"]

    from chainwatch.output import emit_error, emit_report

    try:
        loaded = RiskReport.model_validate_json(report_file.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        emit_error(f"Could not load report {report_file}: {exc}", json_mode=json_mode)
        sys.exit(2)

    emit_report(loaded, json_mode=json_mode, output_file=output)


# ── Pipeline invocation ────────────────────────────────────────────────────────


async def _run_single_diff(
    ecosystem: Ecosystem,
    package: str,
    from_version: str,
    to_version: str,
    no_feeds: bool,
    *,
    strip_comments: bool = False,
    split_large_files: bool = False,
) -> RiskReport:
    """
    Own a client for exactly one `diff` run and delegate to the shared pipeline.

    `scan` doesn't use this — it opens one client and calls
    `pipeline.run_diff_pipeline` in a loop, so the connection pool is shared
    across every package instead of reconnecting per package.
    """
    from chainwatch.pipeline import build_http_client, run_diff_pipeline

    async with build_http_client() as client:
        return await run_diff_pipeline(
            client, ecosystem, package, from_version, to_version, no_feeds,
            strip_comments=strip_comments,
            split_large_files=split_large_files,
        )


async def _run_scan(
    ecosystem: Ecosystem,
    dependencies: list[LockedDependency],
    no_feeds: bool,
    *,
    strip_comments: bool = False,
    split_large_files: bool = False,
) -> list[ScanEntry]:
    """Own one client for the whole scan, so every dependency shares its connection pool."""
    from chainwatch.pipeline import build_http_client
    from chainwatch.scanner import scan_dependencies

    async with build_http_client() as client:
        return await scan_dependencies(
            client, ecosystem, dependencies,
            no_feeds=no_feeds,
            strip_comments=strip_comments,
            split_large_files=split_large_files,
        )
