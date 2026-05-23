"""
chainwatch.cli
~~~~~~~~~~~~~~

Click entry point for the chainwatch command-line tool.

Subcommands:
  diff    — analyse a version-to-version package diff (primary command)
  scan    — [stub] scan a lockfile for all dependency upgrades
  report  — [stub] re-render a saved report JSON

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
import httpx
from rich.console import Console
from rich.logging import RichHandler

from chainwatch.config import get_settings
from chainwatch.models import Ecosystem

_err_console = Console(stderr=True)


# ── Logging setup ─────────────────────────────────────────────────────────────


def _configure_logging(verbose: bool) -> None:
    """
    Configure the root logger.

    Human mode: Rich handler with coloured levels.
    Verbose mode: DEBUG level — shows all stub warnings and HTTP request traces.
    """
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True, show_path=verbose)],
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
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None,
              help="Write report to FILE instead of stdout.")
@click.pass_context
def cli(ctx: click.Context, json_mode: bool, verbose: bool, output: Path | None) -> None:
    """
    chainwatch — LLM-assisted supply chain diff analyzer.

    Research tool for detecting malicious package updates by combining
    semantic diff analysis with live threat intelligence feeds.

    https://github.com/your-org/chainwatch
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
@click.pass_context
def diff(
    ctx: click.Context,
    ecosystem: str,
    package: str,
    from_version: str,
    to_version: str,
    no_feeds: bool,
    threshold: int | None,
) -> None:
    """
    Analyse the diff between two versions of a package.

    \b
    Examples:
      chainwatch diff npm event-stream 3.3.4 3.3.5
      chainwatch diff pypi requests 2.31.0 2.32.0
      chainwatch diff npm lodash 4.17.20 4.17.21 --threshold 50

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
            _run_diff_pipeline(
                ecosystem=eco,
                package=package,
                from_version=from_version,
                to_version=to_version,
                no_feeds=no_feeds,
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


# ── scan subcommand (stub) ────────────────────────────────────────────────────


@cli.command()
@click.argument("lockfile", type=click.Path(exists=True, path_type=Path))
@click.pass_context
def scan(ctx: click.Context, lockfile: Path) -> None:
    """
    [STUB] Scan a lockfile and analyse all dependency upgrades.

    Parses package-lock.json / yarn.lock / requirements.txt and runs
    chainwatch diff on every version bump found.

    Not yet implemented — Day 2 scope.
    """
    _err_console.print(
        "[yellow]scan[/yellow] subcommand is not yet implemented. "
        "Use [bold]chainwatch diff[/bold] for individual package analysis."
    )
    sys.exit(2)


# ── report subcommand (stub) ──────────────────────────────────────────────────


@cli.command()
@click.argument("report_file", type=click.Path(exists=True, path_type=Path))
@click.pass_context
def report(ctx: click.Context, report_file: Path) -> None:
    """
    [STUB] Re-render a saved report JSON in human-readable format.

    Useful for reviewing dataset reports without re-running the pipeline.

    Not yet implemented — Day 4 scope.
    """
    _err_console.print(
        "[yellow]report[/yellow] subcommand is not yet implemented."
    )
    sys.exit(2)


# ── Pipeline coroutine ────────────────────────────────────────────────────────


async def _run_diff_pipeline(
    ecosystem: Ecosystem,
    package: str,
    from_version: str,
    to_version: str,
    no_feeds: bool,
) -> "RiskReport":
    """
    Execute the full chainwatch pipeline for a single package diff.

    Pipeline stages (in order):
      1. Fetch both package versions from the registry
      2. Compute structured diff (engine + chunker)
      3. Concurrently:
           a. Send diff chunks to LLM for risk analysis
           b. Query all three threat feeds (OSV, Rekor, Scorecard)
      4. Aggregate scores into composite RiskReport

    The concurrent stage (3) is the key architectural decision: LLM calls
    are slow (~5–15s) and feed calls are fast (~0.5–2s), so running them
    in parallel saves wall-clock time without complicating the code.

    Args:
        ecosystem:     npm or pypi
        package:       Package name
        from_version:  Baseline version
        to_version:    Target version
        no_feeds:      If True, skip feed lookups

    Returns:
        Fully assembled RiskReport
    """
    from chainwatch.analyzer import aggregator, feeds
    from chainwatch.analyzer.llm import analyze_diff
    from chainwatch.diff import chunker, engine
    from chainwatch.fetcher import npm, pypi
    from chainwatch.models import FeedResult, FeedStatus

    settings = get_settings()
    log = logging.getLogger(__name__)

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(settings.http_timeout),
        follow_redirects=True,
        headers={"User-Agent": f"chainwatch/{_get_version()} (research tool)"},
    ) as client:

        # ── Stage 1: Fetch ────────────────────────────────────────────────────
        log.info("Stage 1/4 — fetching %s/%s %s → %s", ecosystem.value, package, from_version, to_version)

        if ecosystem == Ecosystem.npm:
            fetch_result = await npm.fetch_package_versions(client, package, from_version, to_version)
        else:
            fetch_result = await pypi.fetch_package_versions(client, package, from_version, to_version)

        with fetch_result:  # ensures temp dirs are cleaned up
            # ── Stage 2: Diff ─────────────────────────────────────────────────
            log.info("Stage 2/4 — computing diff")
            diff_summary = engine.compute_diff(fetch_result.from_dir, fetch_result.to_dir)
            diff_chunks = chunker.chunk_diff(diff_summary, settings.max_tokens_per_chunk)

            # ── Stage 3: Concurrent LLM + feeds ──────────────────────────────
            log.info(
                "Stage 3/4 — LLM analysis + feed lookups (%d chunk(s), feeds=%s)",
                len(diff_chunks), "off" if no_feeds else "on",
            )

            # Build stub feed results if feeds are disabled
            stub_feed_results: list[FeedResult] = [
                FeedResult(source="osv",       status=FeedStatus.no_data, details="Feeds disabled (--no-feeds)"),
                FeedResult(source="rekor",     status=FeedStatus.no_data, details="Feeds disabled (--no-feeds)"),
                FeedResult(source="scorecard", status=FeedStatus.no_data, details="Feeds disabled (--no-feeds)"),
            ]

            llm_task = asyncio.create_task(
                analyze_diff(
                    diff_summary=diff_summary,
                    diff_chunks=diff_chunks,
                    package=package,
                    ecosystem=ecosystem,
                    from_version=from_version,
                    to_version=to_version,
                )
            )

            async def _stub_feeds() -> list[FeedResult]:
                return stub_feed_results

            feeds_task = asyncio.create_task(
                feeds.run_all_feeds(
                    client=client,
                    package=package,
                    ecosystem=ecosystem,
                    from_version=from_version,
                    to_version=to_version,
                    to_version_sha256=fetch_result.to_sha256,
                ) if not no_feeds else _stub_feeds()
            )

            (dimensions, llm_summary, llm_model), feed_results = await asyncio.gather(
                llm_task, feeds_task
            )

            # ── Stage 4: Aggregate ────────────────────────────────────────────
            log.info("Stage 4/4 — aggregating scores")
            return aggregator.build_report(
                package=package,
                ecosystem=ecosystem,
                from_version=from_version,
                to_version=to_version,
                from_sha256=fetch_result.from_sha256,
                to_sha256=fetch_result.to_sha256,
                diff_summary=diff_summary,
                dimensions=dimensions,
                feed_results=feed_results,
                llm_summary=llm_summary,
                llm_model=llm_model,
            )


def _get_version() -> str:
    """Return the package version string."""
    try:
        from importlib.metadata import version
        return version("chainwatch")
    except Exception:
        return "0.1.0"
