"""
chainwatch.pipeline
~~~~~~~~~~~~~~~~~~~

The core version-to-version diff pipeline, shared by the ``diff`` and
``scan`` CLI commands.

This used to live inline in ``cli.py`` as a private helper, back when
``diff`` was the only caller. ``scan`` needs to run the same pipeline many
times against one shared ``httpx.AsyncClient`` (so a lockfile scan benefits
from connection pooling across dozens of packages instead of paying a fresh
TCP/TLS handshake per package), so the pipeline itself no longer owns the
client's lifecycle — the caller creates one client and passes it in,
whether that's a single `diff` run or a `scan` loop.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Awaitable
from typing import TypeVar

import httpx

from chainwatch.config import get_settings
from chainwatch.models import Ecosystem, PipelineTimings, RiskReport

log = logging.getLogger(__name__)

T = TypeVar("T")


async def _timed(awaitable: Awaitable[T]) -> tuple[T, float]:
    """Await ``awaitable`` and return its result with the seconds it took."""
    started = time.perf_counter()
    result = await awaitable
    return result, time.perf_counter() - started


def build_http_client() -> httpx.AsyncClient:
    """
    Build the shared ``httpx.AsyncClient`` used for all registry/feed/tarball
    requests in a pipeline run (or a whole `scan` batch of them).

    Centralised so `diff` and `scan` construct it identically — same timeout,
    same redirect policy, same User-Agent — without duplicating the call.
    """
    settings = get_settings()
    return httpx.AsyncClient(
        timeout=httpx.Timeout(settings.http_timeout),
        follow_redirects=True,
        headers={"User-Agent": f"chainwatch/{_get_version()} (research tool)"},
    )


async def run_diff_pipeline(
    client: httpx.AsyncClient,
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
    Execute the full chainwatch pipeline for a single package diff.

    Pipeline stages (in order):
      1. Fetch both package versions from the registry
      2. Compute structured diff (engine + chunker)
      3. Concurrently:
           a. Send diff chunks to LLM for risk analysis
           b. Query all four threat feeds (OSV, Rekor, Scorecard,
              new-dependency provenance — the last keyed on
              diff_summary.new_dependencies, not on package/version)
      4. Aggregate scores into composite RiskReport

    The concurrent stage (3) is the key architectural decision: LLM calls
    are slow (~5–15s) and feed calls are fast (~0.5–2s), so running them
    in parallel saves wall-clock time without complicating the code.

    Args:
        client:        Shared httpx.AsyncClient (caller-owned lifecycle —
                        this function never opens or closes it, so a `scan`
                        loop can reuse one client's connection pool across
                        many calls).
        ecosystem:     npm or pypi
        package:       Package name
        from_version:  Baseline version
        to_version:    Target version
        no_feeds:      If True, skip feed lookups
        strip_comments: If True, remove whole-line comments from the diff
                        before the LLM sees it (the narrative-leakage
                        control — see chainwatch.diff.preprocess)
        split_large_files: If True, split an oversized file diff into parts
                        across chunks instead of truncating it head-first
                        (bounded by settings.max_split_parts_per_file)

    Returns:
        Fully assembled RiskReport, with per-stage ``timings`` recorded
    """
    from chainwatch.analyzer import aggregator, feeds
    from chainwatch.analyzer.llm import analyze_diff
    from chainwatch.diff import chunker, engine, preprocess
    from chainwatch.fetcher import npm, pypi
    from chainwatch.models import FeedResult, FeedStatus

    settings = get_settings()
    started = time.perf_counter()

    # ── Stage 1: Fetch ────────────────────────────────────────────────────────
    log.info(
        "Stage 1/4 — fetching %s/%s %s → %s",
        ecosystem.value, package, from_version, to_version,
    )

    if ecosystem == Ecosystem.npm:
        fetch_result = await npm.fetch_package_versions(
            client, package, from_version, to_version,
        )
    else:
        fetch_result = await pypi.fetch_package_versions(
            client, package, from_version, to_version,
        )

    fetch_seconds = time.perf_counter() - started

    with fetch_result:  # ensures temp dirs are cleaned up
        # ── Stage 2: Diff ───────────────────────────────────────────────────
        log.info("Stage 2/4 — computing diff")
        diff_started = time.perf_counter()
        diff_summary = engine.compute_diff(fetch_result.from_dir, fetch_result.to_dir)
        if strip_comments:
            preprocess.strip_comment_lines(diff_summary)
        diff_chunks = chunker.chunk_diff(
            diff_summary,
            settings.max_tokens_per_chunk,
            split_large_files=split_large_files,
            max_parts_per_file=settings.max_split_parts_per_file,
        )
        diff_seconds = time.perf_counter() - diff_started

        # ── Stage 3: Concurrent LLM + feeds ──────────────────────────────────
        log.info(
            "Stage 3/4 — LLM analysis + feed lookups (%d chunk(s), feeds=%s)",
            len(diff_chunks), "off" if no_feeds else "on",
        )

        # Build stub feed results if feeds are disabled
        no_feeds_msg = "Feeds disabled (--no-feeds)"
        stub_feed_results: list[FeedResult] = [
            FeedResult(source="osv", status=FeedStatus.no_data, details=no_feeds_msg),
            FeedResult(source="rekor", status=FeedStatus.no_data, details=no_feeds_msg),
            FeedResult(source="scorecard", status=FeedStatus.no_data, details=no_feeds_msg),
            FeedResult(source="new_deps", status=FeedStatus.no_data, details=no_feeds_msg),
        ]

        analysis_started = time.perf_counter()
        llm_task = asyncio.create_task(
            _timed(analyze_diff(
                diff_summary=diff_summary,
                diff_chunks=diff_chunks,
                package=package,
                ecosystem=ecosystem,
                from_version=from_version,
                to_version=to_version,
            ))
        )

        async def _stub_feeds() -> list[FeedResult]:
            return stub_feed_results

        feeds_task = asyncio.create_task(
            _timed(
                feeds.run_all_feeds(
                    client=client,
                    package=package,
                    ecosystem=ecosystem,
                    from_version=from_version,
                    to_version=to_version,
                    new_dependencies=diff_summary.new_dependencies,
                ) if not no_feeds else _stub_feeds()
            )
        )

        (
            ((dimensions, llm_summary, llm_model), llm_seconds),
            (feed_results, feeds_seconds),
        ) = await asyncio.gather(llm_task, feeds_task)
        analysis_seconds = time.perf_counter() - analysis_started

        timings = PipelineTimings(
            fetch_seconds=round(fetch_seconds, 3),
            diff_seconds=round(diff_seconds, 3),
            llm_seconds=round(llm_seconds, 3),
            feeds_seconds=round(feeds_seconds, 3),
            analysis_seconds=round(analysis_seconds, 3),
            total_seconds=round(time.perf_counter() - started, 3),
        )

        # ── Stage 4: Aggregate ────────────────────────────────────────────────
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
            timings=timings,
        )


def _get_version() -> str:
    """Return the package version string."""
    try:
        from importlib.metadata import version
        return version("chainwatch")
    except Exception:
        return "0.2.0"
