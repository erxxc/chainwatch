"""
chainwatch.scanner
~~~~~~~~~~~~~~~~~~~

Orchestrates ``chainwatch scan``: for every dependency a lockfile pins,
find the version published immediately before it, and run the diff
pipeline against that pair.

"Immediately before" — not "the latest release" or "the last major line" —
is the deliberate semantic. It answers: *was the specific bump that put
this exact version in the lockfile itself suspicious?* A single lockfile
has no "before" state of its own to diff against; the version published
right before the locked one is the only baseline chainwatch can derive
without a second lockfile to compare against. This is exactly the scenario
that would have caught event-stream/ua-parser-js/node-ipc-style attacks:
diffing the version you just pulled in against the one it replaced.

One package failing (not found, no earlier version, network error, LLM
error, ...) must not abort the whole scan — the same graceful-degradation
principle already used throughout the feed clients (``analyzer/feeds.py``)
applies here: collect a ``ScanEntry`` with ``error`` set and move on to the
next package.

Concurrency: dependencies are diffed with bounded concurrency
(``settings.max_concurrent_scan_deps``, default 3), not fully sequential
and not fully parallel. An earlier version of this module ran strictly
one dependency at a time specifically to avoid firing many LLM calls at
once with no visible warning; that concern is real, but "one at a time"
and "unbounded" were never the only two options. A small, fixed cap keeps
the same predictability (a scan never fans out further than the cap,
regardless of lockfile size) while still cutting wall-clock time roughly
by that cap's factor — meaningful for the default ``--limit 25``, where
strictly sequential scanning means every dependency's full pipeline
(registry fetch + diff + LLM + feeds) waits on the previous one's,
compounding on top of ``analyze_diff``'s own per-chunk latency.
"""

from __future__ import annotations

import asyncio
import logging

import httpx

from chainwatch.config import get_settings
from chainwatch.lockfile import LockedDependency
from chainwatch.models import Ecosystem, ScanEntry
from chainwatch.pipeline import run_diff_pipeline

log = logging.getLogger(__name__)


async def find_previous_version(
    client: httpx.AsyncClient,
    ecosystem: Ecosystem,
    package: str,
    current_version: str,
) -> str | None:
    """
    Return the version published immediately before ``current_version``.

    Returns None if ``current_version`` is the package's first-ever release
    (nothing published before it to diff against) or isn't found in the
    registry's history at all (e.g. it was itself later unpublished).
    """
    from chainwatch.fetcher import npm, pypi

    if ecosystem == Ecosystem.npm:
        history = await npm.fetch_version_history(client, package)
    else:
        history = await pypi.fetch_version_history(client, package)

    if current_version not in history:
        return None
    index = history.index(current_version)
    if index == 0:
        return None
    return history[index - 1]


async def _scan_one(
    client: httpx.AsyncClient,
    ecosystem: Ecosystem,
    dep: LockedDependency,
    *,
    no_feeds: bool,
    strip_comments: bool = False,
) -> ScanEntry:
    """Diff a single dependency's locked version against its predecessor.

    Isolated into its own function (rather than inlined in a loop body) so
    scan_dependencies can run many of these concurrently via asyncio.gather
    while each one's error handling stays exactly as self-contained as it
    was in the old sequential for-loop -- one dependency's exception can't
    leak into another's result either way.
    """
    log.info("scan: %s@%s", dep.name, dep.version)

    try:
        previous = await find_previous_version(client, ecosystem, dep.name, dep.version)
    except Exception as exc:
        log.warning("scan: could not fetch version history for %s: %s", dep.name, exc)
        return ScanEntry(
            package=dep.name,
            to_version=dep.version,
            error=f"Could not fetch version history: {exc}",
        )

    if previous is None:
        return ScanEntry(
            package=dep.name,
            to_version=dep.version,
            error=(
                "No earlier published version to diff against "
                "(first release, or version not found in registry history)"
            ),
        )

    try:
        report = await run_diff_pipeline(
            client, ecosystem, dep.name, previous, dep.version, no_feeds,
            strip_comments=strip_comments,
        )
    except Exception as exc:
        log.warning(
            "scan: diff failed for %s %s→%s: %s", dep.name, previous, dep.version, exc
        )
        return ScanEntry(
            package=dep.name,
            from_version=previous,
            to_version=dep.version,
            error=str(exc),
        )

    return ScanEntry(
        package=dep.name,
        from_version=previous,
        to_version=dep.version,
        report=report,
    )


async def scan_dependencies(
    client: httpx.AsyncClient,
    ecosystem: Ecosystem,
    dependencies: list[LockedDependency],
    *,
    no_feeds: bool,
    strip_comments: bool = False,
) -> list[ScanEntry]:
    """
    Diff every dependency's locked version against its immediate predecessor.

    Runs with bounded concurrency (``settings.max_concurrent_scan_deps``,
    default 3) — not fully sequential, not fully parallel. Firing every
    dependency's LLM call at once would risk tripping Anthropic API rate
    limits and running up cost with no visible warning; a fixed, small cap
    keeps a scan's fan-out predictable regardless of lockfile size while
    still meaningfully cutting wall-clock time for the common case. See
    the module docstring for the full reasoning.

    Args:
        client:       Shared httpx.AsyncClient — reused across every
                      dependency so the scan benefits from one connection
                      pool instead of reconnecting per package.
        ecosystem:    npm or pypi (the whole lockfile is one ecosystem)
        dependencies: Parsed lockfile entries (see chainwatch.lockfile)
        no_feeds:     Passed straight through to the diff pipeline
        strip_comments: Passed straight through to the diff pipeline

    Returns:
        One ScanEntry per dependency, in the same order given — preserved
        under concurrency because asyncio.gather() returns results in
        input order regardless of completion order, not the order tasks
        happen to finish in.
    """
    settings = get_settings()
    semaphore = asyncio.Semaphore(settings.max_concurrent_scan_deps)

    async def _bounded(dep: LockedDependency) -> ScanEntry:
        async with semaphore:
            return await _scan_one(
                client, ecosystem, dep, no_feeds=no_feeds, strip_comments=strip_comments,
            )

    return list(await asyncio.gather(*(_bounded(dep) for dep in dependencies)))
