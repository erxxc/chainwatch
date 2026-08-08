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
"""

from __future__ import annotations

import logging

import httpx

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


async def scan_dependencies(
    client: httpx.AsyncClient,
    ecosystem: Ecosystem,
    dependencies: list[LockedDependency],
    *,
    no_feeds: bool,
) -> list[ScanEntry]:
    """
    Diff every dependency's locked version against its immediate predecessor.

    Runs sequentially, not concurrently. Each entry makes a real LLM call;
    firing many at once risks tripping Anthropic API rate limits and
    running up cost with no visible warning. A CI scan of a lockfile's
    worth of dependencies taking a few minutes is an acceptable trade for
    that predictability — see the module docstring for why this can't be
    trivially parallelised away without that risk.

    Args:
        client:       Shared httpx.AsyncClient — reused across every
                      dependency so the scan benefits from one connection
                      pool instead of reconnecting per package.
        ecosystem:    npm or pypi (the whole lockfile is one ecosystem)
        dependencies: Parsed lockfile entries (see chainwatch.lockfile)
        no_feeds:     Passed straight through to the diff pipeline

    Returns:
        One ScanEntry per dependency, in the same order given.
    """
    entries: list[ScanEntry] = []

    for dep in dependencies:
        log.info("scan: %s@%s", dep.name, dep.version)

        try:
            previous = await find_previous_version(client, ecosystem, dep.name, dep.version)
        except Exception as exc:
            log.warning("scan: could not fetch version history for %s: %s", dep.name, exc)
            entries.append(ScanEntry(
                package=dep.name,
                to_version=dep.version,
                error=f"Could not fetch version history: {exc}",
            ))
            continue

        if previous is None:
            entries.append(ScanEntry(
                package=dep.name,
                to_version=dep.version,
                error=(
                    "No earlier published version to diff against "
                    "(first release, or version not found in registry history)"
                ),
            ))
            continue

        try:
            report = await run_diff_pipeline(
                client, ecosystem, dep.name, previous, dep.version, no_feeds,
            )
        except Exception as exc:
            log.warning(
                "scan: diff failed for %s %s→%s: %s", dep.name, previous, dep.version, exc
            )
            entries.append(ScanEntry(
                package=dep.name,
                from_version=previous,
                to_version=dep.version,
                error=str(exc),
            ))
            continue

        entries.append(ScanEntry(
            package=dep.name,
            from_version=previous,
            to_version=dep.version,
            report=report,
        ))

    return entries
