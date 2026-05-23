"""
chainwatch.analyzer.feeds
~~~~~~~~~~~~~~~~~~~~~~~~~

Async threat intelligence feed clients.

Three feeds, three clients, one shared interface: each client is an
``async def`` function that takes an ``httpx.AsyncClient`` and package
identifiers, and returns a ``FeedResult``.

Architecture:
  The CLI orchestrates all three feed clients concurrently using
  ``asyncio.gather()``, running in parallel with the LLM call.  A feed
  failure returns ``FeedStatus.no_data`` — it never raises and never
  aborts the pipeline.  This is the "graceful degradation" requirement.

  Each client has its own retry logic via ``_get_with_retry()``.

Stub status: STUB
  All three clients return plausible-looking stub FeedResults.
  The real implementations are outlined in comments below each stub block.

OSV client notes:
  - Query: POST api.osv.dev/v1/query with {"package": {"name": ..., "ecosystem": ...}, "version": ...}
  - Flag any advisory ID starting with "MAL-" as FeedStatus.malicious
  - Other advisory IDs (GHSA-*, CVE-*) as FeedStatus.suspicious

Rekor client notes:
  - Strategy: hash-based search (see design discussion)
  - Compute SHA256 of the to_version tarball
  - POST rekor.sigstore.dev/api/v1/index/retrieve with {"hash": "sha256:<hex>"}
  - Extract signing identity (email/URI) from the returned entry's certificate
  - Compare with signing identity from the from_version entry
  - Flag: new/unknown identity = suspicious, no attestation = no_data

Scorecard client notes:
  - GET api.securityscorecards.dev/projects/github.com/{owner}/{repo}
  - Requires mapping package name → GitHub repo (via registry metadata)
  - Extract: score, Maintained, Code-Review, Branch-Protection, Signed-Releases
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx

from chainwatch.config import get_settings
from chainwatch.models import Ecosystem, FeedResult, FeedStatus

log = logging.getLogger(__name__)


# ── Orchestrator ──────────────────────────────────────────────────────────────


async def run_all_feeds(
    client: httpx.AsyncClient,
    package: str,
    ecosystem: Ecosystem,
    from_version: str,
    to_version: str,
    to_version_sha256: str,
) -> list[FeedResult]:
    """
    Run all three feed clients concurrently and return their results.

    Uses ``asyncio.gather()`` with ``return_exceptions=True`` so a feed
    crash doesn't propagate — it becomes a ``no_data`` result.

    Args:
        client:           Shared httpx.AsyncClient
        package:          Package name
        ecosystem:        npm or pypi
        from_version:     Baseline version (for Rekor signing identity comparison)
        to_version:       Target version
        to_version_sha256: SHA256 of the to_version tarball (for Rekor hash lookup)

    Returns:
        List of three FeedResult objects: [osv, rekor, scorecard]
    """
    results = await asyncio.gather(
        _query_osv(client, package, ecosystem, to_version),
        _query_rekor(client, package, from_version, to_version, to_version_sha256),
        _query_scorecard(client, package, ecosystem),
        return_exceptions=True,
    )

    feed_results: list[FeedResult] = []
    feed_names = ["osv", "rekor", "scorecard"]

    for name, result in zip(feed_names, results):
        if isinstance(result, Exception):
            log.error("Feed %s raised an exception: %s", name, result)
            feed_results.append(FeedResult(
                source=name,
                status=FeedStatus.no_data,
                details=f"Feed error: {type(result).__name__}: {result}",
            ))
        else:
            feed_results.append(result)  # type: ignore[arg-type]

    return feed_results


# ── OSV client ────────────────────────────────────────────────────────────────


async def _query_osv(
    client: httpx.AsyncClient,
    package: str,
    ecosystem: Ecosystem,
    version: str,
) -> FeedResult:
    """
    Query OSV.dev for advisories affecting this package version.

    Real API: POST https://api.osv.dev/v1/query
    Request body:
      {
        "version": "1.4.1",
        "package": {
          "name": "colors",
          "ecosystem": "npm"
        }
      }

    Response:
      { "vulns": [ { "id": "MAL-2022-1", "aliases": [...], ... } ] }

    MAL-* IDs indicate confirmed malware in the OSV dataset.
    """
    log.debug("OSV: querying %s@%s", package, version)

    # ── STUB ──────────────────────────────────────────────────────────────────
    log.warning("OSV feed is STUBBED — returning clean fixture result")
    return FeedResult(
        source="osv",
        status=FeedStatus.clean,
        details=f"[STUB] No advisories found for {package}@{version}.",
        url=f"https://osv.dev/list?q={package}",
        advisory_ids=[],
    )
    # ── END STUB ──────────────────────────────────────────────────────────────

    # ── REAL IMPLEMENTATION ───────────────────────────────────────────────────
    # settings = get_settings()
    # osv_ecosystem = "npm" if ecosystem == Ecosystem.npm else "PyPI"
    # try:
    #     resp = await _post_with_retry(
    #         client,
    #         f"{settings.osv_api}/query",
    #         json={"version": version, "package": {"name": package, "ecosystem": osv_ecosystem}},
    #     )
    #     data = resp.json()
    #     vulns = data.get("vulns", [])
    #     if not vulns:
    #         return FeedResult(source="osv", status=FeedStatus.clean, details="No advisories found.")
    #
    #     advisory_ids = [v["id"] for v in vulns]
    #     has_mal = any(aid.startswith("MAL-") for aid in advisory_ids)
    #     status = FeedStatus.malicious if has_mal else FeedStatus.suspicious
    #     details = f"Found {len(vulns)} advisory/ies: {', '.join(advisory_ids[:5])}"
    #     return FeedResult(
    #         source="osv", status=status, details=details,
    #         advisory_ids=advisory_ids,
    #         url=f"https://osv.dev/list?q={package}",
    #         raw=data,
    #     )
    # except Exception as exc:
    #     log.warning("OSV query failed: %s", exc)
    #     return FeedResult(source="osv", status=FeedStatus.no_data, details=str(exc))


# ── Rekor client ──────────────────────────────────────────────────────────────


async def _query_rekor(
    client: httpx.AsyncClient,
    package: str,
    from_version: str,
    to_version: str,
    to_sha256: str,
) -> FeedResult:
    """
    Query the Rekor transparency log for attestation records.

    Strategy: hash-based lookup.
    1. POST rekor.sigstore.dev/api/v1/index/retrieve with {"hash": "sha256:<hex>"}
       to get entry UUIDs for the to_version tarball.
    2. GET rekor.sigstore.dev/api/v1/log/entries?logIndex=<uuid> for each entry.
    3. Extract the signing identity from the certificate in the entry payload.
    4. Repeat for the from_version tarball to get the historical signing identity.
    5. Compare: if identities differ or to_version has no attestation, flag it.

    Signing identity change is a HIGH signal:
      - The event-stream attack involved a maintainer handoff
      - A new, unknown signer publishing to an established package is suspicious
    """
    log.debug("Rekor: querying attestation for %s %s (sha256:%s...)", package, to_version, to_sha256[:12])

    # ── STUB ──────────────────────────────────────────────────────────────────
    log.warning("Rekor feed is STUBBED — returning no_data fixture result")
    return FeedResult(
        source="rekor",
        status=FeedStatus.no_data,
        details=f"[STUB] No Rekor attestation lookup performed for {package}@{to_version}.",
        url=f"https://search.sigstore.dev/?hash={to_sha256}",
        signing_identity=None,
        signing_identity_changed=None,
    )
    # ── END STUB ──────────────────────────────────────────────────────────────


# ── Scorecard client ──────────────────────────────────────────────────────────


async def _query_scorecard(
    client: httpx.AsyncClient,
    package: str,
    ecosystem: Ecosystem,
) -> FeedResult:
    """
    Query the OpenSSF Scorecard API for repository trust signals.

    The Scorecard score acts as a trust modifier in the aggregator:
    - A well-maintained package (Scorecard > 7) with a suspicious diff warrants
      more investigation than a poorly maintained one, because it's anomalous.
    - A poorly maintained package (Scorecard < 4) with suspicious patterns is
      more consistent with compromise or abandonment.

    Key checks we extract:
      - Maintained (0/1 — was there a commit in the last 90 days?)
      - Code-Review (0-10 — are PRs reviewed before merge?)
      - Branch-Protection (0-10 — is the main branch protected?)
      - Signed-Releases (0-10 — are releases signed?)

    Limitation: this requires mapping package name → GitHub repo owner/name.
    For npm packages, this is available in the registry metadata ("repository"
    field in package.json).  For PyPI, it's in the project URLs.
    """
    log.debug("Scorecard: querying %s/%s", ecosystem.value, package)

    # ── STUB ──────────────────────────────────────────────────────────────────
    log.warning("Scorecard feed is STUBBED — returning no_data fixture result")
    return FeedResult(
        source="scorecard",
        status=FeedStatus.no_data,
        details=f"[STUB] Scorecard lookup not yet implemented for {package}.",
        url=f"https://scorecard.dev/viewer/?uri=github.com/npm/{package}",
        scorecard_score=None,
    )
    # ── END STUB ──────────────────────────────────────────────────────────────


# ── Shared HTTP helpers ───────────────────────────────────────────────────────


async def _post_with_retry(
    client: httpx.AsyncClient,
    url: str,
    *,
    json: Any = None,
    max_retries: int | None = None,
) -> httpx.Response:
    """POST with exponential backoff retry on 429/5xx responses."""
    settings = get_settings()
    retries = max_retries if max_retries is not None else settings.max_retries

    for attempt in range(retries + 1):
        resp = await client.post(url, json=json)
        if resp.status_code == 429 and attempt < retries:
            wait = 2 ** attempt
            log.warning("Rate limited by %s — retrying in %ds", url, wait)
            await asyncio.sleep(wait)
            continue
        resp.raise_for_status()
        return resp

    raise RuntimeError(f"Exhausted retries for POST {url}")


async def _get_with_retry(
    client: httpx.AsyncClient,
    url: str,
    max_retries: int | None = None,
) -> httpx.Response:
    """GET with exponential backoff retry on 429/5xx responses."""
    settings = get_settings()
    retries = max_retries if max_retries is not None else settings.max_retries

    for attempt in range(retries + 1):
        resp = await client.get(url)
        if resp.status_code == 429 and attempt < retries:
            wait = 2 ** attempt
            log.warning("Rate limited by %s — retrying in %ds", url, wait)
            await asyncio.sleep(wait)
            continue
        resp.raise_for_status()
        return resp

    raise RuntimeError(f"Exhausted retries for GET {url}")
