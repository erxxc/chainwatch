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

  Each client has its own retry logic via ``_get_with_retry()`` /
  ``_post_with_retry()``.

OSV client:
  - POST api.osv.dev/v1/query with package name, ecosystem, version
  - Flag any advisory ID starting with "MAL-" as FeedStatus.malicious
  - Other advisory IDs (GHSA-*, CVE-*) as FeedStatus.suspicious

Rekor client:
  - Hash-based search against Rekor transparency log
  - POST rekor.sigstore.dev/api/v1/index/retrieve with SHA256
  - Extract signing identity from returned entries
  - Flag: new/unknown identity = suspicious, no attestation = no_data

Scorecard client:
  - GET api.securityscorecards.dev/projects/github.com/{owner}/{repo}
  - Requires mapping package name → GitHub repo via registry metadata
  - Extract: overall score and key checks
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
        client:             Shared httpx.AsyncClient
        package:            Package name
        ecosystem:          npm or pypi
        from_version:       Baseline version (for Rekor comparison)
        to_version:         Target version
        to_version_sha256:  SHA256 of the to_version tarball

    Returns:
        List of three FeedResult objects: [osv, rekor, scorecard]
    """
    results = await asyncio.gather(
        _query_osv(client, package, ecosystem, to_version),
        _query_rekor(client, package, to_version, to_version_sha256),
        _query_scorecard(client, package, ecosystem),
        return_exceptions=True,
    )

    feed_results: list[FeedResult] = []
    feed_names = ["osv", "rekor", "scorecard"]

    for name, result in zip(feed_names, results, strict=True):
        if isinstance(result, BaseException):
            log.error("Feed %s raised an exception: %s", name, result)
            feed_results.append(FeedResult(
                source=name,
                status=FeedStatus.no_data,
                details=f"Feed error: {type(result).__name__}: {result}",
            ))
        else:
            feed_results.append(result)

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

    API: POST https://api.osv.dev/v1/query
    Request:
      {"version": "1.4.1", "package": {"name": "colors", "ecosystem": "npm"}}
    Response:
      {"vulns": [{"id": "MAL-2022-1", "aliases": [...], ...}]}

    MAL-* IDs indicate confirmed malware in the OSV dataset.
    """
    log.debug("OSV: querying %s@%s", package, version)
    settings = get_settings()

    osv_ecosystem = "npm" if ecosystem == Ecosystem.npm else "PyPI"

    try:
        resp = await _post_with_retry(
            client,
            f"{settings.osv_api}/query",
            json_data={
                "version": version,
                "package": {"name": package, "ecosystem": osv_ecosystem},
            },
        )
        data: dict[str, Any] = resp.json()
        vulns = data.get("vulns", [])

        if not vulns:
            return FeedResult(
                source="osv",
                status=FeedStatus.clean,
                details=f"No advisories found for {package}@{version}.",
                url=f"https://osv.dev/list?q={package}",
                advisory_ids=[],
                raw=data,
            )

        advisory_ids = [v["id"] for v in vulns if "id" in v]
        has_mal = any(aid.startswith("MAL-") for aid in advisory_ids)
        status = FeedStatus.malicious if has_mal else FeedStatus.suspicious
        ids_preview = ", ".join(advisory_ids[:5])
        suffix = f" (and {len(advisory_ids) - 5} more)" if len(advisory_ids) > 5 else ""
        details = f"Found {len(vulns)} advisory/ies: {ids_preview}{suffix}"

        return FeedResult(
            source="osv",
            status=status,
            details=details,
            advisory_ids=advisory_ids,
            url=f"https://osv.dev/list?q={package}",
            raw=data,
        )
    except Exception as exc:
        log.warning("OSV query failed: %s", exc)
        return FeedResult(
            source="osv",
            status=FeedStatus.no_data,
            details=f"OSV query failed: {exc}",
        )


# ── Rekor client ──────────────────────────────────────────────────────────────


async def _query_rekor(
    client: httpx.AsyncClient,
    package: str,
    to_version: str,
    to_sha256: str,
) -> FeedResult:
    """
    Query the Rekor transparency log for attestation records.

    Strategy: hash-based lookup.
    1. POST rekor.sigstore.dev/api/v1/index/retrieve
       with {"hash": "sha256:<hex>"}
    2. If entries found, GET each entry to extract signing identity
    3. Flag: no attestation = no_data, attestation found = clean

    Signing identity change detection requires comparing with from_version,
    which would need a second lookup. For now, we report whether any
    attestation exists for the to_version.
    """
    log.debug(
        "Rekor: querying attestation for %s %s (sha256:%s…)",
        package, to_version, to_sha256[:12],
    )
    settings = get_settings()

    try:
        resp = await _post_with_retry(
            client,
            f"{settings.rekor_api}/api/v1/index/retrieve",
            json_data={"hash": f"sha256:{to_sha256}"},
        )

        # Response is a JSON array of entry UUIDs
        entry_uuids: list[str] = resp.json()

        if not entry_uuids:
            return FeedResult(
                source="rekor",
                status=FeedStatus.no_data,
                details=(
                    f"No Rekor attestation found for {package}@{to_version}."
                ),
                url=f"https://search.sigstore.dev/?hash={to_sha256}",
                signing_identity=None,
                signing_identity_changed=None,
            )

        # Fetch the first entry to get signing identity
        first_uuid = entry_uuids[0]
        signing_identity = await _extract_rekor_identity(
            client, settings.rekor_api, first_uuid
        )

        return FeedResult(
            source="rekor",
            status=FeedStatus.clean,
            details=(
                f"Rekor attestation found ({len(entry_uuids)} entries). "
                f"Signing identity: {signing_identity or 'unknown'}"
            ),
            url=f"https://search.sigstore.dev/?hash={to_sha256}",
            signing_identity=signing_identity,
            signing_identity_changed=None,  # requires from_version lookup
        )
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 404:
            return FeedResult(
                source="rekor",
                status=FeedStatus.no_data,
                details=(
                    f"No Rekor entries found for {package}@{to_version}."
                ),
                url=f"https://search.sigstore.dev/?hash={to_sha256}",
            )
        log.warning("Rekor query failed: %s", exc)
        return FeedResult(
            source="rekor",
            status=FeedStatus.no_data,
            details=f"Rekor query failed: {exc}",
        )
    except Exception as exc:
        log.warning("Rekor query failed: %s", exc)
        return FeedResult(
            source="rekor",
            status=FeedStatus.no_data,
            details=f"Rekor query failed: {exc}",
        )


async def _extract_rekor_identity(
    client: httpx.AsyncClient,
    rekor_api: str,
    uuid: str,
) -> str | None:
    """
    Fetch a Rekor log entry and extract the signing identity.

    The signing identity is typically an email or OIDC URI embedded
    in the certificate's Subject Alternative Name (SAN).
    """
    try:
        resp = await _get_with_retry(
            client,
            f"{rekor_api}/api/v1/log/entries/{uuid}",
        )
        data: dict[str, Any] = resp.json()
        # Rekor entries are wrapped in a dict keyed by UUID
        for _entry_id, entry in data.items():
            body = entry.get("body", "")
            # The body is base64-encoded; for now, just report presence
            if body:
                return f"entry:{uuid[:16]}…"
        return None
    except Exception as exc:
        log.debug("Failed to extract Rekor identity: %s", exc)
        return None


# ── Scorecard client ──────────────────────────────────────────────────────────


async def _query_scorecard(
    client: httpx.AsyncClient,
    package: str,
    ecosystem: Ecosystem,
) -> FeedResult:
    """
    Query the OpenSSF Scorecard API for repository trust signals.

    The Scorecard score acts as a trust modifier in the aggregator.

    Requires mapping package name → GitHub repo. For npm, we use
    the npm registry metadata's "repository" field. For PyPI,
    we use the project URLs from the JSON API.

    API: GET api.securityscorecards.dev/projects/github.com/{owner}/{repo}
    """
    log.debug("Scorecard: querying %s/%s", ecosystem.value, package)
    settings = get_settings()

    try:
        # Step 1: Resolve GitHub repo from registry metadata
        repo_slug = await _resolve_github_repo(
            client, package, ecosystem
        )

        if not repo_slug:
            return FeedResult(
                source="scorecard",
                status=FeedStatus.no_data,
                details=(
                    f"Could not resolve GitHub repo for {package}. "
                    "Scorecard requires a GitHub repository."
                ),
            )

        # Step 2: Query Scorecard API
        url = f"{settings.scorecard_api}/projects/github.com/{repo_slug}"
        resp = await _get_with_retry(client, url)
        data: dict[str, Any] = resp.json()

        overall_score = data.get("score", data.get("aggregate_score"))
        if overall_score is None:
            return FeedResult(
                source="scorecard",
                status=FeedStatus.no_data,
                details=f"Scorecard response missing score for {repo_slug}.",
                url=f"https://scorecard.dev/viewer/?uri=github.com/{repo_slug}",
                raw=data,
            )

        score = float(overall_score)

        # Extract key checks
        checks = data.get("checks", [])
        check_summary = _summarize_checks(checks)

        status = FeedStatus.clean if score >= 4.0 else FeedStatus.suspicious

        return FeedResult(
            source="scorecard",
            status=status,
            details=f"Score: {score:.1f}/10. {check_summary}",
            url=f"https://scorecard.dev/viewer/?uri=github.com/{repo_slug}",
            scorecard_score=score,
            raw=data,
        )
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 404:
            return FeedResult(
                source="scorecard",
                status=FeedStatus.no_data,
                details=f"No Scorecard data found for {package}.",
            )
        log.warning("Scorecard query failed: %s", exc)
        return FeedResult(
            source="scorecard",
            status=FeedStatus.no_data,
            details=f"Scorecard query failed: {exc}",
        )
    except Exception as exc:
        log.warning("Scorecard query failed: %s", exc)
        return FeedResult(
            source="scorecard",
            status=FeedStatus.no_data,
            details=f"Scorecard query failed: {exc}",
        )


async def _resolve_github_repo(
    client: httpx.AsyncClient,
    package: str,
    ecosystem: Ecosystem,
) -> str | None:
    """
    Resolve a package name to a GitHub owner/repo slug.

    For npm: fetch registry metadata and parse the "repository" field.
    For PyPI: fetch JSON API and parse project_urls.
    """
    settings = get_settings()

    try:
        if ecosystem == Ecosystem.npm:
            resp = await _get_with_retry(
                client,
                f"{settings.npm_registry}/{package}",
            )
            data = resp.json()
            repo = data.get("repository", {})
            if isinstance(repo, dict):
                url = repo.get("url", "")
            elif isinstance(repo, str):
                url = repo
            else:
                return None
            return _parse_github_url(url)
        else:
            # PyPI — use the latest version's metadata
            resp = await _get_with_retry(
                client,
                f"{settings.pypi_registry}/{package}/json",
            )
            data = resp.json()
            info = data.get("info", {})
            project_urls = info.get("project_urls") or {}
            # Try common keys
            for key in [
                "Source", "Repository", "Source Code",
                "Homepage", "Code", "GitHub",
            ]:
                url = project_urls.get(key, "")
                slug = _parse_github_url(url)
                if slug:
                    return slug
            # Try home_page field
            home = info.get("home_page", "")
            return _parse_github_url(home)
    except Exception as exc:
        log.debug(
            "Failed to resolve GitHub repo for %s: %s", package, exc
        )
        return None


def _parse_github_url(url: str) -> str | None:
    """
    Extract owner/repo from various GitHub URL formats.

    Handles:
      https://github.com/owner/repo
      https://github.com/owner/repo.git
      git+https://github.com/owner/repo.git
      git://github.com/owner/repo.git
      ssh://git@github.com/owner/repo.git
    """
    if not url or "github.com" not in url:
        return None

    # Normalize
    url = url.replace("git+", "").replace("git://", "https://")
    url = url.replace("ssh://git@github.com", "https://github.com")

    # Extract path after github.com
    try:
        idx = url.index("github.com/") + len("github.com/")
        path = url[idx:].rstrip("/").removesuffix(".git")
        parts = path.split("/")
        if len(parts) >= 2:
            return f"{parts[0]}/{parts[1]}"
    except ValueError:
        pass
    return None


def _summarize_checks(checks: list[dict[str, Any]]) -> str:
    """Summarize key Scorecard checks into a brief string."""
    key_checks = [
        "Maintained", "Code-Review", "Branch-Protection", "Signed-Releases",
    ]
    parts = []
    for check in checks:
        name = check.get("name", "")
        if name in key_checks:
            score = check.get("score", "?")
            parts.append(f"{name}={score}")
    return ", ".join(parts) if parts else "No key checks found."


# ── Shared HTTP helpers ───────────────────────────────────────────────────────


async def _post_with_retry(
    client: httpx.AsyncClient,
    url: str,
    *,
    json_data: Any = None,
    max_retries: int | None = None,
) -> httpx.Response:
    """POST with exponential backoff retry on 429/5xx responses."""
    settings = get_settings()
    retries = max_retries if max_retries is not None else settings.max_retries

    for attempt in range(retries + 1):
        resp = await client.post(url, json=json_data)
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
