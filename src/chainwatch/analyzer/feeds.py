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
  - npm packages only. Reads the registry's Sigstore provenance-attestation
    bundle — GET {npm_registry}/-/npm/v1/attestations/{package}@{version} —
    and parses the Fulcio-issued signing certificate to recover the identity
    that published the release (typically a GitHub Actions workflow ref).
  - Compares the from_version identity against the to_version identity: a
    changed identity is a maintainer-hijack / stolen-token signal, flagged
    FeedStatus.suspicious. No attestation on either side (packages predating
    npm provenance, or PyPI — PEP 740 support not implemented) = no_data.
  - This reads the identity the certificate *asserts*; it does not perform
    full Sigstore bundle verification (Rekor inclusion proof, Fulcio chain
    trust, cert validity window). Treat it as a detection heuristic, not a
    cryptographic guarantee.

Scorecard client:
  - GET api.securityscorecards.dev/projects/github.com/{owner}/{repo}
  - Requires mapping package name → GitHub repo via registry metadata
  - Extract: overall score and key checks
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import logging
from typing import Any
from urllib.parse import quote

import httpx
from cryptography import x509

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
) -> list[FeedResult]:
    """
    Run all three feed clients concurrently and return their results.

    Uses ``asyncio.gather()`` with ``return_exceptions=True`` so a feed
    crash doesn't propagate — it becomes a ``no_data`` result.

    Args:
        client:             Shared httpx.AsyncClient
        package:            Package name
        ecosystem:          npm or pypi
        from_version:       Baseline version (compared against to_version for
                             the Rekor signing-identity check)
        to_version:         Target version

    Returns:
        List of three FeedResult objects: [osv, rekor, scorecard]
    """
    results = await asyncio.gather(
        _query_osv(client, package, ecosystem, to_version),
        _query_rekor(client, package, ecosystem, from_version, to_version),
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
    ecosystem: Ecosystem,
    from_version: str,
    to_version: str,
) -> FeedResult:
    """
    Compare Sigstore signing identities between from_version and to_version.

    npm-only for now: packages published with ``npm publish --provenance``
    (npm 9.5+, 2023) carry a Sigstore bundle at the registry's attestations
    endpoint. The bundle's Fulcio certificate records *who* published the
    release — typically a GitHub Actions workflow ref (e.g.
    ``https://github.com/{owner}/{repo}/.github/workflows/release.yml@refs/heads/main``).
    A release published from a different identity than its predecessor is a
    maintainer-hijack / stolen-token signal — exactly the pattern behind the
    event-stream and ua-parser-js incidents this tool's corpus is built on.

    PyPI attestations (PEP 740) are served over the Simple API, not a JSON
    endpoint, and are not implemented here — this returns ``no_data`` for
    PyPI rather than guessing at an unimplemented protocol.

    Packages that predate provenance (essentially anything published before
    2023) will legitimately have no attestation on either side and report
    ``no_data`` — that is a correct "we cannot tell" result, not a bug.
    """
    if ecosystem != Ecosystem.npm:
        return FeedResult(
            source="rekor",
            status=FeedStatus.no_data,
            details=(
                "Sigstore attestation lookup is npm-only "
                "(PyPI PEP 740 support not implemented)."
            ),
        )

    log.debug("Rekor: comparing signing identity for %s %s → %s", package, from_version, to_version)
    settings = get_settings()

    try:
        from_identity, _ = await _fetch_npm_signing_identity(
            client, settings, package, from_version
        )
        to_identity, to_url = await _fetch_npm_signing_identity(
            client, settings, package, to_version
        )
    except Exception as exc:
        log.warning("Rekor/npm attestation query failed: %s", exc)
        return FeedResult(
            source="rekor",
            status=FeedStatus.no_data,
            details=f"Attestation lookup failed: {exc}",
        )

    if to_identity is None:
        return FeedResult(
            source="rekor",
            status=FeedStatus.no_data,
            details=f"No Sigstore provenance attestation found for {package}@{to_version}.",
        )

    if from_identity is None:
        return FeedResult(
            source="rekor",
            status=FeedStatus.clean,
            details=(
                f"Signing identity: {to_identity}. "
                f"No attestation for {package}@{from_version} to compare against."
            ),
            url=to_url,
            signing_identity=to_identity,
            signing_identity_changed=None,
        )

    changed = from_identity != to_identity
    details = f"Signing identity: {to_identity}."
    details += f" Changed from {from_identity}." if changed else " Matches previous release."

    return FeedResult(
        source="rekor",
        status=FeedStatus.suspicious if changed else FeedStatus.clean,
        details=details,
        url=to_url,
        signing_identity=to_identity,
        signing_identity_changed=changed,
    )


async def _fetch_npm_signing_identity(
    client: httpx.AsyncClient,
    settings: Any,
    package: str,
    version: str,
) -> tuple[str | None, str | None]:
    """
    Fetch and parse the Sigstore signing identity for one npm package version.

    Returns (identity, human_url), both None if no attestation exists.
    """
    url = f"{settings.npm_registry}/-/npm/v1/attestations/{quote(package, safe='@')}@{version}"
    try:
        resp = await _get_with_retry(client, url)
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 404:
            return None, None
        raise

    data: dict[str, Any] = resp.json()
    attestations: list[dict[str, Any]] = data.get("attestations") or []

    # Prefer the SLSA provenance attestation; fall back to whichever one has
    # a certificate (the npm publish attestation carries the same cert).
    attestations.sort(key=lambda a: "slsa.dev/provenance" not in a.get("predicateType", ""))

    for attestation in attestations:
        cert_der = _attestation_certificate_der(attestation)
        if cert_der is None:
            continue
        identity = _identity_from_certificate(cert_der)
        if identity is None:
            continue
        human_url = _rekor_search_url(attestation) or (
            f"https://www.npmjs.com/package/{package}/v/{version}#provenance"
        )
        return identity, human_url

    return None, None


def _attestation_certificate_der(attestation: dict[str, Any]) -> bytes | None:
    """Extract the raw DER bytes of the Fulcio signing certificate, if present."""
    try:
        raw_b64 = attestation["bundle"]["verificationMaterial"]["certificate"]["rawBytes"]
        return base64.b64decode(raw_b64)
    except (KeyError, TypeError, binascii.Error):
        return None


def _identity_from_certificate(cert_der: bytes) -> str | None:
    """
    Parse a Fulcio-issued X.509 certificate and return its signing identity.

    Fulcio certificates encode the verified OIDC identity as a Subject
    Alternative Name — a URI (CI/CD workflow identities, e.g. GitHub Actions)
    or an RFC822 email (interactive `npm login` identities). This reads the
    identity the certificate *asserts*; it does not verify the certificate
    chain, validity window, or Rekor inclusion proof.
    """
    try:
        cert = x509.load_der_x509_certificate(cert_der)
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except (ValueError, x509.ExtensionNotFound):
        return None

    uris = san.get_values_for_type(x509.UniformResourceIdentifier)
    if uris:
        return uris[0]
    emails = san.get_values_for_type(x509.RFC822Name)
    if emails:
        return emails[0]
    return None


def _rekor_search_url(attestation: dict[str, Any]) -> str | None:
    """Build a human-viewable search.sigstore.dev link from the bundle's tlog entry."""
    try:
        log_index = attestation["bundle"]["verificationMaterial"]["tlogEntries"][0]["logIndex"]
        return f"https://search.sigstore.dev/?logIndex={log_index}"
    except (KeyError, IndexError, TypeError):
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
