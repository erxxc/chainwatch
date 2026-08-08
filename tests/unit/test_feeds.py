"""
Unit tests for chainwatch.analyzer.feeds

All tests use respx to mock HTTP — no real API calls.
"""

from __future__ import annotations

import base64
import datetime

import httpx
import pytest
import respx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from chainwatch.analyzer.feeds import (
    _attestation_certificate_der,
    _identity_from_certificate,
    _parse_github_url,
    _query_osv,
    _query_rekor,
    _query_scorecard,
    _rekor_search_url,
    run_all_feeds,
)
from chainwatch.config import get_settings
from chainwatch.models import Ecosystem, FeedStatus


@pytest.fixture(autouse=True)
def _reset_settings(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-fake")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def _make_fulcio_style_cert_der(*, uri: str | None = None, email: str | None = None) -> bytes:
    """
    Build a minimal self-signed cert carrying a URI or RFC822 SAN, mirroring
    the shape of a real Fulcio-issued Sigstore signing certificate closely
    enough to exercise the parsing path in ``_identity_from_certificate``.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name([])
    san_values: list[x509.GeneralName] = []
    if uri:
        san_values.append(x509.UniformResourceIdentifier(uri))
    if email:
        san_values.append(x509.RFC822Name(email))
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(minutes=5))
        .add_extension(x509.SubjectAlternativeName(san_values), critical=False)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(encoding=serialization.Encoding.DER)


def _make_attestation_response(*, identity_uri: str, log_index: int = 12345) -> dict:
    """Build a fake npm registry attestations response with a real parseable cert."""
    cert_der = _make_fulcio_style_cert_der(uri=identity_uri)
    return {
        "attestations": [
            {
                "predicateType": "https://slsa.dev/provenance/v1",
                "bundle": {
                    "verificationMaterial": {
                        "certificate": {"rawBytes": base64.b64encode(cert_der).decode()},
                        "tlogEntries": [{"logIndex": str(log_index)}],
                    },
                },
            }
        ]
    }


# ── OSV tests ─────────────────────────────────────────────────────────────────


class TestOsv:
    @respx.mock
    async def test_osv_clean_when_no_vulns(self):
        respx.post("https://api.osv.dev/v1/query").respond(json={"vulns": []})
        async with httpx.AsyncClient() as client:
            result = await _query_osv(client, "lodash", Ecosystem.npm, "4.17.21")
        assert result.status == FeedStatus.clean
        assert result.source == "osv"
        assert result.advisory_ids == []

    @respx.mock
    async def test_osv_malicious_when_mal_advisory(self):
        respx.post("https://api.osv.dev/v1/query").respond(
            json={
                "vulns": [
                    {"id": "MAL-2018-1", "summary": "Malicious package"},
                    {"id": "GHSA-1234-abcd", "summary": "Some vuln"},
                ]
            }
        )
        async with httpx.AsyncClient() as client:
            result = await _query_osv(client, "event-stream", Ecosystem.npm, "3.3.5")
        assert result.status == FeedStatus.malicious
        assert "MAL-2018-1" in result.advisory_ids
        assert "GHSA-1234-abcd" in result.advisory_ids

    @respx.mock
    async def test_osv_suspicious_when_ghsa_only(self):
        respx.post("https://api.osv.dev/v1/query").respond(
            json={
                "vulns": [
                    {"id": "GHSA-abcd-1234-efgh", "summary": "XSS vuln"},
                ]
            }
        )
        async with httpx.AsyncClient() as client:
            result = await _query_osv(client, "some-pkg", Ecosystem.npm, "1.0.0")
        assert result.status == FeedStatus.suspicious
        assert "GHSA-abcd-1234-efgh" in result.advisory_ids

    @respx.mock
    async def test_osv_no_data_on_network_error(self):
        respx.post("https://api.osv.dev/v1/query").mock(
            side_effect=httpx.ConnectError("Connection refused")
        )
        async with httpx.AsyncClient() as client:
            result = await _query_osv(client, "lodash", Ecosystem.npm, "4.17.21")
        assert result.status == FeedStatus.no_data
        assert "failed" in result.details.lower() or "error" in result.details.lower()

    @respx.mock
    async def test_osv_uses_pypi_ecosystem_string(self):
        route = respx.post("https://api.osv.dev/v1/query").respond(json={"vulns": []})
        async with httpx.AsyncClient() as client:
            await _query_osv(client, "requests", Ecosystem.pypi, "2.31.0")
        # Verify the request body used "PyPI" (not "pypi")
        request = route.calls.last.request
        import json
        body = json.loads(request.content)
        assert body["package"]["ecosystem"] == "PyPI"


# ── Rekor tests ───────────────────────────────────────────────────────────────


class TestRekor:
    @respx.mock
    async def test_rekor_no_data_when_neither_version_attested(self):
        respx.get(url__regex=r".*/-/npm/v1/attestations/.*").respond(status_code=404)
        async with httpx.AsyncClient() as client:
            result = await _query_rekor(client, "lodash", Ecosystem.npm, "4.17.20", "4.17.21")
        assert result.status == FeedStatus.no_data
        assert result.signing_identity is None
        assert result.signing_identity_changed is None

    @respx.mock
    async def test_rekor_clean_when_identity_unchanged(self):
        identity = "https://github.com/lodash/lodash/.github/workflows/release.yml@refs/heads/main"
        body = _make_attestation_response(identity_uri=identity)
        respx.get(url__regex=r".*/-/npm/v1/attestations/.*4\.17\.20$").respond(json=body)
        respx.get(url__regex=r".*/-/npm/v1/attestations/.*4\.17\.21$").respond(json=body)
        async with httpx.AsyncClient() as client:
            result = await _query_rekor(client, "lodash", Ecosystem.npm, "4.17.20", "4.17.21")
        assert result.status == FeedStatus.clean
        assert result.signing_identity == identity
        assert result.signing_identity_changed is False

    @respx.mock
    async def test_rekor_suspicious_when_identity_changed(self):
        from_body = _make_attestation_response(
            identity_uri="https://github.com/original-maintainer/pkg/.github/workflows/release.yml@refs/heads/main"
        )
        to_body = _make_attestation_response(
            identity_uri="https://github.com/attacker/pkg/.github/workflows/release.yml@refs/heads/main"
        )
        respx.get(url__regex=r".*/-/npm/v1/attestations/.*event-stream@3\.3\.5$").respond(
            json=from_body
        )
        respx.get(url__regex=r".*/-/npm/v1/attestations/.*event-stream@3\.3\.6$").respond(
            json=to_body
        )
        async with httpx.AsyncClient() as client:
            result = await _query_rekor(client, "event-stream", Ecosystem.npm, "3.3.5", "3.3.6")
        assert result.status == FeedStatus.suspicious
        assert result.signing_identity_changed is True
        assert "attacker" in result.signing_identity

    @respx.mock
    async def test_rekor_clean_with_unknown_changed_when_no_previous_attestation(self):
        """to_version is attested but from_version predates provenance — can't compare."""
        to_body = _make_attestation_response(identity_uri="https://github.com/owner/pkg/.github/workflows/release.yml@refs/heads/main")
        respx.get(url__regex=r".*/-/npm/v1/attestations/.*@1\.0\.0$").respond(status_code=404)
        respx.get(url__regex=r".*/-/npm/v1/attestations/.*@2\.0\.0$").respond(json=to_body)
        async with httpx.AsyncClient() as client:
            result = await _query_rekor(client, "pkg", Ecosystem.npm, "1.0.0", "2.0.0")
        assert result.status == FeedStatus.clean
        assert result.signing_identity is not None
        assert result.signing_identity_changed is None

    async def test_rekor_pypi_is_no_data_without_any_request(self):
        """PyPI attestations (PEP 740) aren't implemented — must not guess or call npm's API."""
        async with httpx.AsyncClient() as client:
            result = await _query_rekor(client, "requests", Ecosystem.pypi, "2.31.0", "2.32.0")
        assert result.status == FeedStatus.no_data
        assert "npm-only" in result.details or "PyPI" in result.details

    @respx.mock
    async def test_rekor_no_data_on_non_404_http_error(self):
        """A 5xx from the attestations endpoint should degrade to no_data, not crash."""
        respx.get(url__regex=r".*/-/npm/v1/attestations/.*").respond(status_code=503)
        async with httpx.AsyncClient() as client:
            result = await _query_rekor(client, "lodash", Ecosystem.npm, "4.17.20", "4.17.21")
        assert result.status == FeedStatus.no_data
        assert "failed" in result.details.lower()


# ── Sigstore identity-extraction helper tests ───────────────────────────────────


class TestNpmSigningIdentityHelpers:
    def test_extracts_email_san_when_no_uri_san(self):
        cert_der = _make_fulcio_style_cert_der(email="maintainer@example.com")
        assert _identity_from_certificate(cert_der) == "maintainer@example.com"

    def test_prefers_uri_san_over_email_san(self):
        cert_der = _make_fulcio_style_cert_der(
            uri="https://github.com/owner/repo/.github/workflows/release.yml@refs/heads/main",
            email="maintainer@example.com",
        )
        identity = _identity_from_certificate(cert_der)
        assert identity is not None
        assert identity.startswith("https://github.com/")

    def test_returns_none_for_garbage_der_bytes(self):
        assert _identity_from_certificate(b"not a certificate") is None

    def test_certificate_der_missing_when_attestation_has_no_bundle(self):
        assert _attestation_certificate_der({"predicateType": "x"}) is None

    def test_certificate_der_missing_when_raw_bytes_not_base64(self):
        attestation = {
            "bundle": {"verificationMaterial": {"certificate": {"rawBytes": "!!!not-base64!!!"}}}
        }
        assert _attestation_certificate_der(attestation) is None

    def test_rekor_search_url_none_when_no_tlog_entries(self):
        assert _rekor_search_url({"bundle": {"verificationMaterial": {"tlogEntries": []}}}) is None
        assert _rekor_search_url({}) is None


# ── Scorecard tests ───────────────────────────────────────────────────────────


class TestScorecard:
    @respx.mock
    async def test_scorecard_clean_with_good_score(self):
        # Mock npm registry for repo resolution
        respx.get("https://registry.npmjs.org/lodash").respond(
            json={
                "repository": {
                    "type": "git",
                    "url": "git+https://github.com/lodash/lodash.git",
                }
            }
        )
        # Mock scorecard API
        respx.get(
            "https://api.securityscorecards.dev/projects/github.com/lodash/lodash"
        ).respond(
            json={
                "score": 7.5,
                "checks": [
                    {"name": "Maintained", "score": 10},
                    {"name": "Code-Review", "score": 8},
                ],
            }
        )
        async with httpx.AsyncClient() as client:
            result = await _query_scorecard(client, "lodash", Ecosystem.npm)
        assert result.status == FeedStatus.clean
        assert result.scorecard_score == 7.5
        assert "Maintained=10" in result.details

    @respx.mock
    async def test_scorecard_suspicious_with_low_score(self):
        respx.get("https://registry.npmjs.org/sketchy-pkg").respond(
            json={
                "repository": {
                    "type": "git",
                    "url": "https://github.com/someone/sketchy-pkg.git",
                }
            }
        )
        respx.get(
            "https://api.securityscorecards.dev/projects/github.com/someone/sketchy-pkg"
        ).respond(json={"score": 2.5, "checks": []})
        async with httpx.AsyncClient() as client:
            result = await _query_scorecard(client, "sketchy-pkg", Ecosystem.npm)
        assert result.status == FeedStatus.suspicious
        assert result.scorecard_score == 2.5

    @respx.mock
    async def test_scorecard_no_data_on_404(self):
        respx.get("https://registry.npmjs.org/unknown-pkg").respond(
            json={
                "repository": {
                    "type": "git",
                    "url": "https://github.com/someone/unknown-pkg.git",
                }
            }
        )
        respx.get(
            "https://api.securityscorecards.dev/projects/github.com/someone/unknown-pkg"
        ).respond(status_code=404)
        async with httpx.AsyncClient() as client:
            result = await _query_scorecard(client, "unknown-pkg", Ecosystem.npm)
        assert result.status == FeedStatus.no_data

    @respx.mock
    async def test_scorecard_no_data_when_no_github_repo(self):
        # Package with no repository field
        respx.get("https://registry.npmjs.org/no-repo-pkg").respond(
            json={"name": "no-repo-pkg"}
        )
        async with httpx.AsyncClient() as client:
            result = await _query_scorecard(client, "no-repo-pkg", Ecosystem.npm)
        assert result.status == FeedStatus.no_data
        assert "Could not resolve" in result.details


# ── GitHub URL parser tests ───────────────────────────────────────────────────


class TestParseGithubUrl:
    def test_https_url(self):
        assert _parse_github_url("https://github.com/owner/repo") == "owner/repo"

    def test_https_with_git_suffix(self):
        assert _parse_github_url("https://github.com/owner/repo.git") == "owner/repo"

    def test_git_plus_https(self):
        assert _parse_github_url("git+https://github.com/owner/repo.git") == "owner/repo"

    def test_git_protocol(self):
        assert _parse_github_url("git://github.com/owner/repo.git") == "owner/repo"

    def test_ssh_protocol(self):
        assert _parse_github_url("ssh://git@github.com/owner/repo.git") == "owner/repo"

    def test_empty_string(self):
        assert _parse_github_url("") is None

    def test_non_github_url(self):
        assert _parse_github_url("https://gitlab.com/owner/repo") is None

    def test_trailing_slash(self):
        assert _parse_github_url("https://github.com/owner/repo/") == "owner/repo"


# ── Orchestrator test ─────────────────────────────────────────────────────────


class TestRunAllFeeds:
    @respx.mock
    async def test_run_all_feeds_returns_three_results(self):
        # Mock OSV
        respx.post("https://api.osv.dev/v1/query").respond(json={"vulns": []})
        # Mock Rekor (npm attestations lookup — neither version attested)
        respx.get(url__regex=r".*/-/npm/v1/attestations/.*").respond(status_code=404)
        # Mock npm registry for scorecard repo resolution
        respx.get("https://registry.npmjs.org/lodash").respond(
            json={
                "repository": {
                    "type": "git",
                    "url": "https://github.com/lodash/lodash.git",
                }
            }
        )
        # Mock scorecard API
        respx.get(
            "https://api.securityscorecards.dev/projects/github.com/lodash/lodash"
        ).respond(json={"score": 7.0, "checks": []})

        async with httpx.AsyncClient() as client:
            results = await run_all_feeds(
                client=client,
                package="lodash",
                ecosystem=Ecosystem.npm,
                from_version="4.17.20",
                to_version="4.17.21",
            )
        assert len(results) == 3
        sources = {r.source for r in results}
        assert sources == {"osv", "rekor", "scorecard"}

    @respx.mock
    async def test_run_all_feeds_graceful_on_exception(self):
        """A feed exception should produce no_data, not crash the pipeline."""
        # OSV raises a network error
        respx.post("https://api.osv.dev/v1/query").mock(
            side_effect=httpx.ConnectError("Connection refused")
        )
        # Rekor: npm attestations lookup finds nothing (still succeeds gracefully)
        respx.get(url__regex=r".*/-/npm/v1/attestations/.*").respond(status_code=404)
        # Scorecard: npm registry returns no repo
        respx.get("https://registry.npmjs.org/test-pkg").respond(
            json={"name": "test-pkg"}
        )

        async with httpx.AsyncClient() as client:
            results = await run_all_feeds(
                client=client,
                package="test-pkg",
                ecosystem=Ecosystem.npm,
                from_version="1.0.0",
                to_version="1.0.1",
            )
        # Should still get 3 results, even with the OSV failure
        assert len(results) == 3
        osv_result = next(r for r in results if r.source == "osv")
        assert osv_result.status == FeedStatus.no_data
