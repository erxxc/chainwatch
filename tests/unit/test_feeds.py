"""
Unit tests for chainwatch.analyzer.feeds

All tests use respx to mock HTTP — no real API calls.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from chainwatch.analyzer.feeds import (
    _parse_github_url,
    _query_osv,
    _query_rekor,
    _query_scorecard,
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
    async def test_rekor_no_data_when_no_entries(self):
        respx.post("https://rekor.sigstore.dev/api/v1/index/retrieve").respond(json=[])
        async with httpx.AsyncClient() as client:
            result = await _query_rekor(client, "lodash", "4.17.21", "abc123" * 8)
        assert result.status == FeedStatus.no_data
        assert result.signing_identity is None

    @respx.mock
    async def test_rekor_clean_when_entries_found(self):
        test_uuid = "abc123def456" * 4
        respx.post("https://rekor.sigstore.dev/api/v1/index/retrieve").respond(
            json=[test_uuid]
        )
        respx.get(
            f"https://rekor.sigstore.dev/api/v1/log/entries/{test_uuid}"
        ).respond(
            json={test_uuid: {"body": "c29tZWJvZHk=", "logIndex": 12345}}
        )
        async with httpx.AsyncClient() as client:
            result = await _query_rekor(client, "lodash", "4.17.21", "abc123" * 8)
        assert result.status == FeedStatus.clean
        assert result.signing_identity is not None

    @respx.mock
    async def test_rekor_no_data_on_404(self):
        respx.post("https://rekor.sigstore.dev/api/v1/index/retrieve").respond(
            status_code=404
        )
        async with httpx.AsyncClient() as client:
            result = await _query_rekor(client, "lodash", "4.17.21", "abc123" * 8)
        assert result.status == FeedStatus.no_data


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
        # Mock Rekor
        respx.post("https://rekor.sigstore.dev/api/v1/index/retrieve").respond(json=[])
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
                to_version_sha256="abc123" * 8,
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
        # Rekor works fine
        respx.post("https://rekor.sigstore.dev/api/v1/index/retrieve").respond(json=[])
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
                to_version_sha256="abc123" * 8,
            )
        # Should still get 3 results, even with the OSV failure
        assert len(results) == 3
        osv_result = next(r for r in results if r.source == "osv")
        assert osv_result.status == FeedStatus.no_data
