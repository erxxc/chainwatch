"""
Unit tests for chainwatch.scanner

Network-free via httpx.MockTransport. LLM calls go through stub mode
(ANTHROPIC_API_KEY starting with sk-ant-test). Feeds are skipped via
no_feeds=True so these tests don't need to mock OSV/Rekor/Scorecard too —
that combination is already covered by the feeds and llm test suites.
"""

from __future__ import annotations

import json
from collections.abc import Iterator

import httpx
import pytest

from chainwatch.config import get_settings
from chainwatch.lockfile import LockedDependency
from chainwatch.models import Ecosystem
from chainwatch.scanner import find_previous_version, scan_dependencies
from tests.fixtures.npm_registry import npm_integrity, npm_tgz


@pytest.fixture(autouse=True)
def _settings(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-fake-key-for-ci")
    monkeypatch.setenv("CHAINWATCH_NPM_REGISTRY", "https://registry.test")
    monkeypatch.setenv("CHAINWATCH_PYPI_REGISTRY", "https://pypi.test")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


# ── find_previous_version ────────────────────────────────────────────────────────


class TestFindPreviousVersionNpm:
    @pytest.mark.asyncio
    async def test_picks_by_publish_time_not_semver_order(self):
        # 1.0.0 published *after* 2.0.0-ish-looking 0.9.0 line — deliberately
        # out of semver order to prove time, not string/semver sort, decides.
        metadata = {
            "versions": {"0.9.0": {}, "1.0.0": {}, "1.1.0": {}},
            "time": {
                "0.9.0": "2020-01-01T00:00:00.000Z",
                "1.1.0": "2020-01-02T00:00:00.000Z",  # published before 1.0.0!
                "1.0.0": "2020-01-03T00:00:00.000Z",
            },
        }

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=metadata)

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            previous = await find_previous_version(client, Ecosystem.npm, "pkg", "1.0.0")

        assert previous == "1.1.0"  # published immediately before 1.0.0 by time

    @pytest.mark.asyncio
    async def test_none_for_first_ever_version(self):
        metadata = {
            "versions": {"1.0.0": {}},
            "time": {"1.0.0": "2020-01-01T00:00:00.000Z"},
        }

        async def _handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=metadata)

        async with httpx.AsyncClient(transport=httpx.MockTransport(_handler)) as client:
            previous = await find_previous_version(client, Ecosystem.npm, "pkg", "1.0.0")

        assert previous is None

    @pytest.mark.asyncio
    async def test_none_when_version_unpublished(self):
        """Locked version isn't in the registry's current versions{} at all."""
        metadata = {
            "versions": {"1.0.0": {}},
            "time": {"1.0.0": "2020-01-01T00:00:00.000Z", "1.0.1": "2020-01-02T00:00:00.000Z"},
        }

        async def _handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=metadata)

        async with httpx.AsyncClient(transport=httpx.MockTransport(_handler)) as client:
            previous = await find_previous_version(client, Ecosystem.npm, "pkg", "1.0.1")

        assert previous is None


class TestFindPreviousVersionPypi:
    @pytest.mark.asyncio
    async def test_picks_by_upload_time(self):
        metadata = {
            "releases": {
                "1.0.0": [{"upload_time_iso_8601": "2021-01-01T00:00:00.000000Z"}],
                "2.0.0": [{"upload_time_iso_8601": "2021-01-02T00:00:00.000000Z"}],
            }
        }

        async def _handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=metadata)

        async with httpx.AsyncClient(transport=httpx.MockTransport(_handler)) as client:
            previous = await find_previous_version(client, Ecosystem.pypi, "pkg", "2.0.0")

        assert previous == "1.0.0"

    @pytest.mark.asyncio
    async def test_yanked_release_with_no_files_skipped(self):
        metadata = {
            "releases": {
                "1.0.0": [{"upload_time_iso_8601": "2021-01-01T00:00:00.000000Z"}],
                "1.5.0": [],  # yanked / nothing ever uploaded
                "2.0.0": [{"upload_time_iso_8601": "2021-01-03T00:00:00.000000Z"}],
            }
        }

        async def _handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=metadata)

        async with httpx.AsyncClient(transport=httpx.MockTransport(_handler)) as client:
            previous = await find_previous_version(client, Ecosystem.pypi, "pkg", "2.0.0")

        assert previous == "1.0.0"


# ── scan_dependencies ─────────────────────────────────────────────────────────────


def _make_npm_backend(packages: dict[str, dict]) -> httpx.MockTransport:
    """
    Build a MockTransport serving several npm packages end-to-end: registry
    metadata (with `time`, for find_previous_version) and real tarball bytes
    for every version referenced.

    `packages` shape: {pkg_name: {version: file_contents_dict}}, in the
    order versions should be treated as published (oldest first).
    """
    tarballs: dict[str, bytes] = {}
    registry: dict[str, dict] = {}

    for pkg_name, versions in packages.items():
        metadata: dict = {"versions": {}, "time": {}}
        for i, (version, files) in enumerate(versions.items()):
            tgz = npm_tgz(files)
            tarball_path = f"/{pkg_name}/-/{version}.tgz"
            tarballs[tarball_path] = tgz
            metadata["versions"][version] = {
                "dist": {
                    "tarball": f"https://registry.test{tarball_path}",
                    "integrity": npm_integrity(tgz),
                }
            }
            metadata["time"][version] = f"2020-01-{i + 1:02d}T00:00:00.000Z"
        registry[f"/{pkg_name}"] = metadata

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path in registry:
            return httpx.Response(200, json=registry[path])
        if path in tarballs:
            return httpx.Response(200, content=tarballs[path])
        return httpx.Response(404)

    return httpx.MockTransport(handler)


class TestScanDependencies:
    @pytest.mark.asyncio
    async def test_scans_multiple_dependencies(self):
        transport = _make_npm_backend({
            "left-pad": {
                "1.0.0": {"package.json": json.dumps({"name": "left-pad", "version": "1.0.0"})},
                "1.0.1": {"package.json": json.dumps({"name": "left-pad", "version": "1.0.1"})},
            },
            "right-pad": {
                "2.0.0": {"package.json": json.dumps({"name": "right-pad", "version": "2.0.0"})},
                "2.1.0": {"package.json": json.dumps({"name": "right-pad", "version": "2.1.0"})},
            },
        })
        deps = [
            LockedDependency("left-pad", "1.0.1"),
            LockedDependency("right-pad", "2.1.0"),
        ]

        async with httpx.AsyncClient(transport=transport) as client:
            entries = await scan_dependencies(client, Ecosystem.npm, deps, no_feeds=True)

        assert len(entries) == 2
        left = next(e for e in entries if e.package == "left-pad")
        assert left.from_version == "1.0.0"
        assert left.to_version == "1.0.1"
        assert left.report is not None
        assert left.error is None
        right = next(e for e in entries if e.package == "right-pad")
        assert right.from_version == "2.0.0"
        assert right.report is not None

    @pytest.mark.asyncio
    async def test_first_ever_version_gets_error_not_crash(self):
        transport = _make_npm_backend({
            "brand-new": {
                "1.0.0": {"package.json": json.dumps({"name": "brand-new", "version": "1.0.0"})},
            },
        })
        deps = [LockedDependency("brand-new", "1.0.0")]

        async with httpx.AsyncClient(transport=transport) as client:
            entries = await scan_dependencies(client, Ecosystem.npm, deps, no_feeds=True)

        assert len(entries) == 1
        assert entries[0].report is None
        assert entries[0].error is not None
        assert "No earlier published version" in entries[0].error

    @pytest.mark.asyncio
    async def test_one_package_failing_does_not_abort_the_scan(self):
        """A 404 for one package's registry metadata must not stop the others."""
        transport = _make_npm_backend({
            "good-pkg": {
                "1.0.0": {"package.json": json.dumps({"name": "good-pkg", "version": "1.0.0"})},
                "1.0.1": {"package.json": json.dumps({"name": "good-pkg", "version": "1.0.1"})},
            },
        })
        deps = [
            LockedDependency("good-pkg", "1.0.1"),
            LockedDependency("does-not-exist", "9.9.9"),
        ]

        async with httpx.AsyncClient(transport=transport) as client:
            entries = await scan_dependencies(client, Ecosystem.npm, deps, no_feeds=True)

        assert len(entries) == 2
        good = next(e for e in entries if e.package == "good-pkg")
        assert good.report is not None
        assert good.error is None

        bad = next(e for e in entries if e.package == "does-not-exist")
        assert bad.report is None
        assert bad.error is not None
