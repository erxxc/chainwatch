"""Unit tests for the npm registry fetcher (network-free via MockTransport)."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator

import httpx
import pytest

from chainwatch.config import get_settings
from chainwatch.fetcher.npm import fetch_package_versions
from tests.fixtures.npm_registry import npm_integrity, npm_tgz


@pytest.fixture(autouse=True)
def npm_settings(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-fake-key-for-ci")
    monkeypatch.setenv("CHAINWATCH_NPM_REGISTRY", "https://registry.test")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_fetch_package_versions_downloads_and_extracts_exact_versions() -> None:
    from_tgz = npm_tgz({
        "package.json": json.dumps({"name": "left-pad", "version": "1.0.0"}),
        "index.js": "module.exports = 'old';\n",
    })
    to_tgz = npm_tgz({
        "package.json": json.dumps({"name": "left-pad", "version": "1.0.1"}),
        "index.js": "module.exports = 'new';\n",
    })
    metadata = {
        "versions": {
            "1.0.0": {
                "dist": {
                    "tarball": "https://registry.test/left-pad/-/1.0.0.tgz",
                    "integrity": npm_integrity(from_tgz),
                }
            },
            "1.0.1": {
                "dist": {
                    "tarball": "https://registry.test/left-pad/-/1.0.1.tgz",
                    "integrity": npm_integrity(to_tgz),
                }
            },
        }
    }

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/left-pad":
            return httpx.Response(200, json=metadata)
        if request.url.path == "/left-pad/-/1.0.0.tgz":
            return httpx.Response(200, content=from_tgz)
        if request.url.path == "/left-pad/-/1.0.1.tgz":
            return httpx.Response(200, content=to_tgz)
        return httpx.Response(404)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await fetch_package_versions(client, "left-pad", "1.0.0", "1.0.1")

    with result:
        assert result.from_dir.is_dir()
        assert result.to_dir.is_dir()
        assert (result.from_dir / "index.js").read_text() == "module.exports = 'old';\n"
        assert (result.to_dir / "index.js").read_text() == "module.exports = 'new';\n"
        assert result.from_sha256 == hashlib.sha256(from_tgz).hexdigest()
        assert result.to_sha256 == hashlib.sha256(to_tgz).hexdigest()


@pytest.mark.asyncio
async def test_fetch_package_versions_encodes_scoped_package_name() -> None:
    tgz = npm_tgz({"index.js": "module.exports = 1;\n"})
    metadata = {
        "versions": {
            "1.0.0": {
                "dist": {
                    "tarball": "https://registry.test/@scope/pkg/-/1.0.0.tgz",
                    "integrity": npm_integrity(tgz),
                }
            },
        }
    }
    seen_paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        raw_path = request.url.raw_path.decode()
        seen_paths.append(raw_path)
        if raw_path == "/%40scope%2Fpkg":
            return httpx.Response(200, json=metadata)
        if request.url.path == "/@scope/pkg/-/1.0.0.tgz":
            return httpx.Response(200, content=tgz)
        return httpx.Response(404)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await fetch_package_versions(client, "@scope/pkg", "1.0.0", "1.0.0")

    result.cleanup()
    assert seen_paths[0] == "/%40scope%2Fpkg"


@pytest.mark.asyncio
async def test_fetch_package_versions_rejects_integrity_mismatch() -> None:
    tgz = npm_tgz({"index.js": "module.exports = 1;\n"})
    metadata = {
        "versions": {
            "1.0.0": {
                "dist": {
                    "tarball": "https://registry.test/pkg/-/1.0.0.tgz",
                    "integrity": npm_integrity(b"not the tarball"),
                }
            },
        }
    }

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/pkg":
            return httpx.Response(200, json=metadata)
        if request.url.path == "/pkg/-/1.0.0.tgz":
            return httpx.Response(200, content=tgz)
        return httpx.Response(404)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(ValueError, match="Integrity mismatch"):
            await fetch_package_versions(client, "pkg", "1.0.0", "1.0.0")


@pytest.mark.asyncio
async def test_fetch_package_versions_rejects_missing_version() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"versions": {}})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(ValueError, match="not found"):
            await fetch_package_versions(client, "pkg", "1.0.0", "1.0.1")
