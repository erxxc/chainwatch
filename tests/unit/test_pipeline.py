"""
Unit tests for chainwatch.pipeline.run_diff_pipeline.

Network-free: npm metadata and real in-memory tarballs come from
tests.fixtures.npm_registry.MockNpmRegistry, the LLM runs in stub mode
(sk-ant-test key), and feeds are skipped with no_feeds=True.
"""

from __future__ import annotations

from collections.abc import Iterator

import httpx
import pytest

from chainwatch.config import get_settings
from chainwatch.models import Ecosystem, RiskReport
from chainwatch.pipeline import run_diff_pipeline
from tests.fixtures.npm_registry import MockNpmRegistry, NpmFixtureVersion, package_json


@pytest.fixture(autouse=True)
def _settings(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-fake-key-for-ci")
    monkeypatch.setenv("CHAINWATCH_NPM_REGISTRY", "https://registry.test")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


_PROSE = (
    "// This release quietly harvests ~/.npmrc and posts it to attacker.example\n"
    "// (placeholder prose — nothing below actually does that)\n"
)


def _registry() -> MockNpmRegistry:
    registry = MockNpmRegistry()
    registry.add(NpmFixtureVersion(
        package="pkg",
        version="1.0.0",
        files={
            "package.json": package_json("pkg", "1.0.0"),
            "index.js": "module.exports = 'old';\n",
        },
    ))
    registry.add(NpmFixtureVersion(
        package="pkg",
        version="1.0.1",
        files={
            "package.json": package_json("pkg", "1.0.1"),
            "index.js": _PROSE + "module.exports = 'new';\n",
        },
    ))
    return registry


def _big_registry(lines: int = 600) -> MockNpmRegistry:
    """A package whose one changed file is far larger than a 1000-token chunk."""
    registry = MockNpmRegistry()
    registry.add(NpmFixtureVersion(
        package="bigpkg",
        version="1.0.0",
        files={
            "package.json": package_json("bigpkg", "1.0.0"),
            "big.js": "\n".join(f"var x{i} = {i};" for i in range(lines)) + "\n",
        },
    ))
    registry.add(NpmFixtureVersion(
        package="bigpkg",
        version="1.0.1",
        files={
            "package.json": package_json("bigpkg", "1.0.1"),
            "big.js": "\n".join(f"var x{i} = {i + 1};" for i in range(lines)) + "\n",
        },
    ))
    return registry


async def _run(
    registry: MockNpmRegistry | None = None, package: str = "pkg", **kwargs
) -> RiskReport:
    registry = registry or _registry()
    async with httpx.AsyncClient(transport=registry.transport()) as client:
        return await run_diff_pipeline(
            client, Ecosystem.npm, package, "1.0.0", "1.0.1", True, **kwargs
        )


class TestTimings:
    @pytest.mark.asyncio
    async def test_every_stage_is_timed(self):
        report = await _run()
        t = report.timings
        assert t is not None
        stages = (
            t.fetch_seconds, t.diff_seconds, t.llm_seconds,
            t.feeds_seconds, t.analysis_seconds, t.total_seconds,
        )
        assert all(value >= 0.0 for value in stages)
        # Each stage was rounded independently, so allow rounding slack.
        assert t.total_seconds + 0.01 >= t.fetch_seconds + t.diff_seconds + t.analysis_seconds
        assert t.analysis_seconds + 0.01 >= max(t.llm_seconds, t.feeds_seconds)

    @pytest.mark.asyncio
    async def test_timings_survive_a_json_roundtrip(self):
        report = await _run()
        restored = RiskReport.model_validate_json(report.model_dump_json())
        assert restored.timings == report.timings


class TestStripComments:
    @pytest.mark.asyncio
    async def test_default_keeps_comments_and_reports_no_caveats(self):
        report = await _run()
        ds = report.diff_summary
        assert ds.comments_stripped is False
        assert ds.comment_lines_stripped == 0
        assert "harvests" in (ds.file_diffs[0].unified_diff or "")
        assert report.caveats == []

    @pytest.mark.asyncio
    async def test_strip_comments_removes_prose_and_records_it(self):
        report = await _run(strip_comments=True)
        ds = report.diff_summary
        assert ds.comments_stripped is True
        assert ds.comment_lines_stripped == 2
        body = ds.file_diffs[0].unified_diff or ""
        assert "harvests" not in body
        assert "+module.exports = 'new';" in body
        assert any("--strip-comments" in caveat for caveat in report.caveats)



class TestSplitLargeFiles:
    @pytest.fixture(autouse=True)
    def _small_chunk_budget(self, monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
        # 1000 tokens (the settings minimum) = 4000 chars; big.js's diff is ~20 KB.
        monkeypatch.setenv("CHAINWATCH_MAX_TOKENS_PER_CHUNK", "1000")
        monkeypatch.setenv("CHAINWATCH_MAX_SPLIT_PARTS_PER_FILE", "3")
        get_settings.cache_clear()
        yield
        get_settings.cache_clear()

    @pytest.mark.asyncio
    async def test_default_mode_truncates_head_first(self):
        report = await _run(_big_registry(), "bigpkg")
        ds = report.diff_summary
        assert ds.large_files_split is False
        assert ds.split_files == []
        assert ds.truncated_files == ["big.js"]
        assert ds.diff_truncated is True
        assert any("head-first" in caveat for caveat in report.caveats)

    @pytest.mark.asyncio
    async def test_split_mode_sends_parts_up_to_the_configured_cap(self):
        report = await _run(_big_registry(), "bigpkg", split_large_files=True)
        ds = report.diff_summary
        assert ds.large_files_split is True
        assert ds.split_files == ["big.js"]
        # ~20 KB of diff at 4000 chars per part needs more than the cap of 3,
        # so the remainder is truncated — and the report says which rule cut it.
        assert ds.truncated_files == ["big.js"]
        assert ds.chunks_sent_to_llm == 3
        text = "\n".join(report.caveats)
        assert "split into parts" in text
        assert "part cap" in text
