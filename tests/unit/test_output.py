"""
Unit tests for chainwatch.output — Rich rendering of untrusted text.

The LLM's reasoning and summary quote attacker-controlled diff text verbatim,
and feed details, package names, hook names, file paths, and scan errors all
come from outside this process. Rich parses plain strings for its own
``[tag]`` markup, including ``[link=URL]`` which becomes a real terminal
hyperlink, so every one of those strings must reach the console as literal
text. These tests render reports into a recording console and check that
hostile markup survives as brackets, that no OSC-8 hyperlink escape is
emitted, and that the tool's own first-party markup still renders.
"""

from __future__ import annotations

import io

import pytest
from rich.console import Console

import chainwatch.output as output
from chainwatch.models import (
    DIMENSIONS,
    DiffSummary,
    Ecosystem,
    FeedResult,
    FeedStatus,
    RiskDimension,
    RiskReport,
    ScanEntry,
    Severity,
)

HOSTILE = "see [link=file:///etc/passwd]docs[/link] then [bold red]ALL CLEAR[/bold red]"
OSC8 = "\x1b]8;"


def _report(**overrides) -> RiskReport:
    dims = [
        RiskDimension(
            name=d["name"], label=d["label"], score=0.0, weight=d["weight"],
            reasoning=overrides.get("reasoning", HOSTILE), confidence=0.9,
        )
        for d in DIMENSIONS
    ]
    feeds = [
        FeedResult(
            source="osv", status=FeedStatus.clean,
            details=overrides.get("details", HOSTILE),
            url="https://osv.dev/[link=file:///x]y[/link]",
        ),
    ]
    return RiskReport(
        ecosystem=Ecosystem.npm, package="pkg", from_version="1", to_version="2",
        risk_score=0.0, severity=Severity.LOW,
        dimensions=dims, feed_results=feeds,
        diff_summary=DiffSummary(new_install_hooks=overrides.get("hooks", [])),
        llm_model="m", llm_summary=overrides.get("summary", HOSTILE),
        caveats=overrides.get("caveats", []),
    )


@pytest.fixture
def recorder(monkeypatch):
    console = Console(
        file=io.StringIO(), record=True, width=200,
        force_terminal=True, color_system="truecolor",
    )
    monkeypatch.setattr(output, "_console", console)
    return console


class TestReportRendering:
    def test_llm_text_is_rendered_literally(self, recorder):
        output.emit_report(_report())
        plain = recorder.export_text()
        ansi = recorder.export_text(styles=True)
        assert "[link=file:///etc/passwd]docs[/link]" in plain
        assert "[bold red]ALL CLEAR[/bold red]" in plain
        assert OSC8 not in ansi

    def test_feed_details_and_url_are_literal(self, recorder):
        output.emit_report(_report())
        plain = recorder.export_text()
        assert "https://osv.dev/[link=file:///x]y[/link]" in plain
        assert OSC8 not in recorder.export_text(styles=True)

    def test_install_hook_names_are_escaped(self, recorder):
        output.emit_report(_report(hooks=["[link=file:///x]postinstall[/link]"]))
        plain = recorder.export_text()
        assert "install hooks: [link=file:///x]postinstall[/link]" in plain
        assert OSC8 not in recorder.export_text(styles=True)

    def test_caveats_are_escaped(self, recorder):
        output.emit_report(_report(caveats=["cut: [link=file:///x]dist/a.js[/link]"]))
        plain = recorder.export_text()
        assert "cut: [link=file:///x]dist/a.js[/link]" in plain
        assert OSC8 not in recorder.export_text(styles=True)

    def test_first_party_markup_still_renders(self, recorder):
        output.emit_report(_report())
        plain = recorder.export_text()
        assert "RISK DIMENSIONS" in plain
        assert "THREAT FEED RESULTS" in plain
        assert "[bold dim]" not in plain


class TestScanRendering:
    def test_package_name_and_error_are_literal(self, recorder):
        entries = [
            ScanEntry(
                package="[link=file:///x]evil[/link]", to_version="1.0.0",
                error="[bold red]looks fine[/bold red]",
            ),
            ScanEntry(package="good", from_version="1", to_version="2", report=_report()),
        ]
        output.emit_scan_results(entries)
        plain = recorder.export_text()
        assert "[link=file:///x]evil[/link]" in plain
        assert "[bold red]looks fine[/bold red]" in plain
        assert "CHAINWATCH SCAN" in plain
        assert OSC8 not in recorder.export_text(styles=True)
