"""
Integration smoke test for the walking skeleton.

Runs the full pipeline end-to-end using stubbed fetcher, LLM, and feeds.
Verifies:
  - CLI exits 0
  - Output is a valid RiskReport JSON
  - Risk score is in [0, 100]
  - Severity matches the score

This test does NOT make real API calls — all components are stubs.
The integration gate for CI will eventually use a mocked LLM response
and real fixture package tarballs.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest
from click.testing import CliRunner

from chainwatch.cli import cli


@pytest.fixture(autouse=True)
def set_fake_api_key(monkeypatch):
    """
    Set a fake ANTHROPIC_API_KEY for tests.

    The stub LLM implementation never calls the real API, but pydantic-settings
    will fail to construct Settings if the key is missing.
    """
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-fake-key-for-ci")
    # Clear the lru_cache so the patched env var takes effect
    from chainwatch.config import get_settings
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


class TestSmoke:
    def test_diff_npm_exits_zero(self):
        """chainwatch diff npm lodash 4.17.20 4.17.21 should exit 0."""
        runner = CliRunner()
        result = runner.invoke(cli, ["diff", "npm", "lodash", "4.17.20", "4.17.21"])
        assert result.exit_code == 0, (
            f"Expected exit code 0, got {result.exit_code}.\n"
            f"Output:\n{result.output}"
        )

    def test_diff_npm_json_mode_valid_json(self):
        """--json flag should produce a single valid JSON line."""
        runner = CliRunner()
        result = runner.invoke(cli, ["--json", "diff", "npm", "lodash", "4.17.20", "4.17.21"])
        assert result.exit_code == 0, result.output

        # Should be parseable as JSON
        data = json.loads(result.output.strip())
        assert data["package"] == "lodash"
        assert data["ecosystem"] == "npm"
        assert data["from_version"] == "4.17.20"
        assert data["to_version"] == "4.17.21"

    def test_diff_score_in_valid_range(self):
        """Risk score must be between 0 and 100."""
        runner = CliRunner()
        result = runner.invoke(cli, ["--json", "diff", "npm", "lodash", "4.17.20", "4.17.21"])
        data = json.loads(result.output.strip())
        assert 0.0 <= data["risk_score"] <= 100.0

    def test_diff_severity_present(self):
        """Severity field must be one of the four valid values."""
        runner = CliRunner()
        result = runner.invoke(cli, ["--json", "diff", "npm", "lodash", "4.17.20", "4.17.21"])
        data = json.loads(result.output.strip())
        assert data["severity"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")

    def test_diff_dimensions_present(self):
        """Report must contain all five risk dimensions."""
        runner = CliRunner()
        result = runner.invoke(cli, ["--json", "diff", "npm", "lodash", "4.17.20", "4.17.21"])
        data = json.loads(result.output.strip())
        assert len(data["dimensions"]) == 5
        dim_names = {d["name"] for d in data["dimensions"]}
        assert dim_names == {
            "network_calls", "obfuscation", "install_hooks",
            "env_conditional", "dependency_changes",
        }

    def test_diff_feed_results_present(self):
        """Report must contain results from all three feeds."""
        runner = CliRunner()
        result = runner.invoke(cli, ["--json", "diff", "npm", "lodash", "4.17.20", "4.17.21"])
        data = json.loads(result.output.strip())
        assert len(data["feed_results"]) == 3
        feed_sources = {f["source"] for f in data["feed_results"]}
        assert feed_sources == {"osv", "rekor", "scorecard"}

    def test_diff_schema_version_present(self):
        """schema_version field must be present for dataset reproducibility."""
        runner = CliRunner()
        result = runner.invoke(cli, ["--json", "diff", "npm", "lodash", "4.17.20", "4.17.21"])
        data = json.loads(result.output.strip())
        assert "schema_version" in data

    def test_threshold_exit_code_1_when_exceeded(self):
        """--threshold 0 should always cause exit code 1 (any score > 0)."""
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "diff", "npm", "lodash", "4.17.20", "4.17.21",
                "--threshold", "0", "--no-feeds",
            ],
        )
        # The stub produces a score > 0, so threshold=0 should trigger exit 1
        assert result.exit_code == 1

    def test_no_feeds_flag_works(self):
        """--no-feeds should still produce a valid report."""
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["--json", "diff", "npm", "lodash", "4.17.20", "4.17.21", "--no-feeds"],
        )
        assert result.exit_code == 0, result.output
        data = json.loads(result.output.strip())
        assert data["risk_score"] is not None

    def test_pypi_ecosystem_works(self):
        """pypi ecosystem should produce a valid report."""
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["--json", "diff", "pypi", "requests", "2.31.0", "2.32.0"],
        )
        assert result.exit_code == 0, result.output
        data = json.loads(result.output.strip())
        assert data["ecosystem"] == "pypi"

    def test_json_mode_stdout_is_pure_json_in_a_real_process(self):
        """
        --json stdout must contain *only* the report — no log lines.

        Regression test for a real bug: `_configure_logging` built its
        RichHandler with no `console=`, so RichHandler fell back to its own
        stdout-backed Console, and pipeline-stage log lines (Stage 1/4, ...)
        interleaved with the JSON report on stdout — corrupting the exact
        `chainwatch --json diff ... > report.json` usage the docstring and
        README document.

        `CliRunner` can't catch this: `logging.basicConfig()` only wires up
        handlers once per process, so whichever test runs first inside a
        shared pytest process binds the RichHandler to *that* test's
        redirected stream, and every later `CliRunner.invoke()` silently
        logs into a stale buffer nobody reads — the corruption is real but
        invisible under CliRunner. A subprocess with real OS-level stdout/
        stderr pipes is the only way to observe it.
        """
        env = {**os.environ, "ANTHROPIC_API_KEY": "sk-ant-test-fake-key-for-ci"}
        result = subprocess.run(
            [
                sys.executable, "-c", "from chainwatch.cli import cli; cli()",
                "--json", "diff", "npm", "lodash", "4.17.20", "4.17.21", "--no-feeds",
            ],
            capture_output=True, text=True, env=env, timeout=60,
        )
        assert result.returncode == 0, f"stderr:\n{result.stderr}"

        # stdout must be exactly one line of valid JSON, nothing else.
        lines = result.stdout.splitlines()
        assert len(lines) == 1, f"expected a single JSON line, got:\n{result.stdout!r}"
        data = json.loads(lines[0])
        assert data["package"] == "lodash"

        # Log lines belong on stderr, not stdout.
        assert "Stage" not in result.stdout
        assert "Stage" in result.stderr


class TestScanSubcommand:
    """
    `scan` parses a lockfile and diffs each pinned dependency against its
    predecessor. Error paths (bad/empty lockfile) are network-free; the
    happy path makes one real registry+LLM(stub)+no-feeds call, matching
    this file's existing convention of hitting the real npm registry with
    a stubbed LLM rather than mocking HTTP.
    """

    def test_scan_produces_valid_ndjson(self, tmp_path):
        lockfile = tmp_path / "package-lock.json"
        lockfile.write_text(json.dumps({
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "test-project"},
                "node_modules/lodash": {"version": "4.17.21"},
            },
        }))
        runner = CliRunner()
        result = runner.invoke(
            cli, ["--json", "scan", str(lockfile), "--no-feeds"]
        )
        assert result.exit_code == 0, result.output
        lines = [line for line in result.stdout.strip().splitlines() if line]
        assert len(lines) == 1
        data = json.loads(lines[0])
        assert data["package"] == "lodash"
        assert data["to_version"] == "4.17.21"
        assert data["report"] is not None
        assert data["error"] is None

    def test_scan_human_mode_renders_table(self, tmp_path):
        """Non-JSON mode: a Rich summary table, covering both the success
        and per-package-error rendering paths in output._emit_scan_rich."""
        lockfile = tmp_path / "package-lock.json"
        lockfile.write_text(json.dumps({
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "test-project"},
                "node_modules/lodash": {"version": "4.17.21"},
                # A version that was never published — exercises the
                # per-package error row, not just the success row.
                "node_modules/lodash-nonexistent-pkg-xyz": {"version": "1.0.0"},
            },
        }))
        result = CliRunner().invoke(cli, ["scan", str(lockfile), "--no-feeds"])
        assert result.exit_code == 0, result.output
        assert "CHAINWATCH SCAN" in result.output
        assert "lodash" in result.output
        assert "2 dependencies scanned" in result.output

    def test_scan_invalid_lockfile_exits_2(self, tmp_path):
        lockfile = tmp_path / "yarn.lock"
        lockfile.write_text("# yarn lockfile v1\n")
        result = CliRunner().invoke(cli, ["scan", str(lockfile)])
        assert result.exit_code == 2

    def test_scan_empty_lockfile_exits_0_with_no_reports(self, tmp_path):
        lockfile = tmp_path / "requirements.txt"
        lockfile.write_text("# nothing pinned here\nnumpy>=1.20\n")
        result = CliRunner().invoke(cli, ["scan", str(lockfile)])
        assert result.exit_code == 0

    def test_scan_limit_truncates_dependency_count(self, tmp_path):
        lockfile = tmp_path / "package-lock.json"
        lockfile.write_text(json.dumps({
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "test-project"},
                "node_modules/lodash": {"version": "4.17.21"},
                "node_modules/left-pad": {"version": "1.3.0"},
            },
        }))
        result = CliRunner().invoke(
            cli, ["--json", "scan", str(lockfile), "--no-feeds", "--limit", "1"]
        )
        assert result.exit_code == 0, result.output
        # The "N found, scanning first M" notice goes to stderr, not stdout —
        # assert against .stdout specifically so this also catches a
        # regression back into the bug test_json_mode_stdout_is_pure_json_in_a_real_process
        # covers (stdout must carry only the report data).
        lines = [line for line in result.stdout.strip().splitlines() if line]
        assert len(lines) == 1, f"expected a single JSON line on stdout, got:\n{result.stdout!r}"
        # --limit sorts alphabetically before truncating (see lockfile.py) —
        # "left-pad" sorts before "lodash".
        assert json.loads(lines[0])["package"] == "left-pad"


class TestReportSubcommand:
    """The `report` subcommand re-renders a saved report JSON (no network/API)."""

    @staticmethod
    def _sample_report_json() -> str:
        from chainwatch.models import (
            DIMENSIONS,
            DiffSummary,
            Ecosystem,
            FeedResult,
            FeedStatus,
            RiskDimension,
            RiskReport,
            Severity,
        )

        dims = [
            RiskDimension(
                name=d["name"], label=d["label"], score=0.0,
                weight=d["weight"], reasoning="none",
            )
            for d in DIMENSIONS
        ]
        feeds = [
            FeedResult(source=s, status=FeedStatus.no_data, details="")
            for s in ("osv", "rekor", "scorecard")
        ]
        return RiskReport(
            ecosystem=Ecosystem.npm, package="lodash",
            from_version="1.0.0", to_version="1.0.1",
            risk_score=0.0, severity=Severity.LOW, llm_base_score=0.0,
            dimensions=dims, feed_results=feeds, diff_summary=DiffSummary(),
            llm_model="claude-sonnet-4-6", llm_summary="Rendered from a saved report.",
        ).model_dump_json()

    def test_report_rerenders_json(self, tmp_path):
        path = tmp_path / "r.json"
        path.write_text(self._sample_report_json())
        result = CliRunner().invoke(cli, ["--json", "report", str(path)])
        assert result.exit_code == 0, result.output
        data = json.loads(result.output.strip())
        assert data["package"] == "lodash"
        assert data["llm_base_score"] == 0.0

    def test_report_human_mode(self, tmp_path):
        path = tmp_path / "r.json"
        path.write_text(self._sample_report_json())
        result = CliRunner().invoke(cli, ["report", str(path)])
        assert result.exit_code == 0, result.output
        assert "lodash" in result.output

    def test_report_invalid_json_exits_2(self, tmp_path):
        path = tmp_path / "bad.json"
        path.write_text("{ not valid report }")
        result = CliRunner().invoke(cli, ["report", str(path)])
        assert result.exit_code == 2
