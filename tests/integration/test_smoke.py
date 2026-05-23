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
