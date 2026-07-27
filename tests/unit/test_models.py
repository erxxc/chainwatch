"""
Unit tests for chainwatch.models

Tests that the pydantic schemas validate correctly — including the cross-field
validators (weight sum, severity-score consistency).  No I/O, no API calls.
"""

from __future__ import annotations

import pytest

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

# ── Helpers ───────────────────────────────────────────────────────────────────


def _make_dimensions(overrides: dict | None = None) -> list[RiskDimension]:
    """Build a valid list of RiskDimensions with default stub scores."""
    scores = {
        "network_calls": 1.0,
        "obfuscation": 0.5,
        "install_hooks": 0.0,
        "env_conditional": 0.0,
        "dependency_changes": 0.5,
    }
    if overrides:
        scores.update(overrides)
    return [
        RiskDimension(
            name=d["name"],
            label=d["label"],
            score=scores.get(d["name"], 0.0),
            weight=d["weight"],
            reasoning="Test reasoning.",
        )
        for d in DIMENSIONS
    ]


def _make_feed_results() -> list[FeedResult]:
    return [
        FeedResult(source="osv", status=FeedStatus.clean, details="No advisories."),
        FeedResult(source="rekor", status=FeedStatus.no_data, details="No attestation."),
        FeedResult(source="scorecard", status=FeedStatus.no_data, details="Not found."),
    ]


def _make_report(**kwargs) -> RiskReport:
    """Build a minimal valid RiskReport. Keyword args override defaults."""
    dims = _make_dimensions()
    from chainwatch.analyzer.aggregator import _compute_llm_base_score
    score = _compute_llm_base_score(dims)
    defaults = dict(
        ecosystem=Ecosystem.npm,
        package="lodash",
        from_version="4.17.20",
        to_version="4.17.21",
        risk_score=round(score, 1),
        severity=RiskReport.severity_for_score(score),
        dimensions=dims,
        feed_results=_make_feed_results(),
        diff_summary=DiffSummary(),
        llm_model="claude-sonnet-4-6",
        llm_summary="Test summary.",
    )
    defaults.update(kwargs)
    return RiskReport(**defaults)


# ── RiskDimension ──────────────────────────────────────────────────────────────


class TestRiskDimension:
    def test_weighted_contribution_calculation(self):
        dim = RiskDimension(
            name="network_calls",
            label="Network calls",
            score=5.0,
            weight=0.25,
            reasoning="Test.",
        )
        # 5.0 * 0.25 * 10 = 12.5
        assert dim.weighted_contribution == pytest.approx(12.5)

    def test_score_bounds_enforced(self):
        with pytest.raises(ValueError):
            RiskDimension(
                name="network_calls",
                label="Network calls",
                score=11.0,  # > 10, should fail
                weight=0.25,
                reasoning="Test.",
            )

    def test_score_zero_contribution(self):
        dim = RiskDimension(
            name="obfuscation",
            label="Obfuscation",
            score=0.0,
            weight=0.25,
            reasoning="None found.",
        )
        assert dim.weighted_contribution == 0.0

    def test_confidence_defaults_to_none(self):
        dim = RiskDimension(
            name="obfuscation", label="Obfuscation", score=0.0,
            weight=0.25, reasoning="None.",
        )
        assert dim.confidence is None

    def test_confidence_bounds_enforced(self):
        with pytest.raises(ValueError):
            RiskDimension(
                name="obfuscation", label="Obfuscation", score=0.0,
                weight=0.25, reasoning="None.", confidence=1.5,
            )


# ── Severity mapping ──────────────────────────────────────────────────────────


class TestSeverityMapping:
    @pytest.mark.parametrize("score,expected", [
        (0.0,   Severity.LOW),
        (15.0,  Severity.LOW),
        (29.9,  Severity.LOW),
        (30.0,  Severity.MEDIUM),
        (50.0,  Severity.MEDIUM),
        (54.9,  Severity.MEDIUM),
        (55.0,  Severity.HIGH),
        (79.9,  Severity.HIGH),
        (80.0,  Severity.CRITICAL),
        (100.0, Severity.CRITICAL),
    ])
    def test_severity_for_score(self, score: float, expected: Severity):
        assert RiskReport.severity_for_score(score) == expected


# ── RiskReport validation ─────────────────────────────────────────────────────


class TestRiskReport:
    def test_valid_report_constructs(self):
        report = _make_report()
        assert report.package == "lodash"
        assert report.severity == Severity.LOW

    def test_weight_sum_validator_passes(self):
        # Weights in DIMENSIONS sum to exactly 1.0 — should not raise
        report = _make_report()
        total = sum(d.weight for d in report.dimensions)
        assert abs(total - 1.0) < 0.01

    def test_severity_score_mismatch_raises(self):
        with pytest.raises(Exception, match="severity"):
            _make_report(
                risk_score=5.0,
                severity=Severity.CRITICAL,  # wrong for score=5
            )

    def test_confirmed_malicious_by_feed_false(self):
        report = _make_report()
        assert report.confirmed_malicious_by_feed() is False

    def test_confirmed_malicious_by_feed_true(self):
        feeds = [
            FeedResult(source="osv", status=FeedStatus.malicious,
                      details="MAL-2018-1", advisory_ids=["MAL-2018-1"]),
            FeedResult(source="rekor", status=FeedStatus.no_data, details=""),
            FeedResult(source="scorecard", status=FeedStatus.no_data, details=""),
        ]
        report = _make_report(feed_results=feeds)
        assert report.confirmed_malicious_by_feed() is True

    def test_has_mal_advisory_true(self):
        feeds = [
            FeedResult(source="osv", status=FeedStatus.malicious,
                      details="MAL", advisory_ids=["MAL-2018-1", "GHSA-1234"]),
            FeedResult(source="rekor", status=FeedStatus.no_data, details=""),
            FeedResult(source="scorecard", status=FeedStatus.no_data, details=""),
        ]
        report = _make_report(feed_results=feeds)
        assert report.has_mal_advisory() is True

    def test_has_mal_advisory_false_when_only_ghsa(self):
        feeds = [
            FeedResult(source="osv", status=FeedStatus.suspicious,
                      details="GHSA only", advisory_ids=["GHSA-1234-abcd-5678"]),
            FeedResult(source="rekor", status=FeedStatus.no_data, details=""),
            FeedResult(source="scorecard", status=FeedStatus.no_data, details=""),
        ]
        report = _make_report(feed_results=feeds)
        assert report.has_mal_advisory() is False

    def test_schema_version_present(self):
        report = _make_report()
        assert report.schema_version == "0.2.0"

    def test_llm_base_score_and_modifiers_default(self):
        # A directly-constructed report carries the new fields with defaults.
        report = _make_report()
        assert report.llm_base_score is None
        assert report.score_modifiers == []

    def test_llm_base_score_and_modifiers_roundtrip(self):
        from chainwatch.models import ScoreModifier
        mod = ScoreModifier(source="scorecard", rule="scorecard_good", delta=-5.0, note="ok")
        report = _make_report(llm_base_score=12.5, score_modifiers=[mod])
        restored = RiskReport.model_validate_json(report.model_dump_json())
        assert restored.llm_base_score == 12.5
        assert restored.score_modifiers[0].rule == "scorecard_good"
        assert restored.score_modifiers[0].delta == -5.0

    def test_json_serialisation_roundtrip(self):
        report = _make_report()
        json_str = report.model_dump_json()
        restored = RiskReport.model_validate_json(json_str)
        assert restored.package == report.package
        assert restored.risk_score == report.risk_score


# ── Aggregator integration ────────────────────────────────────────────────────


class TestAggregator:
    def test_base_score_all_zeros_is_zero(self):
        from chainwatch.analyzer.aggregator import _compute_llm_base_score
        all_dims = [
            "network_calls", "obfuscation", "install_hooks",
            "env_conditional", "dependency_changes",
        ]
        dims = _make_dimensions({k: 0.0 for k in all_dims})
        assert _compute_llm_base_score(dims) == pytest.approx(0.0)

    def test_base_score_all_tens_is_hundred(self):
        from chainwatch.analyzer.aggregator import _compute_llm_base_score
        all_dims = [
            "network_calls", "obfuscation", "install_hooks",
            "env_conditional", "dependency_changes",
        ]
        dims = _make_dimensions({k: 10.0 for k in all_dims})
        assert _compute_llm_base_score(dims) == pytest.approx(100.0)

    def test_feed_malicious_applies_floor(self):
        from chainwatch.analyzer.aggregator import _apply_feed_modifiers
        feeds = [
            FeedResult(source="osv", status=FeedStatus.malicious, details="MAL"),
        ]
        # Low base score gets bumped to the floor
        result, modifiers = _apply_feed_modifiers(10.0, feeds)
        assert result == pytest.approx(55.0)
        assert [m.rule for m in modifiers] == ["malicious_floor"]
        # delta reconstructs the path: base + delta == floor
        assert 10.0 + modifiers[0].delta == pytest.approx(55.0)

    def test_feed_malicious_doesnt_lower_high_score(self):
        from chainwatch.analyzer.aggregator import _apply_feed_modifiers
        feeds = [
            FeedResult(source="osv", status=FeedStatus.malicious, details="MAL"),
        ]
        # Score already above floor — not changed downward, no modifier recorded
        result, modifiers = _apply_feed_modifiers(80.0, feeds)
        assert result == pytest.approx(80.0)
        assert modifiers == []

    def test_rekor_identity_change_adds_bonus(self):
        from chainwatch.analyzer.aggregator import _apply_feed_modifiers
        feeds = [
            FeedResult(
                source="rekor",
                status=FeedStatus.suspicious,
                details="New signer",
                signing_identity_changed=True,
            ),
        ]
        result, modifiers = _apply_feed_modifiers(30.0, feeds)
        assert result == pytest.approx(40.0)
        assert [m.rule for m in modifiers] == ["rekor_identity_changed"]

    def test_build_report_persists_base_score_and_modifiers(self):
        from chainwatch.analyzer.aggregator import build_report
        dims = _make_dimensions()  # base = 1.0*.25 + .5*.25 + .5*.15 = 4.5
        feeds = [
            FeedResult(source="osv", status=FeedStatus.malicious, details="MAL"),
            FeedResult(source="rekor", status=FeedStatus.no_data, details=""),
            FeedResult(source="scorecard", status=FeedStatus.no_data, details=""),
        ]
        report = build_report(
            package="evil", ecosystem=Ecosystem.npm,
            from_version="1.0.0", to_version="1.0.1",
            from_sha256="a", to_sha256="b",
            diff_summary=DiffSummary(), dimensions=dims, feed_results=feeds,
            llm_summary="s", llm_model="m",
        )
        assert report.llm_base_score == pytest.approx(4.5)
        assert report.risk_score == pytest.approx(55.0)  # malicious floor
        assert [m.rule for m in report.score_modifiers] == ["malicious_floor"]
