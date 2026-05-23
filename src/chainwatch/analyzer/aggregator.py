"""
chainwatch.analyzer.aggregator
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Combines LLM dimension scores and feed signals into a composite 0–100 risk
score and assembles the final ``RiskReport``.

This is a pure function module — no I/O, no API calls, no async.  Given the
same inputs it always produces the same output, which makes it:
  - Trivial to test
  - Easy to re-run post-hoc with a different weight matrix
  - Explainable to a conference audience (show the formula, it fits on a slide)

Weight matrix:
  The base weights are defined in ``models.DIMENSIONS`` and enforced by the
  pydantic validator on ``RiskReport.dimensions``.  The Scorecard score acts
  as a trust modifier that can lower the composite score for packages with
  strong hygiene signals — but it can never *raise* a low score above what the
  LLM and other feeds found.

Feed contribution:
  Feed results are not folded into the 0–100 score directly.  Instead:
  - If any feed returns ``malicious``, the severity floor is set to HIGH (≥55)
  - A Rekor signing identity change adds +10 to the raw score (capped at 100)
  - Scorecard score < 4 adds +5 (poor hygiene amplifies other signals)
  - Scorecard score > 7 subtracts 5 (strong hygiene is a mild mitigant)

  This separation keeps the LLM score as the primary signal and makes
  the feed contributions auditable — the final report shows both.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from chainwatch.models import (
    DiffSummary,
    Ecosystem,
    FeedResult,
    FeedStatus,
    RiskDimension,
    RiskReport,
)

log = logging.getLogger(__name__)

# Feed score modifiers — defined as constants so they are easy to cite and tune
_MALICIOUS_FEED_FLOOR_SCORE = 55.0     # minimum score if any feed says malicious
_REKOR_IDENTITY_CHANGE_BONUS = 10.0   # added if signing identity changed
_POOR_SCORECARD_BONUS = 5.0            # added if Scorecard < 4
_GOOD_SCORECARD_PENALTY = -5.0         # subtracted if Scorecard > 7


def build_report(
    package: str,
    ecosystem: Ecosystem,
    from_version: str,
    to_version: str,
    from_sha256: str,
    to_sha256: str,
    diff_summary: DiffSummary,
    dimensions: list[RiskDimension],
    feed_results: list[FeedResult],
    llm_summary: str,
    llm_model: str,
) -> RiskReport:
    """
    Assemble the final RiskReport from all pipeline outputs.

    Args:
        package:        Package name
        ecosystem:      npm or pypi
        from_version:   Baseline version string
        to_version:     Target version string
        from_sha256:    SHA256 of the baseline tarball
        to_sha256:      SHA256 of the target tarball
        diff_summary:   Structured diff from the engine
        dimensions:     LLM-scored risk dimensions
        feed_results:   Results from OSV, Rekor, Scorecard
        llm_summary:    LLM free-text assessment
        llm_model:      Model string used for provenance

    Returns:
        A fully validated RiskReport ready for emission.
    """
    raw_score = _compute_llm_base_score(dimensions)
    adjusted_score = _apply_feed_modifiers(raw_score, feed_results)
    final_score = max(0.0, min(100.0, adjusted_score))
    severity = RiskReport.severity_for_score(final_score)

    log.info(
        "Score: LLM base=%.1f → feed-adjusted=%.1f → severity=%s",
        raw_score, final_score, severity.value,
    )

    return RiskReport(
        ecosystem=ecosystem,
        package=package,
        from_version=from_version,
        to_version=to_version,
        risk_score=round(final_score, 1),
        severity=severity,
        dimensions=dimensions,
        feed_results=feed_results,
        diff_summary=diff_summary,
        llm_model=llm_model,
        llm_summary=llm_summary,
        timestamp=datetime.now(UTC),
        from_version_sha256=from_sha256,
        to_version_sha256=to_sha256,
    )


# ── Score computation ─────────────────────────────────────────────────────────


def _compute_llm_base_score(dimensions: list[RiskDimension]) -> float:
    """
    Compute the 0–100 base score from LLM dimension scores.

    Formula: sum(score_i * weight_i) * 10

    Each dimension score is 0–10, and weights sum to 1.0, so the maximum
    possible base score is 10 * 1.0 * 10 = 100.

    This formula fits on a slide.  It is intentionally simple.
    """
    return sum(dim.weighted_contribution for dim in dimensions)


def _apply_feed_modifiers(base_score: float, feed_results: list[FeedResult]) -> float:
    """
    Apply feed-based score adjustments.

    The modifier logic is additive with a floor — we can push the score up
    based on feed signals, but the LLM base score is never reduced below
    what the LLM found.  The exception is the Scorecard penalty, which
    is a mild mitigant that can lower a borderline score.

    See module docstring for the full modifier table.
    """
    score = base_score
    modifiers_applied: list[str] = []

    for feed in feed_results:
        if feed.status == FeedStatus.malicious and score < _MALICIOUS_FEED_FLOOR_SCORE:
            score = _MALICIOUS_FEED_FLOOR_SCORE
            modifiers_applied.append(
                f"feed:{feed.source}:malicious floor={_MALICIOUS_FEED_FLOOR_SCORE}"
            )

        if feed.source == "rekor" and feed.signing_identity_changed:
            score += _REKOR_IDENTITY_CHANGE_BONUS
            modifiers_applied.append(f"rekor:identity_changed +{_REKOR_IDENTITY_CHANGE_BONUS}")

        if feed.source == "scorecard" and feed.scorecard_score is not None:
            if feed.scorecard_score < 4.0:
                score += _POOR_SCORECARD_BONUS
                modifiers_applied.append(f"scorecard:poor +{_POOR_SCORECARD_BONUS}")
            elif feed.scorecard_score > 7.0:
                score += _GOOD_SCORECARD_PENALTY
                modifiers_applied.append(f"scorecard:good {_GOOD_SCORECARD_PENALTY}")

    if modifiers_applied:
        log.debug("Feed modifiers applied: %s", ", ".join(modifiers_applied))

    return score
