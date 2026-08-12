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

Dimension-floor contribution:
  Not feed-driven — LLM-driven.  If any single dimension scores >= 9.0 at
  confidence >= 0.9, the score is floored to MEDIUM (>=30). Added
  2026-08-10 (dataset/findings/README.md recommendation #1's follow-up):
  the weighted-sum formula structurally caps what one dimension alone can
  contribute (at a 20% weight, a perfect 10/10 only adds 20 points), which
  under-scores genuinely single-vector attacks — colors's real sabotage
  commit scores resource_exhaustion=10.0 at confidence 1.0 and every other
  dimension a correct 0.0, landing at 25/LOW without this floor. Checked
  against the full corpus before shipping: no benign-labelled report in
  this dataset ever hits this threshold on any dimension.
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
    ScoreModifier,
)

log = logging.getLogger(__name__)

# Feed score modifiers — defined as constants so they are easy to cite and tune
_MALICIOUS_FEED_FLOOR_SCORE = 55.0     # minimum score if any feed says malicious
_REKOR_IDENTITY_CHANGE_BONUS = 10.0   # added if signing identity changed
_POOR_SCORECARD_BONUS = 5.0            # added if Scorecard < 4
_GOOD_SCORECARD_PENALTY = -5.0         # subtracted if Scorecard > 7

# LLM dimension-floor modifier — same idea as the feed floor above, but
# triggered by the LLM's own dimension scores rather than a threat feed.
_DEFINITIVE_DIMENSION_SCORE = 9.0        # dimension score threshold
_DEFINITIVE_DIMENSION_CONFIDENCE = 0.9   # dimension confidence threshold
_DEFINITIVE_DIMENSION_FLOOR_SCORE = 30.0  # minimum score (MEDIUM) if triggered


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
    score, modifiers = _apply_dimension_floor(raw_score, dimensions)
    adjusted_score, feed_modifiers = _apply_feed_modifiers(score, feed_results)
    modifiers = modifiers + feed_modifiers
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
        llm_base_score=round(raw_score, 1),
        dimensions=dimensions,
        feed_results=feed_results,
        score_modifiers=modifiers,
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


def _apply_dimension_floor(
    base_score: float, dimensions: list[RiskDimension]
) -> tuple[float, list[ScoreModifier]]:
    """
    Floor the score to MEDIUM if any single dimension is both near-maximal
    (>= 9.0) and near-certain (confidence >= 0.9).

    Why this exists: the weighted-sum formula in ``_compute_llm_base_score``
    structurally caps what one dimension alone can contribute — at this
    tool's heaviest weight (20%), a perfect 10/10 score only adds 20 of the
    100 points. That under-scores genuinely *single-vector* attacks, where
    four or five of the dimensions are correctly, legitimately zero because
    the attack simply doesn't touch those surfaces. colors's real sabotage
    commit (an unconditional infinite loop, see dataset/malicious/colors/)
    is the case that surfaced this: resource_exhaustion scores 10.0 at
    confidence 1.0, every other dimension a genuine 0.0, and the weighted
    sum alone lands at 25 — still LOW. A model that is both maximally
    confident and maximally severe on one axis shouldn't have that signal
    diluted away by the other dimensions legitimately having nothing to say.

    This is the LLM-driven counterpart to ``_apply_feed_modifiers``'s
    ``malicious_floor`` — same shape, different trigger. Verified against
    every report already committed to ``dataset/`` before shipping: no
    benign-labelled pair ever reaches this threshold on any dimension (see
    dataset/findings/README.md recommendation #1).
    """
    triggering = [
        d for d in dimensions
        if d.score >= _DEFINITIVE_DIMENSION_SCORE
        and d.confidence is not None
        and d.confidence >= _DEFINITIVE_DIMENSION_CONFIDENCE
    ]
    if not triggering or base_score >= _DEFINITIVE_DIMENSION_FLOOR_SCORE:
        return base_score, []

    delta = _DEFINITIVE_DIMENSION_FLOOR_SCORE - base_score
    lead = max(triggering, key=lambda d: d.score)
    return _DEFINITIVE_DIMENSION_FLOOR_SCORE, [ScoreModifier(
        source="llm",
        rule="definitive_dimension_floor",
        delta=round(delta, 1),
        note=(
            f"{lead.name} scored {lead.score:.1f}/10 at confidence "
            f"{lead.confidence:.2f} — raised score to floor "
            f"{_DEFINITIVE_DIMENSION_FLOOR_SCORE:.0f}"
        ),
    )]


def _apply_feed_modifiers(
    base_score: float, feed_results: list[FeedResult]
) -> tuple[float, list[ScoreModifier]]:
    """
    Apply feed-based score adjustments and return the adjusted score together
    with a decomposable trace of every modifier applied.

    The modifier logic is additive with a floor — we can push the score up based
    on feed signals, but the LLM base score is never reduced below what the LLM
    found.  The exception is the Scorecard penalty, a mild mitigant that can
    lower a borderline score.

    Each applied adjustment is recorded as a ``ScoreModifier`` whose ``delta`` is
    the signed change it contributed, so a saved report can reconstruct the path
    ``llm_base_score → risk_score`` without re-running the pipeline.

    See module docstring for the full modifier table.
    """
    score = base_score
    modifiers: list[ScoreModifier] = []

    for feed in feed_results:
        if feed.status == FeedStatus.malicious and score < _MALICIOUS_FEED_FLOOR_SCORE:
            delta = _MALICIOUS_FEED_FLOOR_SCORE - score
            score = _MALICIOUS_FEED_FLOOR_SCORE
            modifiers.append(ScoreModifier(
                source=feed.source,
                rule="malicious_floor",
                delta=round(delta, 1),
                note=(
                    f"{feed.source} reported malicious — raised score to floor "
                    f"{_MALICIOUS_FEED_FLOOR_SCORE:.0f}"
                ),
            ))

        if feed.source == "rekor" and feed.signing_identity_changed:
            score += _REKOR_IDENTITY_CHANGE_BONUS
            modifiers.append(ScoreModifier(
                source="rekor",
                rule="rekor_identity_changed",
                delta=_REKOR_IDENTITY_CHANGE_BONUS,
                note="Sigstore signing identity differs from the previous version",
            ))

        if feed.source == "scorecard" and feed.scorecard_score is not None:
            if feed.scorecard_score < 4.0:
                score += _POOR_SCORECARD_BONUS
                modifiers.append(ScoreModifier(
                    source="scorecard",
                    rule="scorecard_poor",
                    delta=_POOR_SCORECARD_BONUS,
                    note=(
                        f"Weak OpenSSF Scorecard ({feed.scorecard_score:.1f}/10) "
                        "amplifies risk"
                    ),
                ))
            elif feed.scorecard_score > 7.0:
                score += _GOOD_SCORECARD_PENALTY
                modifiers.append(ScoreModifier(
                    source="scorecard",
                    rule="scorecard_good",
                    delta=_GOOD_SCORECARD_PENALTY,
                    note=(
                        f"Strong OpenSSF Scorecard ({feed.scorecard_score:.1f}/10) "
                        "is a mild mitigant"
                    ),
                ))

    if modifiers:
        log.debug(
            "Feed modifiers applied: %s",
            ", ".join(f"{m.source}:{m.rule} {m.delta:+.1f}" for m in modifiers),
        )

    return score, modifiers
