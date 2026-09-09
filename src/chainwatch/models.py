"""
chainwatch.models
~~~~~~~~~~~~~~~~~

Pydantic v2 schemas that define the complete output contract for chainwatch.

Every other module imports from here — this file is intentionally dependency-free
(only stdlib + pydantic) so it can be read in isolation by tooling, researchers,
or a conference reviewer who wants to understand the output format without
tracing the full pipeline.

Schema versioning note: bump ``SCHEMA_VERSION`` when fields change in a
backward-incompatible way. Dataset reports embed this value so future tooling
can detect stale reports.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

# 0.2.0 (2026-07-27): llm_base_score, score_modifiers[], per-dimension confidence.
# 0.3.0 (2026-09-09): timings, caveats[], and the diff-visibility fields on
#   DiffSummary (truncated_files, skipped_files, large_files_split,
#   split_files, comments_stripped, comment_lines_stripped). All additive
#   with defaults — 0.2.0 and 0.1.0 reports still validate against this schema.
SCHEMA_VERSION = "0.3.0"


# ── Enumerations ──────────────────────────────────────────────────────────────


class Ecosystem(StrEnum):
    """Package registry ecosystems supported by chainwatch."""

    npm = "npm"
    pypi = "pypi"


class Severity(StrEnum):
    """
    Composite severity bucket derived from the 0-100 risk score.

    Thresholds (used in aggregator.py):
        LOW      :  0 – 29
        MEDIUM   : 30 – 54
        HIGH     : 55 – 79
        CRITICAL : 80 – 100

    These thresholds are a v0.1 heuristic; the research dataset will be used
    to calibrate them in the write-up.
    """

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FeedStatus(StrEnum):
    """
    Normalised status returned by each threat feed client.

    ``no_data`` signals a graceful degradation — the feed was unreachable or
    had no record for this package.  It never causes a pipeline abort.
    """

    clean = "clean"
    suspicious = "suspicious"
    malicious = "malicious"
    no_data = "no_data"


# ── LLM Risk Dimensions ───────────────────────────────────────────────────────


class RiskDimension(BaseModel):
    """
    A single scored risk dimension from the LLM analysis.

    The LLM is prompted to score each dimension 0-10 and provide free-text
    reasoning.  The aggregator applies a weight matrix to produce the composite
    score.  Weights are defined in ``analyzer/aggregator.py``.

    Storing the raw per-dimension scores in the report enables researchers to
    retune the weight matrix post-hoc without re-running the LLM.
    """

    name: str = Field(description="Canonical dimension identifier, e.g. 'network_calls'")
    label: str = Field(description="Human-readable label for display and paper tables")
    score: float = Field(ge=0.0, le=10.0, description="LLM-assigned score, 0–10")
    weight: float = Field(ge=0.0, le=1.0, description="Aggregator weight applied to this dimension")
    reasoning: str = Field(description="LLM-provided explanation for the score")
    confidence: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description=(
            "LLM self-reported confidence in this dimension's score, 0.0–1.0. "
            "Optional — None for reports produced before the field existed."
        ),
    )

    @property
    def weighted_contribution(self) -> float:
        """Contribution to the 0-100 composite score from this dimension alone."""
        return self.score * self.weight * 10.0


# Default dimension definitions — these match the prompt schema in analyzer/llm.py.
# Defined here so models.py remains the single source of truth for the schema.
#
# resource_exhaustion added 2026-08-10 (dataset/findings/README.md
# recommendation #1): the corpus's colors reconstruction showed a complete,
# real denial-of-service attack (an unconditional infinite loop) scoring
# LOW because none of the original five dimensions — all shaped around
# data-exfiltration/credential-theft — have any concept of "this never
# returns". Weights were rebalanced to make room: network_calls/obfuscation
# 25%->20% each, install_hooks 20%->15%, dependency_changes 15%->10%
# (already flagged separately as possibly over-weighted, see recommendation
# #3), env_conditional unchanged at 15%. resource_exhaustion enters at 20%,
# tied with network_calls/obfuscation as the top weight — a DoS payload is
# not inherently less severe than an exfiltration one.
#
# env_conditional's label widened 2026-08-11 (dataset/findings/README.md
# recommendation #9): the corpus's ctx reconstruction showed the model
# already scoring this dimension 8-9/10 on an attack that *reads and
# exfiltrates* environment variables (AWS keys, hostname) with no branching
# on them at all — a materially different pattern from the dimension's
# original "conditional logic gated on env vars" definition (control flow
# that *branches* on environment state, e.g. a CI-detection evasion check).
# The model's actual behaviour was already correct and already safe — the
# corpus's one benign PyPI control with real env-var-reading code
# (`requests`, `os.environ.get('NETRC')`) scores this dimension 1.5/10, not
# 0, correctly distinguishing "reads a var for legitimate configuration"
# from "reads a var to exfiltrate it" even before this change — so this is
# a documentation correction to match validated behaviour, not a new
# behaviour being introduced. No weight change.
DIMENSIONS: list[dict[str, Any]] = [
    {
        "name": "network_calls",
        "label": "New or changed network calls",
        "weight": 0.20,
    },
    {
        "name": "obfuscation",
        "label": "Obfuscation / encoding patterns (base64, eval, dynamic require)",
        "weight": 0.20,
    },
    {
        "name": "install_hooks",
        "label": "Postinstall / preinstall script additions or changes",
        "weight": 0.15,
    },
    {
        "name": "env_conditional",
        "label": (
            "Conditional logic gated on env vars/platform/CI, or environment "
            "variables read/exfiltrated for credential theft"
        ),
        "weight": 0.15,
    },
    {
        "name": "dependency_changes",
        "label": "Dependency graph changes (new transitive deps)",
        "weight": 0.10,
    },
    {
        "name": "resource_exhaustion",
        "label": (
            "Denial-of-service / resource-exhaustion patterns "
            "(unbounded loops, recursion, unthrottled blocking calls)"
        ),
        "weight": 0.20,
    },
]


# ── Feed Results ──────────────────────────────────────────────────────────────


class FeedResult(BaseModel):
    """
    Normalised result from a single threat intelligence feed.

    All four feed clients (OSV, Rekor, Scorecard, new-dependency provenance)
    return this type so the aggregator and output modules have a uniform
    interface.
    """

    source: str = Field(
        description="Feed identifier: 'osv', 'rekor', 'scorecard', or 'new_deps'"
    )
    status: FeedStatus
    details: str = Field(description="Human-readable summary of the feed's finding")
    url: str | None = Field(
        default=None,
        description="Link to the advisory, attestation record, or scorecard report",
    )
    raw: dict[str, Any] | None = Field(
        default=None,
        description="Raw feed response — preserved for reproducibility and debugging",
        exclude=True,  # excluded from JSON report output by default
    )

    # OSV-specific: advisory IDs found for this package version
    advisory_ids: list[str] = Field(
        default_factory=list,
        description="OSV advisory IDs, e.g. ['MAL-2018-1', 'GHSA-...']",
    )

    # Rekor-specific: signing identity found (or not) for the package tarball
    signing_identity: str | None = Field(
        default=None,
        description="Email or URI of the Sigstore signing identity, if present",
    )
    signing_identity_changed: bool | None = Field(
        default=None,
        description="True if the signing identity differs from the previous version",
    )

    # Scorecard-specific: overall score
    scorecard_score: float | None = Field(
        default=None,
        ge=0.0,
        le=10.0,
        description="OpenSSF Scorecard composite score (0–10)",
    )


# ── Diff Summary ──────────────────────────────────────────────────────────────


class FileDiff(BaseModel):
    """Structured diff for a single file between the two package versions."""

    path: str
    change_type: str = Field(description="'added', 'removed', or 'modified'")
    lines_added: int = Field(ge=0)
    lines_removed: int = Field(ge=0)
    # The actual unified diff text — may be truncated by the chunker
    unified_diff: str | None = None


class DiffSummary(BaseModel):
    """
    High-level summary of what changed between the two package versions.

    Produced by the diff engine before the LLM sees anything. Stored in the
    report so researchers can validate the LLM's reasoning against the raw diff.
    """

    files_added: list[str] = Field(default_factory=list)
    files_removed: list[str] = Field(default_factory=list)
    files_modified: list[str] = Field(default_factory=list)
    file_diffs: list[FileDiff] = Field(default_factory=list)

    # Metadata-level changes (package.json / setup.py / pyproject.toml)
    new_dependencies: list[str] = Field(default_factory=list)
    removed_dependencies: list[str] = Field(default_factory=list)
    new_install_hooks: list[str] = Field(
        default_factory=list,
        description="e.g. ['postinstall', 'preinstall']",
    )
    maintainer_changed: bool = False
    native_addons_added: bool = False

    # Chunking metadata — important for reproducibility
    total_diff_lines: int = Field(default=0, ge=0)
    chunks_sent_to_llm: int = Field(default=1, ge=0)
    diff_truncated: bool = Field(
        default=False,
        description="True if the diff exceeded the token budget and was truncated",
    )

    # Diff-visibility fields (schema 0.3.0) — what the LLM did *not* see.
    # dataset/findings/README.md flagged that minified bundles get truncated
    # head-first, exactly where a payload tends to hide, and that the report
    # only carried a single boolean about it. These name the files so a
    # reader can judge the blind spot instead of guessing at it.
    truncated_files: list[str] = Field(
        default_factory=list,
        description=(
            "Files whose diff text was cut head-first at the per-chunk token "
            "budget by the chunker — the LLM never saw the omitted tail"
        ),
    )
    skipped_files: list[str] = Field(
        default_factory=list,
        description=(
            "Files never diffed at all because they exceed "
            "CHAINWATCH_MAX_DIFF_FILE_BYTES — the LLM saw only a placeholder notice"
        ),
    )
    large_files_split: bool = Field(
        default=False,
        description=(
            "True if --split-large-files was on: an oversized file diff is split "
            "into parts sent as separate chunks instead of being cut head-first"
        ),
    )
    split_files: list[str] = Field(
        default_factory=list,
        description=(
            "Files whose diff was split into parts across chunks "
            "(--split-large-files). Nothing omitted unless the file also appears "
            "in truncated_files, which means the per-file part cap was hit"
        ),
    )
    comments_stripped: bool = Field(
        default=False,
        description=(
            "True if comment lines were removed from the diff before LLM analysis "
            "(--strip-comments, the narrative-leakage control — see "
            "dataset/findings/README.md recommendation #8)"
        ),
    )
    comment_lines_stripped: int = Field(
        default=0,
        ge=0,
        description="How many diff lines --strip-comments removed (0 when not enabled)",
    )


# ── Score Modifiers ───────────────────────────────────────────────────────────


class ScoreModifier(BaseModel):
    """
    A single adjustment applied to the LLM base score — feed-driven (OSV,
    Rekor, Scorecard) or LLM-dimension-driven (``definitive_dimension_floor``,
    see ``analyzer/aggregator.py``).

    Recording every modifier makes the composite score decomposable after the
    fact:  ``llm_base_score + sum(m.delta for m in score_modifiers)`` equals the
    raw composite before it is clamped to [0, 100].  This closes the audit-trail
    gap the dataset FINDINGS flagged — a saved report now explains exactly how it
    moved from the LLM score to the final ``risk_score``.
    """

    source: str = Field(description="Feed or component that triggered it, e.g. 'osv', 'llm'")
    rule: str = Field(
        description="Modifier rule id, e.g. 'malicious_floor', 'scorecard_good'",
    )
    delta: float = Field(
        description="Signed points this modifier contributed to the composite score",
    )
    note: str = Field(description="Human-readable explanation of why it applied")


# ── Pipeline Timings ──────────────────────────────────────────────────────────


class PipelineTimings(BaseModel):
    """
    Wall-clock seconds spent in each pipeline stage for one report.

    Added 2026-09-09 because dataset/findings/README.md's "Latency" section
    could only cite hand-timed observations ("roughly 2.5 minutes") — the
    report JSON recorded no duration at all, so the before/after of the
    chunk-parallelisation change was never measurable from the corpus
    itself. These are observational, not a benchmark: they include network
    variance and API queueing, and a single run says little on its own.

    ``llm_seconds`` and ``feeds_seconds`` overlap in time — the two run
    concurrently — so ``analysis_seconds`` (the wall-clock of that
    concurrent stage) is roughly their max, not their sum.
    """

    fetch_seconds: float = Field(
        ge=0.0, description="Registry metadata + tarball download + extraction"
    )
    diff_seconds: float = Field(
        ge=0.0, description="Diff engine + preprocessing + chunking"
    )
    llm_seconds: float = Field(ge=0.0, description="All LLM chunk calls, end to end")
    feeds_seconds: float = Field(
        ge=0.0, description="All feed lookups, end to end (0 with --no-feeds)"
    )
    analysis_seconds: float = Field(
        ge=0.0, description="Wall-clock of the concurrent LLM + feeds stage"
    )
    total_seconds: float = Field(ge=0.0, description="Whole pipeline, fetch to report")


# ── Top-level Report ──────────────────────────────────────────────────────────


class RiskReport(BaseModel):
    """
    The complete chainwatch output for a single package version diff.

    This is the top-level document committed to ``dataset/`` and emitted by
    ``chainwatch diff``.  It is designed to be:

    - Self-contained: all inputs and outputs are recorded
    - Reproducible: schema_version + model + prompt_hash let you re-run identically
    - Citable: the dataset README maps each report to its ground-truth label
    """

    # ── Schema metadata ──────────────────────────────────────────────────────
    schema_version: str = Field(
        default=SCHEMA_VERSION,
        description="chainwatch schema version — bump on breaking changes",
    )

    # ── Package identity ─────────────────────────────────────────────────────
    ecosystem: Ecosystem
    package: str = Field(description="Package name as it appears in the registry")
    from_version: str = Field(description="Baseline version (the 'before')")
    to_version: str = Field(description="Target version under analysis (the 'after')")

    # ── Composite score ──────────────────────────────────────────────────────
    risk_score: float = Field(
        ge=0.0,
        le=100.0,
        description="Composite 0–100 risk score from the aggregator",
    )
    severity: Severity
    llm_base_score: float | None = Field(
        default=None,
        ge=0.0,
        le=100.0,
        description=(
            "Composite 0–100 score from the LLM dimensions alone, before feed "
            "modifiers. None for reports produced before the field existed."
        ),
    )

    # ── Per-dimension LLM scores ─────────────────────────────────────────────
    dimensions: list[RiskDimension] = Field(
        description="One entry per risk dimension, in the order defined in DIMENSIONS",
    )

    # ── Feed results ─────────────────────────────────────────────────────────
    feed_results: list[FeedResult] = Field(
        description="One entry per feed: osv, rekor, scorecard, new_deps",
    )

    # ── Score decomposition ──────────────────────────────────────────────────
    score_modifiers: list[ScoreModifier] = Field(
        default_factory=list,
        description="Feed-driven adjustments applied to llm_base_score to reach risk_score",
    )

    # ── Evidence caveats ─────────────────────────────────────────────────────
    caveats: list[str] = Field(
        default_factory=list,
        description=(
            "Machine-generated statements about evidence the LLM did not see or "
            "scored under a known limitation (truncated or skipped files, "
            "multi-chunk scoring, stripped comments). Empty when the whole diff "
            "was visible in one chunk. Built by analyzer/aggregator.py from "
            "diff_summary — never from the LLM's own output."
        ),
    )

    # ── Diff summary ─────────────────────────────────────────────────────────
    diff_summary: DiffSummary

    # ── LLM metadata ─────────────────────────────────────────────────────────
    llm_model: str = Field(description="Model string used for analysis")
    llm_summary: str = Field(
        description="Free-text summary written by the LLM explaining its overall assessment"
    )

    # ── Provenance ───────────────────────────────────────────────────────────
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="UTC timestamp of when this report was generated",
    )
    from_version_sha256: str | None = Field(
        default=None,
        description="SHA256 of the downloaded from_version tarball — corpus integrity check",
    )
    to_version_sha256: str | None = Field(
        default=None,
        description="SHA256 of the downloaded to_version tarball — corpus integrity check",
    )
    timings: PipelineTimings | None = Field(
        default=None,
        description=(
            "Per-stage wall-clock durations for this run. None for reports "
            "produced before schema 0.3.0 and for reports re-rendered from disk."
        ),
    )

    # ── Validators ───────────────────────────────────────────────────────────

    @field_validator("dimensions")
    @classmethod
    def dimensions_must_have_weights_summing_to_one(
        cls, v: list[RiskDimension]
    ) -> list[RiskDimension]:
        total = sum(d.weight for d in v)
        if v and not (0.99 <= total <= 1.01):
            raise ValueError(
                f"Dimension weights must sum to 1.0, got {total:.3f}. "
                "Check DIMENSIONS in models.py and the aggregator weight matrix."
            )
        return v

    @model_validator(mode="after")
    def severity_must_match_score(self) -> RiskReport:
        expected = Severity.LOW
        if self.risk_score >= 80:
            expected = Severity.CRITICAL
        elif self.risk_score >= 55:
            expected = Severity.HIGH
        elif self.risk_score >= 30:
            expected = Severity.MEDIUM
        if self.severity != expected:
            raise ValueError(
                f"severity={self.severity!r} does not match "
                f"risk_score={self.risk_score} (expected {expected!r}). "
                "Use Severity.from_score() or let the aggregator set both."
            )
        return self

    # ── Helpers ───────────────────────────────────────────────────────────────

    @classmethod
    def severity_for_score(cls, score: float) -> Severity:
        """Canonical mapping from composite score to severity bucket."""
        if score >= 80:
            return Severity.CRITICAL
        if score >= 55:
            return Severity.HIGH
        if score >= 30:
            return Severity.MEDIUM
        return Severity.LOW

    def confirmed_malicious_by_feed(self) -> bool:
        """True if any feed returned status=malicious (e.g. OSV MAL-* entry)."""
        return any(f.status == FeedStatus.malicious for f in self.feed_results)

    def has_mal_advisory(self) -> bool:
        """True if OSV returned at least one MAL-* prefixed advisory ID."""
        for feed in self.feed_results:
            if feed.source == "osv":
                return any(aid.startswith("MAL-") for aid in feed.advisory_ids)
        return False


# ── Scan Results ─────────────────────────────────────────────────────────────


class ScanEntry(BaseModel):
    """
    One row of a ``chainwatch scan`` run: either a completed diff report or
    a per-package failure.

    A lockfile can name dozens of packages; one of them being unreachable
    (deleted from the registry, a transient network error, no earlier
    version to diff against, ...) must not abort the whole scan — see
    ``chainwatch.scanner.scan_dependencies``. Exactly one of ``report`` /
    ``error`` is set.
    """

    package: str = Field(description="Package name as found in the lockfile")
    from_version: str | None = Field(
        default=None,
        description="Version diffed against — the one published immediately "
        "before to_version. None if no diff was attempted.",
    )
    to_version: str = Field(description="The version pinned in the lockfile")
    report: RiskReport | None = Field(
        default=None,
        description="The full risk report, or None if this entry failed",
    )
    error: str | None = Field(
        default=None,
        description="Human-readable failure reason, or None on success",
    )
