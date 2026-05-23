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

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

SCHEMA_VERSION = "0.1.0"


# ── Enumerations ──────────────────────────────────────────────────────────────


class Ecosystem(str, Enum):
    """Package registry ecosystems supported by chainwatch."""

    npm = "npm"
    pypi = "pypi"


class Severity(str, Enum):
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


class FeedStatus(str, Enum):
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

    @property
    def weighted_contribution(self) -> float:
        """Contribution to the 0-100 composite score from this dimension alone."""
        return self.score * self.weight * 10.0


# Default dimension definitions — these match the prompt schema in analyzer/llm.py.
# Defined here so models.py remains the single source of truth for the schema.
DIMENSIONS: list[dict[str, Any]] = [
    {
        "name": "network_calls",
        "label": "New or changed network calls",
        "weight": 0.25,
    },
    {
        "name": "obfuscation",
        "label": "Obfuscation / encoding patterns (base64, eval, dynamic require)",
        "weight": 0.25,
    },
    {
        "name": "install_hooks",
        "label": "Postinstall / preinstall script additions or changes",
        "weight": 0.20,
    },
    {
        "name": "env_conditional",
        "label": "Conditional logic gated on env vars, platform, or CI detection",
        "weight": 0.15,
    },
    {
        "name": "dependency_changes",
        "label": "Dependency graph changes (new transitive deps)",
        "weight": 0.15,
    },
]


# ── Feed Results ──────────────────────────────────────────────────────────────


class FeedResult(BaseModel):
    """
    Normalised result from a single threat intelligence feed.

    All three feed clients (OSV, Rekor, Scorecard) return this type so the
    aggregator and output modules have a uniform interface.
    """

    source: str = Field(description="Feed identifier: 'osv', 'rekor', or 'scorecard'")
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

    # ── Per-dimension LLM scores ─────────────────────────────────────────────
    dimensions: list[RiskDimension] = Field(
        description="One entry per risk dimension, in the order defined in DIMENSIONS",
    )

    # ── Feed results ─────────────────────────────────────────────────────────
    feed_results: list[FeedResult] = Field(
        description="One entry per feed: osv, rekor, scorecard",
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
        default_factory=lambda: datetime.now(timezone.utc),
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
    def severity_must_match_score(self) -> "RiskReport":
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
