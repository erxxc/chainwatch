"""
chainwatch.config
~~~~~~~~~~~~~~~~~

All runtime configuration lives here.  Settings are loaded from environment
variables (with optional ``.env`` file via python-dotenv) using pydantic-settings.

Design rationale:
- One ``Settings`` object, created once at import time via ``get_settings()``.
- All secrets come from env — never from config files committed to the repo.
- Every setting has a sensible default so the tool works out of the box once
  ``ANTHROPIC_API_KEY`` is set.
- URLs are overridable for testing against mirrors, proxies, or mock servers.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    chainwatch runtime settings.

    Loaded from environment variables with the prefix ``CHAINWATCH_``
    (except ANTHROPIC_API_KEY which has no prefix, matching the SDK convention).

    Example .env file: see .env.example in the repo root.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="CHAINWATCH_",
        # ANTHROPIC_API_KEY has no CHAINWATCH_ prefix — handled via alias below
        extra="ignore",
    )

    # ── Required ─────────────────────────────────────────────────────────────

    anthropic_api_key: SecretStr = Field(
        alias="ANTHROPIC_API_KEY",
        description="Anthropic API key. Required for LLM analysis.",
    )

    # ── LLM ──────────────────────────────────────────────────────────────────

    model: str = Field(
        default="claude-sonnet-4-6",
        description="Anthropic model string to use for diff analysis.",
    )

    # Token budget *per file chunk* sent to the LLM.
    # The chunker will split diffs so no single call exceeds this.
    # Keeping this well below the model's context limit leaves room for the
    # system prompt, schema definition, and response.
    max_tokens_per_chunk: int = Field(
        default=8_000,
        ge=1_000,
        le=50_000,
        description="Token budget per file chunk sent to the LLM.",
    )

    # Max tokens requested in the LLM *response*
    max_response_tokens: int = Field(
        default=4_096,
        ge=256,
        le=8_192,
    )

    # ── HTTP ─────────────────────────────────────────────────────────────────

    http_timeout: float = Field(
        default=30.0,
        ge=5.0,
        description="Timeout in seconds for all external HTTP requests.",
    )

    max_retries: int = Field(
        default=3,
        ge=0,
        le=10,
        description="Max retry attempts on rate-limited or transient API failures.",
    )

    max_download_bytes: int = Field(
        default=100 * 1024 * 1024,
        ge=1 * 1024 * 1024,
        description="Maximum compressed archive bytes downloaded per package version.",
    )

    max_extracted_bytes: int = Field(
        default=500 * 1024 * 1024,
        ge=1 * 1024 * 1024,
        description="Maximum total extracted file bytes per package version.",
    )

    max_archive_files: int = Field(
        default=25_000,
        ge=1,
        description="Maximum number of files allowed in a package archive.",
    )

    max_archive_file_bytes: int = Field(
        default=50 * 1024 * 1024,
        ge=1,
        description="Maximum extracted size of any single archive member.",
    )

    max_diff_file_bytes: int = Field(
        default=2 * 1024 * 1024,
        ge=1_024,
        description="Maximum source file bytes read into the diff engine.",
    )

    allowed_archive_hosts: str | None = Field(
        default=None,
        description=(
            "Comma-separated additional hosts permitted for package archive downloads."
        ),
    )

    # ── Registry URLs ─────────────────────────────────────────────────────────

    npm_registry: str = Field(
        default="https://registry.npmjs.org",
        description="npm registry base URL. Override for testing or mirrors.",
    )

    pypi_registry: str = Field(
        default="https://pypi.org/pypi",
        description="PyPI JSON API base URL.",
    )

    # ── Feed API URLs ─────────────────────────────────────────────────────────

    osv_api: str = Field(
        default="https://api.osv.dev/v1",
        description="OSV.dev API base URL.",
    )

    rekor_api: str = Field(
        default="https://rekor.sigstore.dev",
        description="Rekor transparency log API base URL.",
    )

    scorecard_api: str = Field(
        default="https://api.securityscorecards.dev",
        description="OpenSSF Scorecard API base URL.",
    )

    # ── Validators ───────────────────────────────────────────────────────────

    @field_validator("npm_registry", "pypi_registry", "osv_api", "rekor_api", "scorecard_api")
    @classmethod
    def url_must_not_have_trailing_slash(cls, v: str) -> str:
        return v.rstrip("/")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """
    Return the singleton Settings instance.

    Cached after first call — safe to call from anywhere without worrying
    about repeated env-file parsing.  In tests, call ``get_settings.cache_clear()``
    before patching env vars.
    """
    return Settings()  # type: ignore[call-arg]
