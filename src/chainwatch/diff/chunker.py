"""
chainwatch.diff.chunker
~~~~~~~~~~~~~~~~~~~~~~~

Splits a ``DiffSummary`` into chunks that fit within the LLM token budget.

Strategy (Option A from the design discussion):
  Truncate with a token budget per file, preserve the metadata diff in full.

  Rationale: for a research tool, the most important property is knowing
  *exactly* what the LLM saw.  Sliding-window aggregation makes the
  "what input produced this output?" question harder to answer for
  reproducibility.  We accept that very large files may be truncated, and
  we record ``diff_truncated=True`` in the report so the reader knows.

Token estimation:
  We use a simple character-based approximation: 1 token ≈ 4 characters.
  This is conservative (real tokenisers are slightly more efficient) which
  means we err on the side of sending less context rather than hitting the
  API limit.  A future iteration can swap in the ``tiktoken`` library for
  exact counts without changing the interface.

The chunker is a pure function — no I/O, no API calls.  Straightforward to
test and reason about.
"""

from __future__ import annotations

import logging

from chainwatch.models import DiffSummary, FileDiff

log = logging.getLogger(__name__)

# Characters per token (conservative approximation)
CHARS_PER_TOKEN: int = 4


def chunk_diff(
    diff: DiffSummary,
    max_tokens_per_chunk: int,
) -> list[str]:
    """
    Convert a DiffSummary into a list of text chunks, each within the token budget.

    Each chunk is a self-contained text block suitable for including directly
    in an LLM prompt.  The first chunk always includes the metadata summary
    (dependencies, hooks, etc.) so the LLM has structural context even if
    file content is truncated.

    Args:
        diff:                 The full diff summary from the engine.
        max_tokens_per_chunk: Maximum tokens allowed per chunk (from Settings).

    Returns:
        List of text strings, one per chunk.  Typically just one item for
        normal-sized packages.  Multiple items for very large diffs.

    Side effect:
        Sets ``diff.diff_truncated = True`` if any file content was truncated.
        Sets ``diff.chunks_sent_to_llm`` to the number of chunks produced.
    """
    budget_chars = max_tokens_per_chunk * CHARS_PER_TOKEN

    # ── Build the metadata preamble (always included, never truncated) ────────
    preamble = _build_metadata_preamble(diff)

    # ── Build per-file diff blocks ────────────────────────────────────────────
    file_blocks: list[str] = []
    truncated = False

    for file_diff in diff.file_diffs:
        block = _format_file_diff(file_diff)
        # If a single file's diff exceeds the per-chunk budget, truncate it
        if len(block) > budget_chars:
            max_chars = budget_chars - 200  # leave room for truncation notice
            block = block[:max_chars] + f"\n[... diff truncated at {max_tokens_per_chunk} token budget ...]\n"
            truncated = True
            log.warning(
                "File %s diff truncated from %d to ~%d chars",
                file_diff.path, len(block), max_chars,
            )
        file_blocks.append(block)

    # ── Assemble chunks ───────────────────────────────────────────────────────
    chunks: list[str] = []
    current_chunk = preamble
    current_size = len(preamble)

    for block in file_blocks:
        if current_size + len(block) > budget_chars and current_size > len(preamble):
            # Current chunk is full — start a new one (still include preamble for context)
            chunks.append(current_chunk)
            current_chunk = preamble + "\n# (continued)\n" + block
            current_size = len(current_chunk)
        else:
            current_chunk += "\n" + block
            current_size += len(block)

    chunks.append(current_chunk)

    # ── Update diff summary with chunking metadata ─────────────────────────────
    diff.diff_truncated = truncated
    diff.chunks_sent_to_llm = len(chunks)

    log.info(
        "Chunker produced %d chunk(s), truncated=%s, total chars=%d",
        len(chunks), truncated, sum(len(c) for c in chunks),
    )
    return chunks


# ── Internal helpers ──────────────────────────────────────────────────────────


def _build_metadata_preamble(diff: DiffSummary) -> str:
    """
    Build a structured text block describing the metadata-level changes.

    This is always the first content in every chunk so the LLM has
    structural context regardless of how many file chunks there are.
    """
    lines = ["# Package Diff — Metadata Summary", ""]

    lines.append(f"Files added:    {len(diff.files_added)}")
    lines.append(f"Files removed:  {len(diff.files_removed)}")
    lines.append(f"Files modified: {len(diff.files_modified)}")
    lines.append(f"Total changed lines: {diff.total_diff_lines}")
    lines.append("")

    if diff.files_added:
        lines.append("## New files")
        for f in diff.files_added:
            lines.append(f"  + {f}")
        lines.append("")

    if diff.files_removed:
        lines.append("## Removed files")
        for f in diff.files_removed:
            lines.append(f"  - {f}")
        lines.append("")

    if diff.new_dependencies:
        lines.append("## New dependencies added")
        for dep in diff.new_dependencies:
            lines.append(f"  + {dep}")
        lines.append("")

    if diff.removed_dependencies:
        lines.append("## Dependencies removed")
        for dep in diff.removed_dependencies:
            lines.append(f"  - {dep}")
        lines.append("")

    if diff.new_install_hooks:
        lines.append("## ⚠ New install hooks detected")
        for hook in diff.new_install_hooks:
            lines.append(f"  + {hook}")
        lines.append("")

    if diff.maintainer_changed:
        lines.append("## ⚠ Maintainer field changed between versions")
        lines.append("")

    if diff.native_addons_added:
        lines.append("## ⚠ Native addon (binding.gyp / .node file) added")
        lines.append("")

    lines.append("# File-level diffs follow")
    lines.append("")

    return "\n".join(lines)


def _format_file_diff(file_diff: FileDiff) -> str:
    """Format a single FileDiff as a labelled text block for the LLM prompt."""
    header = (
        f"## {file_diff.change_type.upper()}: {file_diff.path}\n"
        f"## +{file_diff.lines_added} lines  -{file_diff.lines_removed} lines\n"
    )
    body = file_diff.unified_diff or "(no diff content)"
    return header + "```diff\n" + body + "\n```\n"
