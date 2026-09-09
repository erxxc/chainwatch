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
  we record ``diff_truncated=True`` (and, since schema 0.3.0, the file
  names in ``truncated_files``) in the report so the reader knows.

Opt-in alternative (``split_large_files=True``, ``--split-large-files``):
  A file diff larger than one chunk is split into consecutive parts, each
  sent as its own chunk, instead of being cut head-first. Nothing is
  omitted, but no single LLM call sees the file whole, and each part costs
  a call — so the number of parts per file is capped
  (``max_parts_per_file``, ``CHAINWATCH_MAX_SPLIT_PARTS_PER_FILE``) and the
  remainder past the cap is truncated with the same bookkeeping as above.
  This exists because dataset/findings/README.md notes that minified
  bundles get cut exactly where a payload tends to hide; the default stays
  head-first truncation so existing corpus numbers keep their meaning.

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

# Split mode: default cap on parts per file (a real 2 MB minified bundle at
# the default 8k-token budget would otherwise be ~64 LLM calls on its own).
DEFAULT_MAX_PARTS_PER_FILE: int = 16

# Split mode: room left in each part for the "(continued)" marker, the
# part header, and the code fences, so a part plus the preamble still fits
# in one chunk. Sized generously; the exact overhead is a few dozen chars.
_PART_OVERHEAD_CHARS: int = 300
_PART_HEADER_ROOM: int = 200


def chunk_diff(
    diff: DiffSummary,
    max_tokens_per_chunk: int,
    *,
    split_large_files: bool = False,
    max_parts_per_file: int = DEFAULT_MAX_PARTS_PER_FILE,
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
        split_large_files:    Split an oversized file diff into parts across
                              chunks instead of truncating it head-first.
        max_parts_per_file:   Split mode only — parts per file before the
                              remainder is truncated (bounds LLM spend).

    Returns:
        List of text strings, one per chunk.  Typically just one item for
        normal-sized packages.  Multiple items for very large diffs.

    Side effect:
        Sets ``diff.diff_truncated = True`` if any file content was truncated,
        and ``diff.truncated_files`` to the paths that were cut (so the report
        can say *which* files the LLM only partially saw).
        Sets ``diff.chunks_sent_to_llm`` to the number of chunks produced.
        In split mode, sets ``diff.large_files_split = True`` and
        ``diff.split_files`` to the paths that were split into parts.
    """
    budget_chars = max_tokens_per_chunk * CHARS_PER_TOKEN

    # ── Build the metadata preamble (always included, never truncated) ────────
    preamble = _build_metadata_preamble(diff)

    # ── Build per-file diff blocks ────────────────────────────────────────────
    file_blocks: list[str] = []
    truncated = False
    truncated_files: list[str] = []
    split_files: list[str] = []
    piece_chars = max(budget_chars - len(preamble) - _PART_OVERHEAD_CHARS, budget_chars // 2)

    for file_diff in diff.file_diffs:
        block = _format_file_diff(file_diff)
        if len(block) > budget_chars and split_large_files:
            parts, part_truncated = _split_file_diff(
                file_diff, piece_chars=piece_chars, max_parts=max_parts_per_file,
            )
            file_blocks.extend(parts)
            split_files.append(file_diff.path)
            if part_truncated:
                truncated = True
                truncated_files.append(file_diff.path)
            log.info(
                "File %s diff split into %d part(s)%s",
                file_diff.path,
                len(parts),
                " (capped, remainder truncated)" if part_truncated else "",
            )
            continue
        # If a single file's diff exceeds the per-chunk budget, truncate it.
        # Head-first: the LLM sees the start of the file and loses the tail.
        # The report names the file in ``truncated_files`` and the aggregator
        # turns that into a caveat, so nobody has to guess what was cut.
        if len(block) > budget_chars:
            original_len = len(block)
            max_chars = budget_chars - 200  # leave room for truncation notice
            block = (
                block[:max_chars]
                + f"\n[... diff truncated head-first at the {max_tokens_per_chunk}-token "
                f"chunk budget: {max_chars} of {original_len} chars shown, "
                f"{original_len - max_chars} omitted ...]\n"
            )
            truncated = True
            truncated_files.append(file_diff.path)
            log.warning(
                "File %s diff truncated from %d to ~%d chars",
                file_diff.path, original_len, max_chars,
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
    diff.truncated_files = truncated_files
    diff.large_files_split = split_large_files
    diff.split_files = split_files
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

    if diff.comments_stripped:
        lines.append(
            f"Note: {diff.comment_lines_stripped} comment line(s) were removed from the "
            "file diffs below before analysis; only executable code is shown."
        )
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


def _split_file_diff(
    file_diff: FileDiff,
    *,
    piece_chars: int,
    max_parts: int,
) -> tuple[list[str], bool]:
    """
    Split one oversized file diff into labelled parts, each within ``piece_chars``.

    Splits on line boundaries where possible; a single line longer than the
    budget (the normal shape of a minified bundle) is hard-split so nothing
    is silently dropped. Returns the formatted parts and whether the
    ``max_parts`` cap forced the remainder to be truncated.
    """
    body = file_diff.unified_diff or "(no diff content)"
    segments = _segment_lines(body, max(piece_chars - _PART_HEADER_ROOM, 1))

    part_truncated = False
    if len(segments) > max_parts:
        omitted = sum(len(segment) + 1 for segment in segments[max_parts:])
        segments = segments[:max_parts]
        segments[-1] += (
            f"\n[... remaining {omitted} chars of this file omitted: --split-large-files "
            f"is capped at {max_parts} part(s) per file "
            "(CHAINWATCH_MAX_SPLIT_PARTS_PER_FILE) ...]"
        )
        part_truncated = True

    total = len(segments)
    parts: list[str] = []
    for index, segment in enumerate(segments, start=1):
        header = (
            f"## {file_diff.change_type.upper()}: {file_diff.path} "
            f"(part {index}/{total} — this file's diff was split across chunks)\n"
            f"## +{file_diff.lines_added} lines  -{file_diff.lines_removed} lines "
            "(counts are for the whole file)\n"
        )
        parts.append(header + "```diff\n" + segment + "\n```\n")
    return parts, part_truncated


def _segment_lines(body: str, limit: int) -> list[str]:
    """Group ``body``'s lines into segments of at most ``limit`` chars each."""
    segments: list[str] = []
    current: list[str] = []
    size = 0
    for line in body.split("\n"):
        pieces = [line[i:i + limit] for i in range(0, len(line), limit)] or [""]
        for piece in pieces:
            if current and size + len(piece) + 1 > limit:
                segments.append("\n".join(current))
                current, size = [], 0
            current.append(piece)
            size += len(piece) + 1
    if current or not segments:
        segments.append("\n".join(current))
    return segments
