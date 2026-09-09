"""
chainwatch.diff.preprocess
~~~~~~~~~~~~~~~~~~~~~~~~~~

Optional transformations applied to a ``DiffSummary`` between the diff
engine and the chunker.  Nothing here runs by default.

Currently one transformation: **comment stripping**, an experimental control
for the narrative-leakage finding in dataset/findings/README.md
(recommendation #8). That finding measured 20–28.5 points of a report's
score coming from descriptive prose sitting inside a diff — header comments
describing an attack — rather than from any code being analysed. The
controlled comparison that produced the number had to be assembled by hand
(placeholder files vs. empty stub files). ``--strip-comments`` makes the
"same code, no prose" condition a one-flag rerun instead, so the effect can
be measured on any pair in the corpus, not just the one it was noticed on.

Design constraints, in priority order:

1. **Never strip code.** A false strip silently removes evidence, which is
   worse than a missed comment. So only lines that *begin* with a comment
   token (after the diff marker and leading whitespace) are candidates;
   trailing comments after code on the same line are left alone, and a
   block comment is only removed when its closing token is found inside the
   same diff hunk with nothing but whitespace after it.
2. **Keep the diff structure intact.** Hunk headers (``@@``), file headers
   (``---``/``+++``), and the ``+``/``-``/`` `` markers on every remaining
   line are preserved verbatim. Hunk line counts in ``@@`` headers are
   *not* recomputed — the LLM reads them as labels, not offsets.
3. **Record what happened.** ``DiffSummary.comments_stripped`` and
   ``comment_lines_stripped`` are set so the report says the LLM scored
   code only, and the chunker's preamble tells the LLM the same thing.

Known limits (documented, deliberate):

- Python docstrings are only stripped when the triple-quote sits at the
  start of a line, which catches module/class/function docstrings and
  bare string-expression "comments" but not ``x = '''...'''`` (an assignment).
- Inline trailing comments (``code(); // note``) are kept.
- A block comment whose opener sits in a previous hunk (so only ``*``
  continuation lines and the ``*/`` closer are visible) is kept, because
  the opener can't be verified.
- ``lines_added``/``lines_removed`` and ``total_diff_lines`` still describe
  the *real* change, not the stripped text; ``comment_lines_stripped`` is
  the correction term.
"""

from __future__ import annotations

import logging
from pathlib import PurePosixPath

from chainwatch.models import DiffSummary, FileDiff

log = logging.getLogger(__name__)

_JS_EXTS = frozenset({".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"})
_PY_EXTS = frozenset({".py", ".pyi"})

# Tokens a line must *start* with (after the diff marker and whitespace) to be
# treated as a whole-line comment. Compared case-insensitively for batch files
# only — ``REM``/``rem``/``Rem`` are all valid there.
_LINE_COMMENT_TOKENS: dict[str, tuple[str, ...]] = {
    **{ext: ("//",) for ext in _JS_EXTS},
    **{ext: ("#",) for ext in _PY_EXTS},
    ".sh": ("#",),
    ".ps1": ("#",),
    ".bat": ("rem ", "rem\t", "::"),
    ".cmd": ("rem ", "rem\t", "::"),
}
_CASE_INSENSITIVE_EXTS = frozenset({".bat", ".cmd"})

# (opener, closer) pairs. A block is stripped only when the opener starts a
# line and the closer is found on that line or a later line *within the same
# hunk*, with nothing but whitespace after it.
_BLOCK_COMMENT_TOKENS: dict[str, tuple[tuple[str, str], ...]] = {
    **{ext: (("/*", "*/"),) for ext in _JS_EXTS},
    **{ext: (('"""', '"""'), ("'''", "'''")) for ext in _PY_EXTS},
    ".ps1": (("<#", "#>"),),
}

# A "#" line that is not a comment: shebangs must survive in shell/Python.
_KEEP_PREFIXES: tuple[str, ...] = ("#!",)

_SKIPPED_DIFF_PREFIX = "[diff skipped"
_DIFF_MARKERS = ("+", "-", " ")


def strip_comment_lines(diff: DiffSummary) -> int:
    """
    Remove whole-line comments from every ``FileDiff`` in ``diff``, in place.

    Returns the number of diff lines removed and records it (plus the
    ``comments_stripped`` flag) on ``diff`` itself so the report carries the
    correction term. Files with no recognised comment syntax, skipped
    (oversized) diffs, and empty diffs are left untouched.
    """
    total = 0
    for file_diff in diff.file_diffs:
        total += _strip_file_diff(file_diff)

    diff.comments_stripped = True
    diff.comment_lines_stripped = total
    log.info(
        "Comment stripping removed %d line(s) across %d file diff(s)",
        total,
        len(diff.file_diffs),
    )
    return total


def _strip_file_diff(file_diff: FileDiff) -> int:
    text = file_diff.unified_diff
    if not text or text.startswith(_SKIPPED_DIFF_PREFIX):
        return 0

    ext = PurePosixPath(file_diff.path).suffix.lower()
    line_tokens = _LINE_COMMENT_TOKENS.get(ext, ())
    block_tokens = _BLOCK_COMMENT_TOKENS.get(ext, ())
    if not line_tokens and not block_tokens:
        return 0

    lines = text.split("\n")
    kept: list[str] = []
    removed = 0

    # Process hunk by hunk so a block comment can't be "closed" by a line
    # from a different, non-contiguous region of the file.
    for hunk in _split_hunks(lines):
        if hunk.is_header:
            kept.extend(hunk.lines)
            continue
        to_drop = _comment_line_indices(hunk.lines, ext, line_tokens, block_tokens)
        for index, line in enumerate(hunk.lines):
            if index in to_drop:
                removed += 1
            else:
                kept.append(line)

    if removed:
        file_diff.unified_diff = "\n".join(kept)
    return removed


class _Hunk:
    __slots__ = ("is_header", "lines")

    def __init__(self, *, is_header: bool) -> None:
        self.is_header = is_header
        self.lines: list[str] = []


def _is_diff_header(line: str) -> bool:
    return line.startswith(("--- ", "+++ ", "@@ "))


def _split_hunks(lines: list[str]) -> list[_Hunk]:
    """Group diff lines into alternating header / body runs."""
    hunks: list[_Hunk] = []
    current: _Hunk | None = None
    for line in lines:
        header = _is_diff_header(line)
        if current is None or current.is_header != header:
            current = _Hunk(is_header=header)
            hunks.append(current)
        current.lines.append(line)
    return hunks


def _content(line: str) -> str | None:
    """The source text behind a diff line's marker, or None for non-body lines."""
    if not line or line[0] not in _DIFF_MARKERS:
        return None
    return line[1:]


def _comment_line_indices(
    lines: list[str],
    ext: str,
    line_tokens: tuple[str, ...],
    block_tokens: tuple[tuple[str, str], ...],
) -> set[int]:
    drop: set[int] = set()
    index = 0
    while index < len(lines):
        content = _content(lines[index])
        if content is None:
            index += 1
            continue
        stripped = content.strip()
        if not stripped or stripped.startswith(_KEEP_PREFIXES):
            index += 1
            continue

        block_end = _block_comment_end(lines, index, stripped, block_tokens)
        if block_end is not None:
            drop.update(range(index, block_end + 1))
            index = block_end + 1
            continue

        if _is_line_comment(stripped, ext, line_tokens):
            drop.add(index)
        index += 1
    return drop


def _is_line_comment(stripped: str, ext: str, tokens: tuple[str, ...]) -> bool:
    probe = stripped.lower() if ext in _CASE_INSENSITIVE_EXTS else stripped
    return any(probe.startswith(token) for token in tokens)


def _block_comment_end(
    lines: list[str],
    start: int,
    stripped: str,
    block_tokens: tuple[tuple[str, str], ...],
) -> int | None:
    """
    If ``lines[start]`` opens a block comment that closes cleanly within this
    hunk, return the index of the closing line; otherwise None.
    """
    for opener, closer in block_tokens:
        if not stripped.startswith(opener):
            continue
        rest = stripped[len(opener):]
        if closer in rest:
            after = rest.split(closer, 1)[1]
            return start if not after.strip() else None
        for index in range(start + 1, len(lines)):
            content = _content(lines[index])
            if content is None:
                return None  # hunk structure broke — don't guess
            if closer in content:
                after = content.split(closer, 1)[1]
                return index if not after.strip() else None
        return None
    return None
