"""
chainwatch.diff.engine
~~~~~~~~~~~~~~~~~~~~~~

Computes a structured diff between two extracted package directories.

The engine:
  1. Enumerates source files (filtered to .js / .ts / .py / .mjs / .cjs)
  2. Categorises each file as added, removed, or modified
  3. Computes a unified diff for each modified/added file
  4. Extracts metadata-level changes (package.json, setup.py, pyproject.toml)
  5. Returns a ``DiffSummary`` — the raw input to the chunker and LLM

The engine is a pure function over two directories — no I/O beyond reading
files.  This makes it straightforward to test with fixture directories.

Stub status: PARTIAL STUB
  File enumeration and categorisation are real.  Unified diff generation and
  metadata extraction have stub implementations that return plausible-looking
  output.  These will be replaced in Day 1 Part 2.
"""

from __future__ import annotations

import difflib
import json
import logging
from pathlib import Path

from chainwatch.models import DiffSummary, FileDiff

log = logging.getLogger(__name__)

# Source file extensions we send to the LLM.
# Binary files, images, lock files, etc. are excluded.
SOURCE_EXTENSIONS: frozenset[str] = frozenset(
    {".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx", ".py", ".pyi"}
)

# Metadata files we parse for dependency/hook changes
METADATA_FILES: frozenset[str] = frozenset(
    {"package.json", "setup.py", "setup.cfg", "pyproject.toml"}
)


def compute_diff(from_dir: Path, to_dir: Path) -> DiffSummary:
    """
    Compute a structured diff between two extracted package directories.

    Args:
        from_dir: Extracted baseline version directory
        to_dir:   Extracted target version directory

    Returns:
        DiffSummary — the input contract for ``diff.chunker`` and ``analyzer.llm``
    """
    log.debug("Computing diff: %s → %s", from_dir, to_dir)

    from_files = _enumerate_source_files(from_dir)
    to_files = _enumerate_source_files(to_dir)

    from_paths = set(from_files)
    to_paths = set(to_files)

    added = sorted(to_paths - from_paths)
    removed = sorted(from_paths - to_paths)
    common = sorted(from_paths & to_paths)

    file_diffs: list[FileDiff] = []
    modified: list[str] = []

    for rel_path in common:
        from_text = (from_dir / rel_path).read_text(errors="replace")
        to_text = (to_dir / rel_path).read_text(errors="replace")
        if from_text == to_text:
            continue  # unchanged
        modified.append(rel_path)
        diff = _unified_diff(from_text, to_text, rel_path)
        file_diffs.append(diff)

    # Add new files as diffs too (all lines are additions)
    for rel_path in added:
        content = (to_dir / rel_path).read_text(errors="replace")
        lines = content.splitlines()
        file_diffs.append(FileDiff(
            path=rel_path,
            change_type="added",
            lines_added=len(lines),
            lines_removed=0,
            unified_diff="\n".join(f"+{l}" for l in lines),
        ))

    total_lines = sum(
        (f.lines_added + f.lines_removed) for f in file_diffs
    )

    # Metadata extraction
    meta = _extract_metadata_diff(from_dir, to_dir)

    summary = DiffSummary(
        files_added=added,
        files_removed=removed,
        files_modified=modified,
        file_diffs=file_diffs,
        total_diff_lines=total_lines,
        **meta,
    )

    log.info(
        "Diff complete: +%d -%d ~%d files, %d total changed lines",
        len(added), len(removed), len(modified), total_lines,
    )
    return summary


# ── Internal helpers ──────────────────────────────────────────────────────────


def _enumerate_source_files(directory: Path) -> list[str]:
    """
    Return relative paths of all source files in a directory.

    Filters to SOURCE_EXTENSIONS only.  Paths are normalised with forward
    slashes for cross-platform reproducibility.
    """
    result = []
    for path in directory.rglob("*"):
        if path.is_file() and path.suffix.lower() in SOURCE_EXTENSIONS:
            rel = path.relative_to(directory)
            result.append(str(rel).replace("\\", "/"))
    return result


def _unified_diff(from_text: str, to_text: str, path: str) -> FileDiff:
    """Compute a unified diff between two file contents."""
    from_lines = from_text.splitlines(keepends=True)
    to_lines = to_text.splitlines(keepends=True)

    diff_lines = list(difflib.unified_diff(
        from_lines,
        to_lines,
        fromfile=f"a/{path}",
        tofile=f"b/{path}",
        lineterm="",
    ))

    lines_added = sum(1 for l in diff_lines if l.startswith("+") and not l.startswith("+++"))
    lines_removed = sum(1 for l in diff_lines if l.startswith("-") and not l.startswith("---"))

    return FileDiff(
        path=path,
        change_type="modified",
        lines_added=lines_added,
        lines_removed=lines_removed,
        unified_diff="\n".join(diff_lines),
    )


def _extract_metadata_diff(from_dir: Path, to_dir: Path) -> dict:
    """
    Compare package metadata files between versions.

    Currently implements package.json parsing.  setup.py / pyproject.toml
    parsing is stubbed — they return empty results.

    Returns a dict matching the extra kwargs of DiffSummary's metadata fields.
    """
    result: dict = {
        "new_dependencies": [],
        "removed_dependencies": [],
        "new_install_hooks": [],
        "maintainer_changed": False,
        "native_addons_added": False,
    }

    # ── package.json ─────────────────────────────────────────────────────────
    from_pkg = from_dir / "package.json"
    to_pkg = to_dir / "package.json"

    if from_pkg.exists() and to_pkg.exists():
        try:
            from_meta = json.loads(from_pkg.read_text())
            to_meta = json.loads(to_pkg.read_text())

            from_deps = set(
                (from_meta.get("dependencies") or {}).keys()
            ) | set((from_meta.get("devDependencies") or {}).keys())
            to_deps = set(
                (to_meta.get("dependencies") or {}).keys()
            ) | set((to_meta.get("devDependencies") or {}).keys())

            result["new_dependencies"] = sorted(to_deps - from_deps)
            result["removed_dependencies"] = sorted(from_deps - to_deps)

            # Install hooks: look at scripts.postinstall / scripts.preinstall
            from_scripts = from_meta.get("scripts") or {}
            to_scripts = to_meta.get("scripts") or {}
            hooks = ["postinstall", "preinstall", "install"]
            for hook in hooks:
                if hook not in from_scripts and hook in to_scripts:
                    result["new_install_hooks"].append(hook)

            # Maintainer change heuristic: check "author" field
            if from_meta.get("author") != to_meta.get("author"):
                result["maintainer_changed"] = True

        except (json.JSONDecodeError, KeyError) as exc:
            log.warning("Failed to parse package.json metadata: %s", exc)

    # ── setup.py / pyproject.toml — STUB ─────────────────────────────────────
    # Real implementation: parse AST of setup.py or use tomllib for pyproject.toml
    # For now these return empty — the skeleton works without them.

    return result
