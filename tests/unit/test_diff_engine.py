"""
Unit tests for chainwatch.diff.engine and chainwatch.diff.chunker

Uses fixture directories — no network calls, no API calls.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from chainwatch.diff.chunker import chunk_diff
from chainwatch.diff.engine import compute_diff

# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def identical_dirs(tmp_path: Path):
    """Two directories with identical content — diff should be empty."""
    a = tmp_path / "a"
    b = tmp_path / "b"
    a.mkdir()
    b.mkdir()
    (a / "index.js").write_text("module.exports = 1;\n")
    (b / "index.js").write_text("module.exports = 1;\n")
    return a, b


@pytest.fixture
def simple_change(tmp_path: Path):
    """Two directories with one modified file."""
    a = tmp_path / "a"
    b = tmp_path / "b"
    a.mkdir()
    b.mkdir()
    (a / "index.js").write_text("module.exports = function() { return 'hello'; };\n")
    (b / "index.js").write_text("module.exports = function() { return 'hello world'; };\n")
    return a, b


@pytest.fixture
def added_and_removed(tmp_path: Path):
    """from_dir has extra.js, to_dir has new.js instead."""
    a = tmp_path / "a"
    b = tmp_path / "b"
    a.mkdir()
    b.mkdir()
    (a / "index.js").write_text("// shared\n")
    (a / "extra.js").write_text("// will be removed\n")
    (b / "index.js").write_text("// shared\n")
    (b / "new.js").write_text("// was added\n")
    return a, b


@pytest.fixture
def with_package_json(tmp_path: Path):
    """Directories with package.json that has a new dependency and postinstall hook."""
    a = tmp_path / "a"
    b = tmp_path / "b"
    a.mkdir()
    b.mkdir()

    (a / "index.js").write_text("module.exports = 1;\n")
    (a / "package.json").write_text(json.dumps({
        "name": "test-pkg",
        "version": "1.0.0",
        "dependencies": {"lodash": "^4.17.0"},
        "scripts": {},
    }))

    (b / "index.js").write_text("module.exports = 1;\n")
    (b / "package.json").write_text(json.dumps({
        "name": "test-pkg",
        "version": "1.0.1",
        "dependencies": {"lodash": "^4.17.0", "axios": "^1.0.0"},
        "scripts": {"postinstall": "node setup.js"},
    }))
    return a, b


@pytest.fixture
def non_source_files(tmp_path: Path):
    """to_dir has image and binary files — should be ignored by the engine."""
    a = tmp_path / "a"
    b = tmp_path / "b"
    a.mkdir()
    b.mkdir()
    (a / "index.js").write_text("// src\n")
    (b / "index.js").write_text("// src changed\n")
    (b / "image.png").write_bytes(b"\x89PNG\r\n")
    (b / "README.md").write_text("# docs\n")
    return a, b


# ── Engine tests ──────────────────────────────────────────────────────────────


class TestDiffEngine:
    def test_identical_dirs_produce_empty_diff(self, identical_dirs):
        a, b = identical_dirs
        result = compute_diff(a, b)
        assert result.files_added == []
        assert result.files_removed == []
        assert result.files_modified == []
        assert result.file_diffs == []
        assert result.total_diff_lines == 0

    def test_detects_modified_file(self, simple_change):
        a, b = simple_change
        result = compute_diff(a, b)
        assert "index.js" in result.files_modified
        assert len(result.file_diffs) == 1
        assert result.file_diffs[0].change_type == "modified"
        assert result.file_diffs[0].lines_added > 0

    def test_detects_added_and_removed(self, added_and_removed):
        a, b = added_and_removed
        result = compute_diff(a, b)
        assert "new.js" in result.files_added
        assert "extra.js" in result.files_removed

    def test_non_source_files_excluded(self, non_source_files):
        a, b = non_source_files
        result = compute_diff(a, b)
        # Only index.js should be in the diff — image.png and README.md excluded
        all_files = result.files_added + result.files_modified + result.files_removed
        assert all(f.endswith(".js") for f in all_files)

    def test_package_json_new_dependency_detected(self, with_package_json):
        a, b = with_package_json
        result = compute_diff(a, b)
        assert "axios" in result.new_dependencies

    def test_package_json_postinstall_hook_detected(self, with_package_json):
        a, b = with_package_json
        result = compute_diff(a, b)
        assert "postinstall" in result.new_install_hooks

    def test_total_diff_lines_counted(self, simple_change):
        a, b = simple_change
        result = compute_diff(a, b)
        assert result.total_diff_lines > 0


# ── Chunker tests ─────────────────────────────────────────────────────────────


class TestChunker:
    def test_small_diff_produces_single_chunk(self, simple_change):
        a, b = simple_change
        diff = compute_diff(a, b)
        chunks = chunk_diff(diff, max_tokens_per_chunk=8_000)
        assert len(chunks) == 1
        assert diff.chunks_sent_to_llm == 1
        assert diff.diff_truncated is False

    def test_chunk_contains_metadata_preamble(self, simple_change):
        a, b = simple_change
        diff = compute_diff(a, b)
        chunks = chunk_diff(diff, max_tokens_per_chunk=8_000)
        assert "# Package Diff — Metadata Summary" in chunks[0]

    def test_large_file_triggers_truncation(self, tmp_path: Path):
        """A file whose diff exceeds the token budget should be truncated."""
        a = tmp_path / "a"
        b = tmp_path / "b"
        a.mkdir()
        b.mkdir()
        # Generate a large diff: 10000 lines changed
        (a / "big.js").write_text("\n".join(f"var x{i} = {i};" for i in range(10_000)))
        (b / "big.js").write_text("\n".join(f"var x{i} = {i + 1};" for i in range(10_000)))

        diff = compute_diff(a, b)
        # Very small token budget to force truncation
        chunks = chunk_diff(diff, max_tokens_per_chunk=100)
        assert diff.diff_truncated is True
        assert "truncated" in chunks[0].lower()

    def test_metadata_postinstall_appears_in_chunk(self, with_package_json):
        a, b = with_package_json
        diff = compute_diff(a, b)
        chunks = chunk_diff(diff, max_tokens_per_chunk=8_000)
        assert "postinstall" in chunks[0]

    def test_metadata_new_dep_appears_in_chunk(self, with_package_json):
        a, b = with_package_json
        diff = compute_diff(a, b)
        chunks = chunk_diff(diff, max_tokens_per_chunk=8_000)
        assert "axios" in chunks[0]
