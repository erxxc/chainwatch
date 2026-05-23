"""
Unit tests for chainwatch.fetcher.npm and chainwatch.fetcher.pypi

Tests the helper functions (version resolution, tarball extraction, etc.)
using in-memory fixtures — no real registry calls.
"""

from __future__ import annotations

import io
import tarfile
import zipfile
from pathlib import Path

import pytest

from chainwatch.config import get_settings
from chainwatch.fetcher.npm import (
    FetchResult,
    _extract_npm_tarball,
    _get_version_info,
)
from chainwatch.fetcher.pypi import (
    _extract_tarball,
    _extract_zip,
    _pick_download,
)


@pytest.fixture(autouse=True)
def _reset_settings(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-fake")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


# ── npm: _get_version_info ────────────────────────────────────────────────────


class TestGetVersionInfo:
    def test_valid_version(self):
        metadata = {
            "versions": {
                "1.0.0": {"dist": {"tarball": "https://example.com/1.0.0.tgz"}},
                "1.0.1": {"dist": {"tarball": "https://example.com/1.0.1.tgz"}},
            }
        }
        result = _get_version_info(metadata, "test-pkg", "1.0.1")
        assert result["dist"]["tarball"] == "https://example.com/1.0.1.tgz"

    def test_missing_version_raises(self):
        metadata = {
            "versions": {
                "1.0.0": {"dist": {"tarball": "https://example.com/1.0.0.tgz"}},
            }
        }
        with pytest.raises(ValueError, match="not found"):
            _get_version_info(metadata, "test-pkg", "2.0.0")

    def test_missing_version_shows_available(self):
        metadata = {
            "versions": {
                "1.0.0": {},
                "1.0.1": {},
                "1.0.2": {},
            }
        }
        with pytest.raises(ValueError, match="1.0.0"):
            _get_version_info(metadata, "test-pkg", "9.9.9")


# ── npm: _extract_npm_tarball ─────────────────────────────────────────────────


class TestExtractNpmTarball:
    def test_extracts_package_directory(self, tmp_path):
        """npm tarballs nest files under package/ — extraction should return that."""
        data = _make_npm_tarball({
            "package/index.js": b"module.exports = 1;",
            "package/package.json": b'{"name": "test"}',
        })
        result = _extract_npm_tarball(data, tmp_path)
        assert result == tmp_path / "package"
        assert (result / "index.js").read_text() == "module.exports = 1;"
        assert (result / "package.json").exists()

    def test_extracts_single_subdirectory_fallback(self, tmp_path):
        """If no package/ dir, use the single subdirectory."""
        data = _make_npm_tarball({
            "my-pkg/index.js": b"exports.hello = true;",
        })
        result = _extract_npm_tarball(data, tmp_path)
        assert result == tmp_path / "my-pkg"
        assert (result / "index.js").exists()

    def test_returns_dest_when_flat(self, tmp_path):
        """If files are at the root level, return dest directly."""
        data = _make_npm_tarball({
            "index.js": b"module.exports = 1;",
            "readme.md": b"# Test",
        })
        result = _extract_npm_tarball(data, tmp_path)
        assert result == tmp_path
        assert (tmp_path / "index.js").exists()

    def test_skips_path_traversal(self, tmp_path):
        """Members with .. in the name should be skipped for security."""
        data = _make_npm_tarball({
            "package/index.js": b"safe content",
            "package/../etc/passwd": b"evil content",
        })
        result = _extract_npm_tarball(data, tmp_path)
        # The safe file should exist, the traversal file should not
        assert (result / "index.js").exists()
        assert not (tmp_path / "etc" / "passwd").exists()


# ── npm: FetchResult context manager ─────────────────────────────────────────


class TestFetchResult:
    def test_context_manager_cleanup(self, tmp_path):
        import tempfile

        td = tempfile.TemporaryDirectory(prefix="test-")
        td_path = Path(td.name)
        assert td_path.exists()

        fr = FetchResult(
            package="test",
            from_version="1.0.0",
            to_version="1.0.1",
            from_dir=td_path,
            to_dir=td_path,
            from_sha256="abc",
            to_sha256="def",
            _temp_dirs=[td],
        )
        with fr:
            assert td_path.exists()
        assert not td_path.exists()


# ── pypi: _pick_download ─────────────────────────────────────────────────────


class TestPickDownload:
    def test_prefers_sdist(self):
        metadata = {
            "urls": [
                {
                    "packagetype": "bdist_wheel",
                    "url": "https://example.com/pkg-1.0.0-py3-none-any.whl",
                    "filename": "pkg-1.0.0-py3-none-any.whl",
                },
                {
                    "packagetype": "sdist",
                    "url": "https://example.com/pkg-1.0.0.tar.gz",
                    "filename": "pkg-1.0.0.tar.gz",
                },
            ]
        }
        result = _pick_download(metadata, "pkg", "1.0.0")
        assert result["packagetype"] == "sdist"

    def test_falls_back_to_wheel(self):
        metadata = {
            "urls": [
                {
                    "packagetype": "bdist_wheel",
                    "url": "https://example.com/pkg-1.0.0-py3-none-any.whl",
                    "filename": "pkg-1.0.0-py3-none-any.whl",
                },
            ]
        }
        result = _pick_download(metadata, "pkg", "1.0.0")
        assert result["packagetype"] == "bdist_wheel"

    def test_empty_urls_raises(self):
        metadata = {"urls": []}
        with pytest.raises(ValueError, match="No download URLs"):
            _pick_download(metadata, "pkg", "1.0.0")

    def test_falls_back_to_first_entry(self):
        metadata = {
            "urls": [
                {
                    "packagetype": "other",
                    "url": "https://example.com/pkg-1.0.0.egg",
                    "filename": "pkg-1.0.0.egg",
                },
            ]
        }
        result = _pick_download(metadata, "pkg", "1.0.0")
        assert result["url"] == "https://example.com/pkg-1.0.0.egg"


# ── pypi: _extract_tarball ────────────────────────────────────────────────────


class TestExtractTarball:
    def test_extracts_sdist_with_top_directory(self, tmp_path):
        """sdist archives have a top-level pkg-version/ directory."""
        data = _make_npm_tarball({  # reuse helper — same tar.gz format
            "mypackage-1.0.0/mypackage/__init__.py": b"",
            "mypackage-1.0.0/mypackage/main.py": b'print("hello")',
            "mypackage-1.0.0/setup.py": b"from setuptools import setup; setup()",
        })
        result = _extract_tarball(data, tmp_path)
        assert result == tmp_path / "mypackage-1.0.0"
        assert (result / "setup.py").exists()
        assert (result / "mypackage" / "main.py").exists()


# ── pypi: _extract_zip (wheel) ────────────────────────────────────────────────


class TestExtractZip:
    def test_extracts_wheel_zip(self, tmp_path):
        data = _make_wheel_zip({
            "mypackage/__init__.py": b"",
            "mypackage/main.py": b'print("hello")',
            "mypackage-1.0.0.dist-info/METADATA": b"Name: mypackage",
        })
        result = _extract_zip(data, tmp_path)
        # Should return the source dir, not the dist-info dir
        assert result == tmp_path / "mypackage"
        assert (result / "main.py").exists()

    def test_extracts_flat_zip(self, tmp_path):
        data = _make_wheel_zip({
            "main.py": b'print("hello")',
            "utils.py": b'print("utils")',
        })
        result = _extract_zip(data, tmp_path)
        assert result == tmp_path
        assert (tmp_path / "main.py").exists()


# ── Helpers ───────────────────────────────────────────────────────────────────


def _make_npm_tarball(files: dict[str, bytes]) -> bytes:
    """Create an in-memory tar.gz file with the given files."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, content in files.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))
    return buf.getvalue()


def _make_wheel_zip(files: dict[str, bytes]) -> bytes:
    """Create an in-memory zip file (simulating a .whl wheel)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()
