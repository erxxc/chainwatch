"""
Unit tests for chainwatch.fetcher.npm and chainwatch.fetcher.pypi

Tests the helper functions (version resolution, tarball extraction, etc.)
using in-memory fixtures — no real registry calls.
"""

from __future__ import annotations

import base64
import hashlib
import io
import tarfile
import zipfile
from pathlib import Path

import httpx
import pytest
import respx

from chainwatch.config import get_settings
from chainwatch.fetcher.archive import (
    _validate_download_url,
    download_with_limit,
    safe_archive_path,
    validate_tar_members,
    validate_zip_infos,
)
from chainwatch.fetcher.npm import (
    FetchResult,
    _allowed_npm_hosts,
    _extract_npm_tarball,
    _get_version_info,
    _matches_sri,
    _verify_npm_integrity,
)
from chainwatch.fetcher.pypi import (
    _allowed_pypi_hosts,
    _extract_tarball,
    _extract_zip,
    _pick_download,
    _verify_pypi_sha256,
    fetch_release_filename,
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

    def test_rejects_oversized_tar_member(self, monkeypatch):
        monkeypatch.setenv("CHAINWATCH_MAX_ARCHIVE_FILE_BYTES", "1048576")
        get_settings.cache_clear()
        info = tarfile.TarInfo(name="package/big.js")
        info.size = 1048577
        with pytest.raises(ValueError, match="too large"):
            validate_tar_members([info], label="test tar")

    def test_rejects_too_many_tar_directories(self, monkeypatch):
        monkeypatch.setenv("CHAINWATCH_MAX_ARCHIVE_FILES", "1")
        get_settings.cache_clear()
        first = tarfile.TarInfo(name="package/one")
        first.type = tarfile.DIRTYPE
        second = tarfile.TarInfo(name="package/two")
        second.type = tarfile.DIRTYPE
        with pytest.raises(ValueError, match="too many members"):
            validate_tar_members([first, second], label="test tar")

    def test_rejects_backslash_archive_paths(self):
        assert not safe_archive_path(r"package\..\evil.py")

    def test_skips_tar_symlink(self, tmp_path):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            link = tarfile.TarInfo(name="package/link.js")
            link.type = tarfile.SYMTYPE
            link.linkname = "/etc/passwd"
            tar.addfile(link)
            safe = tarfile.TarInfo(name="package/index.js")
            content = b"safe"
            safe.size = len(content)
            tar.addfile(safe, io.BytesIO(content))

        result = _extract_npm_tarball(buf.getvalue(), tmp_path)
        assert (result / "index.js").exists()
        assert not (result / "link.js").exists()


class TestNpmIntegrity:
    def test_matches_sri_sha512(self):
        data = b"package tarball"
        digest = base64.b64encode(hashlib.sha512(data).digest()).decode()
        assert _matches_sri(data, f"sha512-{digest}")

    def test_verify_integrity_mismatch_raises(self):
        digest = base64.b64encode(hashlib.sha512(b"expected").digest()).decode()
        version_info = {"dist": {"integrity": f"sha512-{digest}"}}
        with pytest.raises(ValueError, match="Integrity mismatch"):
            _verify_npm_integrity(b"actual", version_info, "pkg", "1.0.0")

    def test_verify_shasum_fallback(self):
        data = b"package tarball"
        version_info = {"dist": {"shasum": hashlib.sha1(data).hexdigest()}}
        _verify_npm_integrity(data, version_info, "pkg", "1.0.0")

    def test_verify_shasum_mismatch_raises(self):
        version_info = {"dist": {"shasum": "0" * 40}}
        with pytest.raises(ValueError, match="SHA1 mismatch"):
            _verify_npm_integrity(b"package tarball", version_info, "pkg", "1.0.0")

    def test_verify_missing_both_fields_raises(self):
        """If npm returns neither integrity nor shasum we refuse to proceed (H-3)."""
        with pytest.raises(ValueError, match="neither dist.integrity nor dist.shasum"):
            _verify_npm_integrity(b"x", {"dist": {}}, "pkg", "1.0.0")

    def test_verify_empty_integrity_and_no_shasum_raises(self):
        """Empty integrity string must not count as a successful verification."""
        with pytest.raises(ValueError, match="neither dist.integrity nor dist.shasum"):
            _verify_npm_integrity(b"x", {"dist": {"integrity": ""}}, "pkg", "1.0.0")


class TestPypiSha256Verification:
    """H-2: missing sha256 in PyPI metadata must be fatal, not a silent pass."""

    def test_accepts_matching_digest(self):
        data = b"package archive"
        digest = hashlib.sha256(data).hexdigest()
        entry = {"digests": {"sha256": digest}}
        _verify_pypi_sha256(digest, entry, "pkg", "1.0.0")

    def test_missing_digests_field_raises(self):
        with pytest.raises(ValueError, match="missing a sha256 digest"):
            _verify_pypi_sha256("a" * 64, {}, "pkg", "1.0.0")

    def test_missing_sha256_in_digests_raises(self):
        entry = {"digests": {"md5": "abc"}}
        with pytest.raises(ValueError, match="missing a sha256 digest"):
            _verify_pypi_sha256("a" * 64, entry, "pkg", "1.0.0")

    def test_mismatching_digest_raises(self):
        entry = {"digests": {"sha256": "b" * 64}}
        with pytest.raises(ValueError, match="SHA256 mismatch"):
            _verify_pypi_sha256("a" * 64, entry, "pkg", "1.0.0")


class TestDownloadUrlValidation:
    def test_accepts_https_public_host(self):
        assert (
            _validate_download_url("https://registry.npmjs.org/pkg/-/pkg.tgz", label="test")
            == "https://registry.npmjs.org/pkg/-/pkg.tgz"
        )

    def test_rejects_cleartext_url(self):
        with pytest.raises(ValueError, match="https"):
            _validate_download_url("http://registry.npmjs.org/pkg.tgz", label="test")

    def test_rejects_loopback_ip(self):
        with pytest.raises(ValueError, match="non-public IP"):
            _validate_download_url("https://127.0.0.1/pkg.tgz", label="test")

    def test_rejects_localhost(self):
        with pytest.raises(ValueError, match="localhost"):
            _validate_download_url("https://localhost/pkg.tgz", label="test")

    def test_rejects_url_credentials(self):
        with pytest.raises(ValueError, match="credentials"):
            _validate_download_url("https://user:pass@example.com/pkg.tgz", label="test")

    def test_rejects_host_outside_allow_list(self):
        """H-1: a public host not in the allow-list must be rejected."""
        allow = frozenset({"registry.npmjs.org"})
        with pytest.raises(ValueError, match="not in the allow-list"):
            _validate_download_url(
                "https://attacker.example.com/pkg.tgz",
                label="test",
                allowed_hosts=allow,
            )

    def test_accepts_host_inside_allow_list(self):
        allow = frozenset({"registry.npmjs.org"})
        assert (
            _validate_download_url(
                "https://registry.npmjs.org/pkg/-/pkg.tgz",
                label="test",
                allowed_hosts=allow,
            )
            == "https://registry.npmjs.org/pkg/-/pkg.tgz"
        )

    def test_allow_list_is_case_insensitive(self):
        allow = frozenset({"REGISTRY.npmjs.ORG"})
        _validate_download_url(
            "https://registry.npmjs.org/pkg/-/pkg.tgz",
            label="test",
            allowed_hosts=allow,
        )

    @respx.mock
    async def test_redirect_does_not_consume_retry_budget(self, monkeypatch):
        monkeypatch.setenv("CHAINWATCH_MAX_RETRIES", "0")
        get_settings.cache_clear()

        start = "https://registry.npmjs.org/pkg/-/pkg.tgz"
        final = "https://registry.npmjs.org/pkg/-/pkg-final.tgz"
        respx.get(start).respond(status_code=302, headers={"Location": final})
        respx.get(final).respond(content=b"archive")

        async with httpx.AsyncClient() as client:
            result = await download_with_limit(
                client,
                start,
                label="test",
                allowed_hosts=frozenset({"registry.npmjs.org"}),
            )

        assert result == b"archive"


class TestArchiveHostAllowList:
    def test_npm_includes_configured_extra_archive_hosts(self, monkeypatch):
        monkeypatch.setenv(
            "CHAINWATCH_ALLOWED_ARCHIVE_HOSTS",
            "Artifacts.EXAMPLE.com,https://cdn.example.com/path",
        )
        get_settings.cache_clear()

        assert _allowed_npm_hosts() == frozenset(
            {"registry.npmjs.org", "artifacts.example.com", "cdn.example.com"}
        )

    def test_pypi_includes_default_cdn_and_configured_extra_hosts(self, monkeypatch):
        monkeypatch.setenv("CHAINWATCH_ALLOWED_ARCHIVE_HOSTS", "artifacts.example.com")
        get_settings.cache_clear()

        assert _allowed_pypi_hosts() == frozenset(
            {"pypi.org", "files.pythonhosted.org", "artifacts.example.com"}
        )


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


# ── pypi: fetch_release_filename ────────────────────────────────────────────────


class TestFetchReleaseFilename:
    @respx.mock
    async def test_prefers_sdist_filename(self):
        respx.get("https://pypi.org/pypi/pkg/1.0.0/json").respond(json={
            "urls": [
                {
                    "packagetype": "bdist_wheel",
                    "url": "https://files.pythonhosted.org/pkg-1.0.0-py3-none-any.whl",
                    "filename": "pkg-1.0.0-py3-none-any.whl",
                },
                {
                    "packagetype": "sdist",
                    "url": "https://files.pythonhosted.org/pkg-1.0.0.tar.gz",
                    "filename": "pkg-1.0.0.tar.gz",
                },
            ]
        })
        async with httpx.AsyncClient() as client:
            filename = await fetch_release_filename(client, "pkg", "1.0.0")
        assert filename == "pkg-1.0.0.tar.gz"

    @respx.mock
    async def test_returns_none_when_version_not_found(self):
        respx.get("https://pypi.org/pypi/pkg/9.9.9/json").respond(status_code=404)
        async with httpx.AsyncClient() as client:
            filename = await fetch_release_filename(client, "pkg", "9.9.9")
        assert filename is None

    @respx.mock
    async def test_returns_none_when_no_files_published(self):
        respx.get("https://pypi.org/pypi/pkg/1.0.0/json").respond(json={"urls": []})
        async with httpx.AsyncClient() as client:
            filename = await fetch_release_filename(client, "pkg", "1.0.0")
        assert filename is None


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

    def test_rejects_oversized_zip_member(self, monkeypatch):
        monkeypatch.setenv("CHAINWATCH_MAX_ARCHIVE_FILE_BYTES", "1048576")
        get_settings.cache_clear()
        info = zipfile.ZipInfo("big.py")
        info.file_size = 1048577
        with pytest.raises(ValueError, match="too large"):
            validate_zip_infos([info], label="test zip")

    def test_rejects_too_many_zip_directories(self, monkeypatch):
        monkeypatch.setenv("CHAINWATCH_MAX_ARCHIVE_FILES", "1")
        get_settings.cache_clear()
        with pytest.raises(ValueError, match="too many members"):
            validate_zip_infos(
                [zipfile.ZipInfo("one/"), zipfile.ZipInfo("two/")],
                label="test zip",
            )


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
