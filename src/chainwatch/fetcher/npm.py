"""
chainwatch.fetcher.npm
~~~~~~~~~~~~~~~~~~~~~~

Downloads two versions of an npm package from the registry and extracts them
to temporary directories for the diff engine.

npm registry API:
  GET https://registry.npmjs.org/{package}
  Returns JSON with a ``versions`` object keyed by semver string.
  Each version entry has a ``dist.tarball`` URL, ``dist.integrity`` (SRI),
  and/or ``dist.shasum`` (SHA1).

  Tarballs are gzip-compressed tar files.  The contents are always nested
  under a ``package/`` directory inside the tar.

Architecture (async):
  The caller (cli.py) owns the ``httpx.AsyncClient`` and passes it in.
  This module downloads both tarballs concurrently using ``asyncio.gather()``.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import io
import logging
import tarfile
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from chainwatch.config import get_settings
from chainwatch.fetcher.archive import download_with_limit, validate_tar_members

log = logging.getLogger(__name__)


@dataclass
class FetchResult:
    """
    Paths to the extracted package directories for both versions.

    Both directories are owned by the caller; clean them up with
    ``cleanup()`` when done, or use ``FetchResult`` as a context manager.
    """

    package: str
    from_version: str
    to_version: str
    from_dir: Path
    to_dir: Path
    from_sha256: str
    to_sha256: str
    # Temp directories to clean up; may overlap with from_dir/to_dir parents
    _temp_dirs: list[tempfile.TemporaryDirectory[str]] = field(default_factory=list, repr=False)

    def cleanup(self) -> None:
        for td in self._temp_dirs:
            td.cleanup()

    def __enter__(self) -> FetchResult:
        return self

    def __exit__(self, *_: object) -> None:
        self.cleanup()


async def fetch_package_versions(
    client: httpx.AsyncClient,
    package: str,
    from_version: str,
    to_version: str,
) -> FetchResult:
    """
    Download and extract both versions of an npm package.

    1. GET registry.npmjs.org/{package} to resolve tarball URLs
    2. Download both tarballs concurrently
    3. Verify registry-provided integrity for each tarball
    4. Extract to temp directories

    Args:
        client:       Shared httpx.AsyncClient (caller-owned lifecycle)
        package:      npm package name (scoped names like @org/pkg supported)
        from_version: Baseline version string
        to_version:   Target version string

    Returns:
        FetchResult with paths to extracted directories and tarball hashes
    """
    settings = get_settings()
    log.info("npm: fetching %s %s → %s", package, from_version, to_version)

    # Resolve metadata — full package document
    metadata = await _fetch_metadata(client, settings.npm_registry, package)

    from_info = _get_version_info(metadata, package, from_version)
    to_info = _get_version_info(metadata, package, to_version)

    from_url = from_info["dist"]["tarball"]
    to_url = to_info["dist"]["tarball"]

    log.debug("Downloading tarballs: %s, %s", from_url, to_url)

    # Download both tarballs concurrently
    from_bytes, to_bytes = await asyncio.gather(
        _download_tarball(client, from_url),
        _download_tarball(client, to_url),
    )

    from_sha256 = hashlib.sha256(from_bytes).hexdigest()
    to_sha256 = hashlib.sha256(to_bytes).hexdigest()
    _verify_npm_integrity(from_bytes, from_info, package, from_version)
    _verify_npm_integrity(to_bytes, to_info, package, to_version)

    log.debug(
        "Downloaded: from=%d bytes (sha256:%s…), to=%d bytes (sha256:%s…)",
        len(from_bytes), from_sha256[:12],
        len(to_bytes), to_sha256[:12],
    )

    # Extract to temp directories
    from_td = tempfile.TemporaryDirectory(prefix="chainwatch-from-")
    to_td = tempfile.TemporaryDirectory(prefix="chainwatch-to-")

    from_dir = _extract_npm_tarball(from_bytes, Path(from_td.name))
    to_dir = _extract_npm_tarball(to_bytes, Path(to_td.name))

    log.info(
        "npm: extracted %s@%s (%d files) and %s@%s (%d files)",
        package, from_version, _count_files(from_dir),
        package, to_version, _count_files(to_dir),
    )

    return FetchResult(
        package=package,
        from_version=from_version,
        to_version=to_version,
        from_dir=from_dir,
        to_dir=to_dir,
        from_sha256=from_sha256,
        to_sha256=to_sha256,
        _temp_dirs=[from_td, to_td],
    )


# ── Internal helpers ──────────────────────────────────────────────────────────


async def _fetch_metadata(
    client: httpx.AsyncClient,
    registry: str,
    package: str,
) -> dict[str, Any]:
    """Fetch the full package metadata document from npm registry."""
    url = f"{registry}/{package}"
    settings = get_settings()

    for attempt in range(settings.max_retries + 1):
        resp = await client.get(url)
        if resp.status_code == 429 and attempt < settings.max_retries:
            wait = 2 ** attempt
            log.warning("Rate limited by npm registry — retrying in %ds", wait)
            await asyncio.sleep(wait)
            continue
        resp.raise_for_status()
        return resp.json()  # type: ignore[no-any-return]

    raise RuntimeError(f"Exhausted retries fetching npm metadata for {package}")


def _get_version_info(
    metadata: dict[str, Any],
    package: str,
    version: str,
) -> dict[str, Any]:
    """Extract version-specific info from the package metadata."""
    versions = metadata.get("versions", {})
    if version not in versions:
        available = sorted(versions.keys())[-10:]  # show last 10
        raise ValueError(
            f"Version {version} not found for {package}. "
            f"Available (last 10): {', '.join(available)}"
        )
    return versions[version]  # type: ignore[no-any-return]


async def _download_tarball(client: httpx.AsyncClient, url: str) -> bytes:
    """Download a tarball with retry on rate limit."""
    return await download_with_limit(client, url, label="npm tarball")


def _verify_npm_integrity(
    data: bytes,
    version_info: dict[str, Any],
    package: str,
    version: str,
) -> None:
    """Verify an npm tarball against dist.integrity or dist.shasum."""
    dist = version_info.get("dist") or {}
    integrity = dist.get("integrity")
    if isinstance(integrity, str) and integrity:
        if _matches_sri(data, integrity):
            return
        raise ValueError(f"Integrity mismatch for {package}@{version}")

    shasum = dist.get("shasum")
    if isinstance(shasum, str) and shasum:
        actual = hashlib.sha1(data).hexdigest()
        if actual != shasum:
            raise ValueError(
                f"SHA1 mismatch for {package}@{version}: expected {shasum}, got {actual}"
            )


def _matches_sri(data: bytes, integrity: str) -> bool:
    """Return True if data matches any digest in an npm SRI string."""
    algorithms = {
        "sha512": hashlib.sha512,
        "sha384": hashlib.sha384,
        "sha256": hashlib.sha256,
    }
    for token in integrity.split():
        algorithm, sep, digest_b64 = token.partition("-")
        if not sep or algorithm not in algorithms:
            continue
        try:
            expected = base64.b64decode(digest_b64, validate=True)
        except (ValueError, binascii.Error):
            continue
        actual = algorithms[algorithm](data).digest()
        if actual == expected:
            return True
    return False


def _extract_npm_tarball(data: bytes, dest: Path) -> Path:
    """
    Extract an npm tarball to a destination directory.

    npm tarballs nest everything under a ``package/`` directory.
    We extract and return the path to that inner directory, or the
    dest root if the structure is different.
    """
    buf = io.BytesIO(data)
    with tarfile.open(fileobj=buf, mode="r:gz") as tar:
        members = validate_tar_members(tar.getmembers(), label="npm tarball")
        tar.extractall(path=dest, members=members, filter="data")

    # npm tarballs always contain a top-level "package/" directory
    package_dir = dest / "package"
    if package_dir.is_dir():
        return package_dir
    # Fallback: if there's exactly one top-level directory, use it
    subdirs = [p for p in dest.iterdir() if p.is_dir()]
    if len(subdirs) == 1:
        return subdirs[0]
    return dest


def _count_files(directory: Path) -> int:
    """Count files recursively in a directory."""
    return sum(1 for p in directory.rglob("*") if p.is_file())


def _sha256_dir(directory: Path) -> str:
    """
    Compute a deterministic SHA256 over all files in a directory.

    Files are hashed in sorted order so the result is reproducible regardless
    of filesystem ordering.
    """
    h = hashlib.sha256()
    for path in sorted(directory.rglob("*")):
        if path.is_file():
            h.update(path.read_bytes())
    return h.hexdigest()
