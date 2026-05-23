"""
chainwatch.fetcher.pypi
~~~~~~~~~~~~~~~~~~~~~~~

Downloads two versions of a PyPI package and extracts them to temp directories.

PyPI JSON API:
  GET https://pypi.org/pypi/{package}/{version}/json
  Returns JSON with a ``urls`` array containing download links.
  Each URL entry has ``packagetype`` (``sdist`` or ``bdist_wheel``),
  ``url``, and ``digests.sha256``.

We prefer sdist (.tar.gz) over wheel (.whl) because sdist contains the
raw source tree which is better for diff analysis.  If only a wheel is
available we extract it (wheels are zip files).
"""

from __future__ import annotations

import asyncio
import hashlib
import io
import logging
import tarfile
import tempfile
import zipfile
from pathlib import Path
from typing import Any

import httpx

from chainwatch.config import get_settings
from chainwatch.fetcher.npm import FetchResult  # reuse shared FetchResult type

log = logging.getLogger(__name__)


async def fetch_package_versions(
    client: httpx.AsyncClient,
    package: str,
    from_version: str,
    to_version: str,
) -> FetchResult:
    """
    Download and extract both versions of a PyPI package.

    1. GET pypi.org/pypi/{package}/{version}/json for each version
    2. Prefer sdist (.tar.gz) over wheel (.whl)
    3. Download both archives concurrently
    4. Verify SHA256 against PyPI-reported digest
    5. Extract to temp directories

    Args:
        client:       Shared httpx.AsyncClient
        package:      PyPI package name (normalised: lowercase, hyphens)
        from_version: Baseline version
        to_version:   Target version

    Returns:
        FetchResult with paths to extracted directories
    """
    settings = get_settings()
    log.info("pypi: fetching %s %s → %s", package, from_version, to_version)

    # Fetch version metadata concurrently
    from_meta, to_meta = await asyncio.gather(
        _fetch_version_metadata(client, settings.pypi_registry, package, from_version),
        _fetch_version_metadata(client, settings.pypi_registry, package, to_version),
    )

    from_dl = _pick_download(from_meta, package, from_version)
    to_dl = _pick_download(to_meta, package, to_version)

    log.debug("Downloading: %s, %s", from_dl["url"], to_dl["url"])

    # Download both concurrently
    from_bytes, to_bytes = await asyncio.gather(
        _download_archive(client, from_dl["url"]),
        _download_archive(client, to_dl["url"]),
    )

    # Verify SHA256 against PyPI-reported digests
    from_sha256 = hashlib.sha256(from_bytes).hexdigest()
    to_sha256 = hashlib.sha256(to_bytes).hexdigest()

    expected_from = from_dl.get("digests", {}).get("sha256")
    expected_to = to_dl.get("digests", {}).get("sha256")

    if expected_from and from_sha256 != expected_from:
        raise ValueError(
            f"SHA256 mismatch for {package}@{from_version}: "
            f"expected {expected_from}, got {from_sha256}"
        )
    if expected_to and to_sha256 != expected_to:
        raise ValueError(
            f"SHA256 mismatch for {package}@{to_version}: "
            f"expected {expected_to}, got {to_sha256}"
        )

    # Extract to temp directories
    from_td = tempfile.TemporaryDirectory(prefix="chainwatch-from-")
    to_td = tempfile.TemporaryDirectory(prefix="chainwatch-to-")

    from_dir = _extract_archive(
        from_bytes, Path(from_td.name), from_dl["filename"]
    )
    to_dir = _extract_archive(
        to_bytes, Path(to_td.name), to_dl["filename"]
    )

    log.info(
        "pypi: extracted %s@%s (%d files) and %s@%s (%d files)",
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


async def _fetch_version_metadata(
    client: httpx.AsyncClient,
    registry: str,
    package: str,
    version: str,
) -> dict[str, Any]:
    """Fetch version-specific metadata from PyPI."""
    url = f"{registry}/{package}/{version}/json"
    settings = get_settings()

    for attempt in range(settings.max_retries + 1):
        resp = await client.get(url)
        if resp.status_code == 429 and attempt < settings.max_retries:
            wait = 2 ** attempt
            log.warning("Rate limited by PyPI — retrying in %ds", wait)
            await asyncio.sleep(wait)
            continue
        if resp.status_code == 404:
            raise ValueError(
                f"Version {version} not found for {package} on PyPI"
            )
        resp.raise_for_status()
        return resp.json()  # type: ignore[no-any-return]

    raise RuntimeError(f"Exhausted retries fetching PyPI metadata for {package}@{version}")


def _pick_download(
    metadata: dict[str, Any],
    package: str,
    version: str,
) -> dict[str, Any]:
    """
    Pick the best download URL from the PyPI version metadata.

    Preference: sdist (.tar.gz) > wheel (.whl)
    """
    urls = metadata.get("urls", [])
    if not urls:
        raise ValueError(
            f"No download URLs found for {package}@{version}"
        )

    # Prefer sdist
    for entry in urls:
        if entry.get("packagetype") == "sdist":
            return entry  # type: ignore[no-any-return]

    # Fall back to first wheel
    for entry in urls:
        if entry.get("packagetype") == "bdist_wheel":
            return entry  # type: ignore[no-any-return]

    # Last resort: first entry
    return urls[0]  # type: ignore[no-any-return]


async def _download_archive(client: httpx.AsyncClient, url: str) -> bytes:
    """Download an archive with retry on rate limit."""
    settings = get_settings()

    for attempt in range(settings.max_retries + 1):
        resp = await client.get(url)
        if resp.status_code == 429 and attempt < settings.max_retries:
            wait = 2 ** attempt
            log.warning("Rate limited downloading archive — retrying in %ds", wait)
            await asyncio.sleep(wait)
            continue
        resp.raise_for_status()
        return resp.content

    raise RuntimeError(f"Exhausted retries downloading {url}")


def _extract_archive(data: bytes, dest: Path, filename: str) -> Path:
    """
    Extract a PyPI archive (sdist tar.gz or wheel zip) to a destination.

    sdist archives typically have a top-level directory named
    ``{package}-{version}/``.  Wheels are flat zip files.
    """
    if filename.endswith(".tar.gz") or filename.endswith(".tgz"):
        return _extract_tarball(data, dest)
    elif filename.endswith(".whl") or filename.endswith(".zip"):
        return _extract_zip(data, dest)
    else:
        # Try tar first, fall back to zip
        try:
            return _extract_tarball(data, dest)
        except (tarfile.TarError, Exception):
            return _extract_zip(data, dest)


def _extract_tarball(data: bytes, dest: Path) -> Path:
    """Extract a .tar.gz sdist archive."""
    buf = io.BytesIO(data)
    with tarfile.open(fileobj=buf, mode="r:gz") as tar:
        members = []
        for member in tar.getmembers():
            if member.name.startswith("/") or ".." in member.name:
                log.warning("Skipping unsafe tar member: %s", member.name)
                continue
            members.append(member)
        tar.extractall(path=dest, members=members, filter="data")

    # sdist archives usually have a single top-level directory
    subdirs = [p for p in dest.iterdir() if p.is_dir()]
    if len(subdirs) == 1:
        return subdirs[0]
    return dest


def _extract_zip(data: bytes, dest: Path) -> Path:
    """Extract a .whl (zip) archive."""
    buf = io.BytesIO(data)
    with zipfile.ZipFile(buf) as zf:
        for info in zf.infolist():
            if info.filename.startswith("/") or ".." in info.filename:
                log.warning("Skipping unsafe zip member: %s", info.filename)
                continue
            zf.extract(info, path=dest)

    # Wheels may have a dist-info directory; find the source directory
    subdirs = [p for p in dest.iterdir() if p.is_dir()]
    # Filter out .dist-info directories
    source_dirs = [d for d in subdirs if not d.name.endswith(".dist-info")]
    if len(source_dirs) == 1:
        return source_dirs[0]
    return dest


def _count_files(directory: Path) -> int:
    """Count files recursively in a directory."""
    return sum(1 for p in directory.rglob("*") if p.is_file())
