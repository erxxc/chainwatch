"""
chainwatch.fetcher.pypi
~~~~~~~~~~~~~~~~~~~~~~~

Downloads two versions of a PyPI package and extracts them to temp directories.

Architecture note:
  PyPI packages come in two formats: sdist (``.tar.gz``) and wheel (``.whl``).
  We prefer sdist for diff analysis because it contains the raw source files.
  If only a wheel is available we extract it (wheels are just zip files).

Stub status: STUB
  Returns fixture directories.  Real implementation downloads from pypi.org.
"""

from __future__ import annotations

import logging
import tempfile
from pathlib import Path

import httpx

from chainwatch.config import get_settings
from chainwatch.fetcher.npm import FetchResult, _sha256_dir  # reuse shared types

log = logging.getLogger(__name__)


async def fetch_package_versions(
    client: httpx.AsyncClient,
    package: str,
    from_version: str,
    to_version: str,
) -> FetchResult:
    """
    Download and extract both versions of a PyPI package.

    Real implementation will:
    1. GET pypi.org/pypi/{package}/{version}/json to get download URLs
    2. Prefer sdist (.tar.gz) over wheel (.whl) for source-level diff
    3. Download and verify SHA256 (PyPI provides these in the JSON metadata)
    4. Extract to temp directories

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

    # ── STUB ──────────────────────────────────────────────────────────────────
    log.warning("pypi fetcher is STUBBED — returning fixture data")

    from_td = tempfile.TemporaryDirectory(prefix="chainwatch-from-")
    to_td = tempfile.TemporaryDirectory(prefix="chainwatch-to-")

    from_dir = Path(from_td.name)
    to_dir = Path(to_td.name)

    (from_dir / "main.py").write_text(
        f'"""  {package} v{from_version}  """\n\ndef run():\n    return "hello"\n'
    )
    (from_dir / "setup.py").write_text(
        f"from setuptools import setup\nsetup(name='{package}', version='{from_version}')\n"
    )

    (to_dir / "main.py").write_text(
        f'"""  {package} v{to_version}  """\n\ndef run():\n    return "hello world"\n'
    )
    (to_dir / "setup.py").write_text(
        f"from setuptools import setup\nsetup(name='{package}', version='{to_version}')\n"
    )

    return FetchResult(
        package=package,
        from_version=from_version,
        to_version=to_version,
        from_dir=from_dir,
        to_dir=to_dir,
        from_sha256=_sha256_dir(from_dir),
        to_sha256=_sha256_dir(to_dir),
        _temp_dirs=[from_td, to_td],
    )
    # ── END STUB ──────────────────────────────────────────────────────────────
