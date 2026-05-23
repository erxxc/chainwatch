"""
chainwatch.fetcher.npm
~~~~~~~~~~~~~~~~~~~~~~

Downloads two versions of an npm package from the registry and extracts them
to temporary directories for the diff engine.

Architecture (async):
  The client uses ``httpx.AsyncClient`` with a shared session so all requests
  within a single ``chainwatch diff`` invocation reuse connection pools.
  The caller (cli.py) owns the async context and passes the client in.

Stub status: STUB
  ``fetch_package_versions()`` currently returns a ``FetchResult`` with the
  two temp directories pointing at a fixture package.  The real implementation
  will download and extract the actual tarballs.
"""

from __future__ import annotations

import hashlib
import logging
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from chainwatch.config import get_settings

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
    _temp_dirs: list[tempfile.TemporaryDirectory] = field(default_factory=list, repr=False)

    def cleanup(self) -> None:
        for td in self._temp_dirs:
            td.cleanup()

    def __enter__(self) -> "FetchResult":
        return self

    def __exit__(self, *_) -> None:  # type: ignore[override]
        self.cleanup()


async def fetch_package_versions(
    client: httpx.AsyncClient,
    package: str,
    from_version: str,
    to_version: str,
) -> FetchResult:
    """
    Download and extract both versions of an npm package.

    Real implementation will:
    1. GET registry.npmjs.org/{package} to resolve metadata and tarball URLs
    2. Download both tarballs with progress indication
    3. Verify SHA256 of each tarball
    4. Extract to temp directories, filtering to source files

    Args:
        client:       Shared httpx.AsyncClient (caller-owned lifecycle)
        package:      npm package name (scoped names like @org/pkg are supported)
        from_version: Baseline version string
        to_version:   Target version string

    Returns:
        FetchResult with paths to extracted directories and tarball hashes
    """
    settings = get_settings()
    log.info("npm: fetching %s %s → %s", package, from_version, to_version)

    # ── STUB ──────────────────────────────────────────────────────────────────
    # Returns fixture directories. Replace with real tarball download logic.
    # The fixture simulates a package with a trivial file change.
    log.warning("npm fetcher is STUBBED — returning fixture data")

    from_td = tempfile.TemporaryDirectory(prefix="chainwatch-from-")
    to_td = tempfile.TemporaryDirectory(prefix="chainwatch-to-")

    from_dir = Path(from_td.name)
    to_dir = Path(to_td.name)

    # Minimal fixture: index.js with a trivial change between versions
    (from_dir / "index.js").write_text(
        f"// {package} v{from_version}\nmodule.exports = function() {{ return 'hello'; }};\n"
    )
    (from_dir / "package.json").write_text(
        f'{{"name": "{package}", "version": "{from_version}", "main": "index.js"}}\n'
    )

    (to_dir / "index.js").write_text(
        f"// {package} v{to_version}\nmodule.exports = function() {{ return 'hello world'; }};\n"
    )
    (to_dir / "package.json").write_text(
        f'{{"name": "{package}", "version": "{to_version}", "main": "index.js"}}\n'
    )

    from_sha256 = _sha256_dir(from_dir)
    to_sha256 = _sha256_dir(to_dir)

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

    # ── END STUB ──────────────────────────────────────────────────────────────


def _sha256_dir(directory: Path) -> str:
    """
    Compute a deterministic SHA256 over all files in a directory.

    Files are hashed in sorted order so the result is reproducible regardless
    of filesystem ordering.  Used for corpus integrity verification.
    """
    h = hashlib.sha256()
    for path in sorted(directory.rglob("*")):
        if path.is_file():
            h.update(path.read_bytes())
    return h.hexdigest()
