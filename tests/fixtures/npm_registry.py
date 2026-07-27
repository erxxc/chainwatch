"""Offline npm registry fixtures for tests.

These helpers build real ``.tgz`` bytes in memory and serve npm metadata
through ``httpx.MockTransport``. Tests using them exercise the same metadata
and tarball flow as the live npm registry without making network calls or
committing binary fixture archives.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import tarfile
from dataclasses import dataclass, field
from typing import Any

import httpx


@dataclass(frozen=True)
class NpmFixtureVersion:
    package: str
    version: str
    files: dict[str, str]


@dataclass
class MockNpmRegistry:
    base_url: str = "https://registry.test"
    metadata: dict[str, dict[str, Any]] = field(default_factory=dict)
    tarballs: dict[str, bytes] = field(default_factory=dict)

    def add(self, fixture: NpmFixtureVersion) -> bytes:
        tarball = npm_tgz(fixture.files)
        metadata_path = f"/{fixture.package}"
        tarball_path = f"/{fixture.package}/-/{fixture.version}.tgz"

        package_metadata = self.metadata.setdefault(metadata_path, {"versions": {}})
        package_metadata["versions"][fixture.version] = {
            "dist": {
                "tarball": f"{self.base_url}{tarball_path}",
                "integrity": npm_integrity(tarball),
            }
        }
        self.tarballs[tarball_path] = tarball
        return tarball

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self._handle)

    def tarball(self, package: str, version: str) -> bytes:
        return self.tarballs[f"/{package}/-/{version}.tgz"]

    def _handle(self, request: httpx.Request) -> httpx.Response:
        if request.url.path in self.metadata:
            return httpx.Response(200, json=self.metadata[request.url.path])
        if request.url.path in self.tarballs:
            return httpx.Response(200, content=self.tarballs[request.url.path])
        return httpx.Response(404)


def npm_tgz(files: dict[str, str]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tf:
        for name, content in files.items():
            data = content.encode()
            info = tarfile.TarInfo(f"package/{name}")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def npm_integrity(content: bytes) -> str:
    digest = hashlib.sha512(content).digest()
    return "sha512-" + base64.b64encode(digest).decode()


def package_json(name: str, version: str, *, scripts: dict[str, str] | None = None) -> str:
    return json.dumps({
        "name": name,
        "version": version,
        "scripts": scripts or {},
    })
