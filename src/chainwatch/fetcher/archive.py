"""
Shared archive safety helpers for package fetchers.

Package archives are attacker-controlled input.  These helpers keep downloads
and extraction bounded before the diff engine touches the filesystem.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import tarfile
import zipfile
from pathlib import PurePosixPath
from urllib.parse import urljoin, urlsplit

import httpx

from chainwatch.config import get_settings

log = logging.getLogger(__name__)

_MAX_DOWNLOAD_REDIRECTS = 5


async def download_with_limit(
    client: httpx.AsyncClient,
    url: str,
    *,
    label: str,
    allowed_hosts: frozenset[str] | None = None,
) -> bytes:
    """Download a response body while enforcing the configured byte cap.

    ``allowed_hosts`` further restricts the URL host (and any redirect target)
    to a caller-supplied allow-list. Without it, only the cleartext / loopback /
    private-IP / credentialled-URL guards apply, which still leaves the request
    free to land on any public host the registry response points at.
    """
    settings = get_settings()
    current_url = _validate_download_url(url, label=label, allowed_hosts=allowed_hosts)
    redirects_followed = 0
    retry_attempt = 0

    while True:
        async with client.stream("GET", current_url, follow_redirects=False) as resp:
            if resp.is_redirect:
                if redirects_followed >= _MAX_DOWNLOAD_REDIRECTS:
                    raise ValueError(f"{label} archive exceeded redirect limit")
                location = resp.headers.get("location")
                if not location:
                    raise ValueError(f"{label} archive redirect missing Location header")
                current_url = _validate_download_url(
                    urljoin(str(resp.url), location),
                    label=label,
                    allowed_hosts=allowed_hosts,
                )
                redirects_followed += 1
                continue

            if resp.status_code == 429 and retry_attempt < settings.max_retries:
                wait = 2 ** retry_attempt
                retry_attempt += 1
                log.warning("Rate limited downloading %s - retrying in %ds", label, wait)
                await resp.aclose()
                await asyncio.sleep(wait)
                continue

            resp.raise_for_status()
            content_length = resp.headers.get("content-length")
            if (
                content_length is not None
                and int(content_length) > settings.max_download_bytes
            ):
                raise ValueError(
                    f"{label} archive is too large: {content_length} bytes exceeds "
                    f"limit {settings.max_download_bytes}"
                )

            chunks: list[bytes] = []
            total = 0
            async for chunk in resp.aiter_bytes():
                total += len(chunk)
                if total > settings.max_download_bytes:
                    raise ValueError(
                        f"{label} archive download exceeded limit "
                        f"{settings.max_download_bytes} bytes"
                    )
                chunks.append(chunk)
            return b"".join(chunks)


def _validate_download_url(
    url: str,
    *,
    label: str,
    allowed_hosts: frozenset[str] | None = None,
) -> str:
    """
    Validate an archive URL before httpx connects to it.

    Registry metadata is remote input.  Without this guard, a malicious or
    compromised registry response could make the CLI request localhost, cloud
    metadata IPs, or cleartext endpoints while resolving a package archive.

    When ``allowed_hosts`` is provided, the URL host (and any redirect target)
    must be a case-insensitive exact match for one of the entries — this is the
    backstop against a hostile registry pointing ``dist.tarball`` at an
    arbitrary public host.
    """
    parsed = urlsplit(url)
    if parsed.scheme != "https":
        raise ValueError(f"{label} archive URL must use https: {url}")
    if parsed.username or parsed.password:
        raise ValueError(f"{label} archive URL must not contain credentials")
    if not parsed.hostname:
        raise ValueError(f"{label} archive URL is missing a host")

    host = parsed.hostname.rstrip(".").lower()
    if host == "localhost" or host.endswith(".localhost"):
        raise ValueError(f"{label} archive URL must not target localhost")

    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        if not ip.is_global:
            raise ValueError(f"{label} archive URL must not target a non-public IP")

    normalized_allowed_hosts = (
        None if allowed_hosts is None else frozenset(h.rstrip(".").lower() for h in allowed_hosts)
    )
    if normalized_allowed_hosts is not None and host not in normalized_allowed_hosts:
        raise ValueError(
            f"{label} archive URL host {host!r} is not in the allow-list "
            f"{sorted(normalized_allowed_hosts)}"
        )
    return url


def host_from_url(url: str) -> str:
    """Return the lowercased hostname of ``url`` or raise ValueError."""
    host = (urlsplit(url).hostname or "").rstrip(".").lower()
    if not host:
        raise ValueError(f"could not extract host from URL: {url!r}")
    return host


def configured_archive_hosts() -> frozenset[str]:
    """Return user-configured extra archive hosts."""
    raw_hosts = get_settings().allowed_archive_hosts
    if not raw_hosts:
        return frozenset()
    return frozenset(
        _normalize_host_entry(entry)
        for entry in raw_hosts.split(",")
        if entry.strip()
    )


def _normalize_host_entry(entry: str) -> str:
    entry = entry.strip()
    host = host_from_url(entry) if "://" in entry else entry.rstrip(".").lower()
    if not host:
        raise ValueError("archive host allow-list contains an empty host")
    return host


def safe_archive_path(name: str) -> bool:
    """Return True only for relative POSIX archive paths without traversal."""
    if not name or "\\" in name:
        return False
    path = PurePosixPath(name)
    return not path.is_absolute() and ".." not in path.parts


def extract_tar_safely(tar: tarfile.TarFile, dest: str, *, label: str) -> None:
    """Validate and extract tar members incrementally to avoid member-list DoS."""
    state = _ArchiveValidationState(label=label)
    for member in tar:
        if _validate_tar_member(member, state):
            tar.extract(member, path=dest, filter="data")


def validate_tar_members(members: list[tarfile.TarInfo], *, label: str) -> list[tarfile.TarInfo]:
    """Filter and validate tar members before extraction."""
    state = _ArchiveValidationState(label=label)
    safe_members: list[tarfile.TarInfo] = []

    for member in members:
        if _validate_tar_member(member, state):
            safe_members.append(member)

    return safe_members


def validate_zip_infos(infos: list[zipfile.ZipInfo], *, label: str) -> list[zipfile.ZipInfo]:
    """Filter and validate zip members before extraction."""
    state = _ArchiveValidationState(label=label)
    safe_infos: list[zipfile.ZipInfo] = []

    for info in infos:
        state.count_member()
        if not safe_archive_path(info.filename):
            log.warning("Skipping unsafe zip member: %s", info.filename)
            continue
        if _zipinfo_is_symlink(info):
            log.warning("Skipping archive symlink member: %s", info.filename)
            continue
        if info.is_dir():
            safe_infos.append(info)
            continue

        state.count_file(info.filename, info.file_size)
        safe_infos.append(info)

    return safe_infos


class _ArchiveValidationState:
    def __init__(self, *, label: str) -> None:
        self.label = label
        self.settings = get_settings()
        self.member_count = 0
        self.total_size = 0

    def count_member(self) -> None:
        self.member_count += 1
        if self.member_count > self.settings.max_archive_files:
            raise ValueError(
                f"{self.label} archive has too many members: {self.member_count} exceeds "
                f"limit {self.settings.max_archive_files}"
            )

    def count_file(self, name: str, size: int) -> None:
        self.total_size += size
        if size > self.settings.max_archive_file_bytes:
            raise ValueError(
                f"{self.label} member {name} is too large: {size} bytes "
                f"exceeds limit {self.settings.max_archive_file_bytes}"
            )
        if self.total_size > self.settings.max_extracted_bytes:
            raise ValueError(
                f"{self.label} archive expands to too many bytes: {self.total_size} exceeds "
                f"limit {self.settings.max_extracted_bytes}"
            )


def _validate_tar_member(member: tarfile.TarInfo, state: _ArchiveValidationState) -> bool:
    state.count_member()
    if not safe_archive_path(member.name):
        log.warning("Skipping unsafe tar member: %s", member.name)
        return False
    if member.issym() or member.islnk():
        log.warning("Skipping archive link member: %s", member.name)
        return False
    if not (member.isfile() or member.isdir()):
        log.warning("Skipping unsupported tar member: %s", member.name)
        return False
    if member.isfile():
        state.count_file(member.name, member.size)
    return True


def _zipinfo_is_symlink(info: zipfile.ZipInfo) -> bool:
    unix_mode = info.external_attr >> 16
    return (unix_mode & 0o170000) == 0o120000
