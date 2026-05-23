"""
Shared archive safety helpers for package fetchers.

Package archives are attacker-controlled input.  These helpers keep downloads
and extraction bounded before the diff engine touches the filesystem.
"""

from __future__ import annotations

import asyncio
import logging
import tarfile
import zipfile
from pathlib import PurePosixPath

import httpx

from chainwatch.config import get_settings

log = logging.getLogger(__name__)


async def download_with_limit(
    client: httpx.AsyncClient,
    url: str,
    *,
    label: str,
) -> bytes:
    """Download a response body while enforcing the configured byte cap."""
    settings = get_settings()

    for attempt in range(settings.max_retries + 1):
        async with client.stream("GET", url) as resp:
            if resp.status_code == 429 and attempt < settings.max_retries:
                wait = 2 ** attempt
                log.warning("Rate limited downloading %s - retrying in %ds", label, wait)
                await resp.aclose()
                await asyncio.sleep(wait)
                continue

            resp.raise_for_status()
            content_length = resp.headers.get("content-length")
            if content_length is not None and int(content_length) > settings.max_download_bytes:
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

    raise RuntimeError(f"Exhausted retries downloading {url}")


def safe_archive_path(name: str) -> bool:
    """Return True only for relative POSIX archive paths without traversal."""
    if not name:
        return False
    path = PurePosixPath(name)
    return not path.is_absolute() and ".." not in path.parts


def validate_tar_members(members: list[tarfile.TarInfo], *, label: str) -> list[tarfile.TarInfo]:
    """Filter and validate tar members before extraction."""
    settings = get_settings()
    safe_members: list[tarfile.TarInfo] = []
    total_size = 0
    file_count = 0

    for member in members:
        if not safe_archive_path(member.name):
            log.warning("Skipping unsafe tar member: %s", member.name)
            continue
        if member.issym() or member.islnk():
            log.warning("Skipping archive link member: %s", member.name)
            continue
        if not (member.isfile() or member.isdir()):
            log.warning("Skipping unsupported tar member: %s", member.name)
            continue
        if member.isfile():
            file_count += 1
            total_size += member.size
            if member.size > settings.max_archive_file_bytes:
                raise ValueError(
                    f"{label} member {member.name} is too large: {member.size} bytes "
                    f"exceeds limit {settings.max_archive_file_bytes}"
                )
            if file_count > settings.max_archive_files:
                raise ValueError(
                    f"{label} archive has too many files: {file_count} exceeds "
                    f"limit {settings.max_archive_files}"
                )
            if total_size > settings.max_extracted_bytes:
                raise ValueError(
                    f"{label} archive expands to too many bytes: {total_size} exceeds "
                    f"limit {settings.max_extracted_bytes}"
                )
        safe_members.append(member)

    return safe_members


def validate_zip_infos(infos: list[zipfile.ZipInfo], *, label: str) -> list[zipfile.ZipInfo]:
    """Filter and validate zip members before extraction."""
    settings = get_settings()
    safe_infos: list[zipfile.ZipInfo] = []
    total_size = 0
    file_count = 0

    for info in infos:
        if not safe_archive_path(info.filename):
            log.warning("Skipping unsafe zip member: %s", info.filename)
            continue
        if _zipinfo_is_symlink(info):
            log.warning("Skipping archive symlink member: %s", info.filename)
            continue
        if info.is_dir():
            safe_infos.append(info)
            continue

        file_count += 1
        total_size += info.file_size
        if info.file_size > settings.max_archive_file_bytes:
            raise ValueError(
                f"{label} member {info.filename} is too large: {info.file_size} bytes "
                f"exceeds limit {settings.max_archive_file_bytes}"
            )
        if file_count > settings.max_archive_files:
            raise ValueError(
                f"{label} archive has too many files: {file_count} exceeds "
                f"limit {settings.max_archive_files}"
            )
        if total_size > settings.max_extracted_bytes:
            raise ValueError(
                f"{label} archive expands to too many bytes: {total_size} exceeds "
                f"limit {settings.max_extracted_bytes}"
            )
        safe_infos.append(info)

    return safe_infos


def _zipinfo_is_symlink(info: zipfile.ZipInfo) -> bool:
    unix_mode = info.external_attr >> 16
    return (unix_mode & 0o170000) == 0o120000
