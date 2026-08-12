"""
chainwatch.lockfile
~~~~~~~~~~~~~~~~~~~

Parses a dependency lockfile into a flat list of (name, locked version)
pairs for ``chainwatch scan``.

Supported today:
  - ``package-lock.json`` — both the modern flat ``packages`` schema
    (npm 7+, lockfileVersion 2/3) and the legacy nested ``dependencies``
    tree (npm <7, lockfileVersion 1). ``packages`` is preferred when both
    are present, since v2/v3 lockfiles keep the nested tree only for
    backward compatibility and ``packages`` is the authoritative one.
  - ``requirements.txt`` — exact pins only (``name==1.2.3``). Range
    specifiers (``>=``, ``~=``, ...) don't name a single concrete version
    to diff against and are skipped, not guessed at.

Not yet supported: ``yarn.lock`` (a bespoke, non-JSON format — a real
parser is a separate, larger effort, not something worth guessing at with
regexes). Detected and rejected with a clear error rather than silently
producing wrong or partial results.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from chainwatch.models import Ecosystem


@dataclass(frozen=True)
class LockedDependency:
    """One resolved (name, version) pair found in a lockfile."""

    name: str
    version: str


def parse_lockfile(path: Path) -> tuple[Ecosystem, list[LockedDependency]]:
    """
    Detect a lockfile's ecosystem from its filename and parse it.

    Returns the ecosystem plus every distinct (name, version) pair found,
    sorted by name for deterministic ``--limit`` truncation downstream.

    Raises:
        ValueError: Unrecognised filename, unsupported format (``yarn.lock``),
                    or content that doesn't parse as the expected format.
    """
    name = path.name.lower()
    text = path.read_text(encoding="utf-8")

    if name == "package-lock.json":
        deps = _parse_npm_lockfile(text)
        return Ecosystem.npm, deps
    if name == "yarn.lock":
        raise ValueError(
            "yarn.lock is not yet supported (it's a bespoke, non-JSON format — "
            "a real parser is future work, not implemented here). "
            "Use package-lock.json instead, or run `chainwatch diff` on "
            "individual packages."
        )
    if name.startswith("requirements") and name.endswith(".txt"):
        deps = _parse_requirements_txt(text)
        return Ecosystem.pypi, deps

    raise ValueError(
        f"Unrecognised lockfile: {path.name!r}. "
        "Supported: package-lock.json, requirements*.txt."
    )


# ── npm: package-lock.json ──────────────────────────────────────────────────────


def _parse_npm_lockfile(text: str) -> list[LockedDependency]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"package-lock.json is not valid JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError("package-lock.json does not contain a JSON object")

    seen: dict[tuple[str, str], LockedDependency] = {}

    packages = data.get("packages")
    if isinstance(packages, dict):
        for pkg_path, info in packages.items():
            if not pkg_path:  # "" is the root project itself, not a dependency
                continue
            if not isinstance(info, dict) or info.get("link"):
                continue  # workspace symlinks have no independent version to diff
            version = info.get("version")
            dep_name = _name_from_packages_path(pkg_path)
            if version and dep_name:
                key = (dep_name, version)
                seen.setdefault(key, LockedDependency(name=dep_name, version=version))
    else:
        # Legacy lockfileVersion 1: nested "dependencies" tree.
        dependencies = data.get("dependencies")
        if not isinstance(dependencies, dict):
            raise ValueError(
                "package-lock.json has neither a `packages` nor a `dependencies` "
                "object — not a recognisable lockfile"
            )
        for dep in _walk_v1_dependencies(dependencies):
            seen.setdefault((dep.name, dep.version), dep)

    return sorted(seen.values(), key=lambda d: (d.name, d.version))


def _name_from_packages_path(pkg_path: str) -> str | None:
    """
    Recover a package name from a `packages` map key.

    Keys are node_modules-relative paths, e.g. ``node_modules/lodash`` or,
    for de-duplicated nested installs, ``node_modules/foo/node_modules/bar``
    — the package name is always everything after the *last*
    ``node_modules/`` segment, which also correctly preserves scoped names
    (``node_modules/@babel/core`` -> ``@babel/core``, no extra slash to
    confuse the split since the scope separator isn't "node_modules/").
    """
    if "node_modules/" not in pkg_path:
        return None
    return pkg_path.rsplit("node_modules/", 1)[1]


def _walk_v1_dependencies(dependencies: dict[str, Any]) -> list[LockedDependency]:
    """Recursively flatten a lockfileVersion 1 nested `dependencies` tree."""
    result: list[LockedDependency] = []
    for name, info in dependencies.items():
        if not isinstance(info, dict):
            continue
        version = info.get("version")
        if version:
            result.append(LockedDependency(name=name, version=version))
        nested = info.get("dependencies")
        if isinstance(nested, dict):
            result.extend(_walk_v1_dependencies(nested))
    return result


# ── PyPI: requirements.txt ──────────────────────────────────────────────────────

# Matches `name==1.2.3`, optionally with extras (`name[extra]==1.2.3`) and a
# trailing environment marker (`; python_version >= "3.8"`) or comment.
# Anything not an exact `==` pin (`>=`, `~=`, `*`, unpinned, ...) doesn't name
# a single concrete version and is intentionally not matched.
_REQUIREMENTS_PIN_RE = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9._-]*?)(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9.!+_-]+)"
)


def _parse_requirements_txt(text: str) -> list[LockedDependency]:
    seen: dict[tuple[str, str], LockedDependency] = {}
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue  # blank, comment-only, or a pip option (-r, -e, --hash, ...)
        match = _REQUIREMENTS_PIN_RE.match(line)
        if not match:
            continue  # not an exact pin — nothing concrete to diff against
        name, version = match.group(1), match.group(2)
        seen.setdefault((name, version), LockedDependency(name=name, version=version))
    return sorted(seen.values(), key=lambda d: (d.name, d.version))
