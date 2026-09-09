"""
chainwatch.diff.engine
~~~~~~~~~~~~~~~~~~~~~~

Computes a structured diff between two extracted package directories.

The engine:
  1. Enumerates source files (filtered to .js / .ts / .py / .mjs / .cjs /
     .sh / .bat / .ps1 / .cmd)
  2. Categorises each file as added, removed, or modified
  3. Computes a unified diff for each modified/added file
  4. Extracts metadata-level changes (package.json, setup.py, pyproject.toml)
  5. Returns a ``DiffSummary`` — the raw input to the chunker and LLM

The engine is a pure function over two directories — no I/O beyond reading
files.  This makes it straightforward to test with fixture directories.

SOURCE_EXTENSIONS history: originally JS/TS/Python only. Widened to add
install-time script extensions (.sh/.bat/.ps1/.cmd) after the ua-parser-js
corpus reconstruction (dataset/malicious/ua-parser-js/) showed the gap
directly — a real 2021 attack whose payload lived entirely in
preinstall.sh/preinstall.bat scored MEDIUM instead of HIGH because those
two files were never enumerated, even though they were present in the
diffed directory and package.json's new "preinstall" hook pointed straight
at them. See dataset/findings/README.md recommendation #2 for the
before/after numbers.

Metadata parsing history: originally npm ``package.json`` plus the three
setuptools/PEP 621 manifests (``pyproject.toml``/``setup.cfg``/``setup.py``)
for dependencies, and npm-only for maintainer-change detection. Widened
2026-08-11, after the `ctx` corpus reconstruction
(dataset/malicious/ctx/) showed both gaps directly on a real 2022 attack:
a genuine new ``requirements.txt`` dependency (``Flask==2.1.0``, added by
the attacker) was invisible to ``new_dependencies`` because
``requirements.txt`` was parsed by nothing, and a genuine ``__author__``
change (the maintainer-identity signal npm packages already get) had no
PyPI equivalent at all. Neither gap caused a misclassification at the
time — the LLM caught both signals anyway by reading the diff text
directly — but both are now real, structured inputs rather than
LLM-inferred ones. See dataset/findings/README.md recommendation #10 for
the corpus writeup.
"""

from __future__ import annotations

import ast
import configparser
import difflib
import hashlib
import json
import logging
import tomllib
from pathlib import Path
from typing import Any

from packaging.requirements import InvalidRequirement, Requirement

from chainwatch.config import get_settings
from chainwatch.models import DiffSummary, FileDiff

log = logging.getLogger(__name__)

# Source file extensions we send to the LLM.
# Binary files, images, lock files, etc. are excluded.
#
# Includes install-time script extensions (.sh/.bat/.ps1/.cmd) alongside the
# JS/TS/Python source types — a real payload can live entirely in a
# preinstall/postinstall shell or batch script with only a thin dispatcher
# in JS (see dataset/malicious/ua-parser-js/FINDINGS.md: the diff engine
# used to miss exactly those two files for a real 2021 attack, holding the
# composite score at MEDIUM instead of HIGH).
SOURCE_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx", ".py", ".pyi",
        ".sh", ".bat", ".ps1", ".cmd",
    }
)

# Metadata files we parse for dependency/hook changes
METADATA_FILES: frozenset[str] = frozenset(
    {"package.json", "setup.py", "setup.cfg", "pyproject.toml", "requirements.txt"}
)


def compute_diff(from_dir: Path, to_dir: Path) -> DiffSummary:
    """
    Compute a structured diff between two extracted package directories.

    Args:
        from_dir: Extracted baseline version directory
        to_dir:   Extracted target version directory

    Returns:
        DiffSummary — the input contract for ``diff.chunker`` and ``analyzer.llm``
    """
    log.debug("Computing diff: %s → %s", from_dir, to_dir)

    from_files = _enumerate_source_files(from_dir)
    to_files = _enumerate_source_files(to_dir)

    from_paths = set(from_files)
    to_paths = set(to_files)

    added = sorted(to_paths - from_paths)
    removed = sorted(from_paths - to_paths)
    common = sorted(from_paths & to_paths)

    file_diffs: list[FileDiff] = []
    modified: list[str] = []
    # Files we refused to diff (over CHAINWATCH_MAX_DIFF_FILE_BYTES). Named
    # explicitly so the report — and the aggregator's caveats — can say the
    # LLM never saw them, rather than burying that in a placeholder string.
    skipped_files: list[str] = []

    for rel_path in common:
        from_path = from_dir / rel_path
        to_path = to_dir / rel_path
        oversized = _oversized_diff(from_path, to_path, rel_path)
        if oversized is not None:
            if _sha256_file(from_path) != _sha256_file(to_path):
                modified.append(rel_path)
                file_diffs.append(oversized)
                skipped_files.append(rel_path)
            continue

        from_text = from_path.read_text(errors="replace")
        to_text = to_path.read_text(errors="replace")
        if from_text == to_text:
            continue  # unchanged
        modified.append(rel_path)
        diff = _unified_diff(from_text, to_text, rel_path)
        file_diffs.append(diff)

    # Add new files as diffs too (all lines are additions)
    for rel_path in added:
        to_path = to_dir / rel_path
        if _file_exceeds_diff_limit(to_path):
            file_diffs.append(_skipped_file_diff(to_path, rel_path, "added"))
            skipped_files.append(rel_path)
            continue

        content = to_path.read_text(errors="replace")
        lines = content.splitlines()
        file_diffs.append(FileDiff(
            path=rel_path,
            change_type="added",
            lines_added=len(lines),
            lines_removed=0,
            unified_diff="\n".join(f"+{line}" for line in lines),
        ))

    total_lines = sum(
        (f.lines_added + f.lines_removed) for f in file_diffs
    )

    # Metadata extraction
    meta = _extract_metadata_diff(from_dir, to_dir)

    summary = DiffSummary(
        files_added=added,
        files_removed=removed,
        files_modified=modified,
        file_diffs=file_diffs,
        total_diff_lines=total_lines,
        skipped_files=skipped_files,
        **meta,
    )

    log.info(
        "Diff complete: +%d -%d ~%d files, %d total changed lines",
        len(added), len(removed), len(modified), total_lines,
    )
    return summary


# ── Internal helpers ──────────────────────────────────────────────────────────


def _enumerate_source_files(directory: Path) -> list[str]:
    """
    Return relative paths of all source files in a directory.

    Filters to SOURCE_EXTENSIONS only.  Paths are normalised with forward
    slashes for cross-platform reproducibility.
    """
    result = []
    for path in directory.rglob("*"):
        if path.is_file() and path.suffix.lower() in SOURCE_EXTENSIONS:
            rel = path.relative_to(directory)
            result.append(str(rel).replace("\\", "/"))
    return result


def _file_exceeds_diff_limit(path: Path) -> bool:
    settings = get_settings()
    try:
        return path.stat().st_size > settings.max_diff_file_bytes
    except OSError:
        return True


def _oversized_diff(from_path: Path, to_path: Path, rel_path: str) -> FileDiff | None:
    if not (_file_exceeds_diff_limit(from_path) or _file_exceeds_diff_limit(to_path)):
        return None
    return _skipped_file_diff(to_path, rel_path, "modified")


def _skipped_file_diff(path: Path, rel_path: str, change_type: str) -> FileDiff:
    settings = get_settings()
    try:
        size = path.stat().st_size
    except OSError:
        size = -1
    return FileDiff(
        path=rel_path,
        change_type=change_type,
        lines_added=0,
        lines_removed=0,
        unified_diff=(
            f"[diff skipped: file size {size} bytes exceeds "
            f"CHAINWATCH_MAX_DIFF_FILE_BYTES={settings.max_diff_file_bytes}]"
        ),
    )


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _unified_diff(from_text: str, to_text: str, path: str) -> FileDiff:
    """Compute a unified diff between two file contents."""
    from_lines = from_text.splitlines(keepends=True)
    to_lines = to_text.splitlines(keepends=True)

    diff_lines = list(difflib.unified_diff(
        from_lines,
        to_lines,
        fromfile=f"a/{path}",
        tofile=f"b/{path}",
        lineterm="",
    ))

    lines_added = sum(
        1 for line in diff_lines if line.startswith("+") and not line.startswith("+++")
    )
    lines_removed = sum(
        1 for line in diff_lines if line.startswith("-") and not line.startswith("---")
    )

    return FileDiff(
        path=path,
        change_type="modified",
        lines_added=lines_added,
        lines_removed=lines_removed,
        unified_diff="\n".join(diff_lines),
    )


def _extract_metadata_diff(from_dir: Path, to_dir: Path) -> dict[str, Any]:
    """
    Compare package metadata files between versions.

    Handles the npm ``package.json`` (dependencies, install hooks, author) and
    the three Python manifests — ``pyproject.toml``, ``setup.cfg``, and
    ``setup.py`` (dependency lists only, parsed statically; ``setup.py`` is
    never executed). Also flags newly-introduced native addons.

    Returns a dict matching the extra kwargs of DiffSummary's metadata fields.
    """
    result: dict[str, Any] = {
        "new_dependencies": [],
        "removed_dependencies": [],
        "new_install_hooks": [],
        "maintainer_changed": False,
        "native_addons_added": False,
    }

    from_deps: set[str] = set()
    to_deps: set[str] = set()

    # ── npm package.json ─────────────────────────────────────────────────────
    npm_from = _npm_manifest(from_dir / "package.json")
    npm_to = _npm_manifest(to_dir / "package.json")
    if npm_from is not None:
        from_deps |= npm_from["deps"]
    if npm_to is not None:
        to_deps |= npm_to["deps"]
    # Install hooks and maintainer changes are only meaningful when we can
    # compare two manifests, so keep the conservative both-present requirement.
    if npm_from is not None and npm_to is not None:
        for hook in ("postinstall", "preinstall", "install"):
            if hook not in npm_from["scripts"] and hook in npm_to["scripts"]:
                result["new_install_hooks"].append(hook)
        if npm_from["author"] != npm_to["author"]:
            result["maintainer_changed"] = True

    # ── Python: pyproject.toml / setup.cfg / setup.py / requirements.txt ─────
    from_deps |= _python_dependencies(from_dir)
    to_deps |= _python_dependencies(to_dir)

    result["new_dependencies"] = sorted(to_deps - from_deps)
    result["removed_dependencies"] = sorted(from_deps - to_deps)

    # ── PyPI maintainer-identity signal (setup.py / pyproject.toml authors) ──
    # npm's author-change check above already requires both manifests present
    # before comparing; mirror that conservatism here so a package that never
    # declared authorship doesn't spuriously flag on first declaring it.
    pypi_from_author = _pypi_author(from_dir)
    pypi_to_author = _pypi_author(to_dir)
    if (
        pypi_from_author is not None
        and pypi_to_author is not None
        and pypi_from_author != pypi_to_author
    ):
        result["maintainer_changed"] = True

    # ── Native addons (binding.gyp / compiled artifacts / C extensions) ──────
    result["native_addons_added"] = (
        _has_native_addons(to_dir) and not _has_native_addons(from_dir)
    )

    return result


def _npm_manifest(path: Path) -> dict[str, Any] | None:
    """Parse an npm package.json into {deps, scripts, author}, or None if absent."""
    if not path.is_file():
        return None
    try:
        meta = json.loads(path.read_text(errors="replace"))
    except (json.JSONDecodeError, OSError) as exc:
        log.warning("Failed to parse package.json metadata: %s", exc)
        return None
    deps = set((meta.get("dependencies") or {}).keys()) | set(
        (meta.get("devDependencies") or {}).keys()
    )
    return {
        "deps": deps,
        "scripts": meta.get("scripts") or {},
        "author": meta.get("author"),
    }


def _python_dependencies(directory: Path) -> set[str]:
    """Union of dependency names declared across the Python manifests."""
    return (
        _pyproject_dependencies(directory / "pyproject.toml")
        | _setup_cfg_dependencies(directory / "setup.cfg")
        | _setup_py_dependencies(directory / "setup.py")
        | _requirements_txt_dependencies(directory / "requirements.txt")
    )


def _requirement_name(spec: str) -> str | None:
    """Return the normalised distribution name from a PEP 508 requirement string."""
    spec = spec.strip().rstrip(",")
    if not spec:
        return None
    try:
        return Requirement(spec).name.lower()
    except (InvalidRequirement, ValueError):
        return None


def _pyproject_dependencies(path: Path) -> set[str]:
    if not path.is_file():
        return set()
    try:
        data = tomllib.loads(path.read_text(errors="replace"))
    except (tomllib.TOMLDecodeError, OSError) as exc:
        log.warning("Failed to parse pyproject.toml: %s", exc)
        return set()
    project = data.get("project") or {}
    specs: list[str] = list(project.get("dependencies") or [])
    for group in (project.get("optional-dependencies") or {}).values():
        specs.extend(group or [])
    # Build-time requirements are an install-time attack surface too.
    specs.extend((data.get("build-system") or {}).get("requires") or [])
    return {name for spec in specs if (name := _requirement_name(spec))}


def _setup_cfg_dependencies(path: Path) -> set[str]:
    if not path.is_file():
        return set()
    parser = configparser.ConfigParser(interpolation=None)
    try:
        parser.read_string(path.read_text(errors="replace"))
    except (configparser.Error, OSError) as exc:
        log.warning("Failed to parse setup.cfg: %s", exc)
        return set()
    lines: list[str] = []
    if parser.has_option("options", "install_requires"):
        lines.extend(parser.get("options", "install_requires").splitlines())
    if parser.has_section("options.extras_require"):
        for _extra, value in parser.items("options.extras_require"):
            lines.extend(value.splitlines())
    return {name for line in lines if (name := _requirement_name(line))}


def _setup_py_dependencies(path: Path) -> set[str]:
    """Statically extract literal install_requires/setup_requires from setup.py.

    Parses the AST only — the file is never imported or executed, which matters
    because a hostile package's setup.py is attacker-controlled code that would
    otherwise run arbitrary logic the moment we touched it.
    """
    if not path.is_file():
        return set()
    try:
        tree = ast.parse(path.read_text(errors="replace"))
    except (SyntaxError, ValueError, OSError) as exc:
        log.warning("Failed to parse setup.py: %s", exc)
        return set()
    names: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        for kw in node.keywords:
            if kw.arg not in ("install_requires", "setup_requires"):
                continue
            if not isinstance(kw.value, ast.List | ast.Tuple):
                continue
            for elt in kw.value.elts:
                if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                    name = _requirement_name(elt.value)
                    if name:
                        names.add(name)
    return names


def _requirements_txt_dependencies(path: Path) -> set[str]:
    """Parse a pip requirements.txt into a set of distribution names.

    Deliberately conservative: skips blank lines, ``#`` comments, and any
    line starting with ``-`` (pip options like ``-r other.txt``,
    ``--hash=...``, ``-e .`` editable installs — none of these are a
    literal package name, and ``-r``'s target isn't followed to avoid
    unbounded recursion into attacker-controlled paths).

    Unlike ``pyproject.toml``/``setup.cfg``/``setup.py``, a requirements.txt
    isn't necessarily enforced by the actual install (``setup.py``'s
    ``install_requires`` is what pip actually honours) — but a real 2022
    incident (dataset/malicious/ctx/) shipped a genuine new dependency
    here that was otherwise invisible to this analyzer, so it's treated as
    real signal rather than ignored as dev-only noise.
    """
    if not path.is_file():
        return set()
    try:
        text = path.read_text(errors="replace")
    except OSError as exc:
        log.warning("Failed to read requirements.txt: %s", exc)
        return set()
    names: set[str] = set()
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        if (name := _requirement_name(line)) is not None:
            names.add(name)
    return names


def _setup_py_author(path: Path) -> str | None:
    """Statically extract a literal author=/author_email= pair from setup.py.

    AST-only, same rationale as ``_setup_py_dependencies`` — a hostile
    package's setup.py is attacker-controlled code that must never be
    executed to inspect it.
    """
    if not path.is_file():
        return None
    try:
        tree = ast.parse(path.read_text(errors="replace"))
    except (SyntaxError, ValueError, OSError) as exc:
        log.warning("Failed to parse setup.py for author: %s", exc)
        return None
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        found: dict[str, str] = {}
        for kw in node.keywords:
            if kw.arg not in ("author", "author_email"):
                continue
            if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                found[kw.arg] = kw.value.value
        if found:
            return f"{found.get('author', '')} <{found.get('author_email', '')}>"
    return None


def _pyproject_authors(path: Path) -> str | None:
    """Extract PEP 621 ``[project] authors`` from pyproject.toml, if present."""
    if not path.is_file():
        return None
    try:
        data = tomllib.loads(path.read_text(errors="replace"))
    except (tomllib.TOMLDecodeError, OSError) as exc:
        log.warning("Failed to parse pyproject.toml for authors: %s", exc)
        return None
    authors = (data.get("project") or {}).get("authors")
    if not authors:
        return None
    parts = sorted(
        f"{a.get('name', '')} <{a.get('email', '')}>"
        for a in authors if isinstance(a, dict)
    )
    return "; ".join(parts) if parts else None


def _module_dunder_author(directory: Path) -> str | None:
    """Static ``__author__``/``__email__`` module dunders in top-level .py files.

    Small, single-module PyPI packages (the shape of dataset/malicious/ctx/,
    for instance) often carry authorship as informal ``__author__ =``/
    ``__email__ =`` assignments in the main module rather than in
    ``setup()``'s ``author=`` kwarg — which is exactly what that real 2022
    incident's attacker changed, and exactly what ``setup.py``'s own
    unmodified ``author=`` kwarg missed entirely. Deliberately shallow (top
    level only, not recursive) to stay cheap and avoid false matches in
    vendored dependencies or test fixtures.
    """
    found: dict[str, str] = {}
    for path in sorted(directory.glob("*.py")):
        try:
            tree = ast.parse(path.read_text(errors="replace"))
        except (SyntaxError, ValueError, OSError):
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            for target in node.targets:
                if (
                    isinstance(target, ast.Name)
                    and target.id in ("__author__", "__email__")
                    and isinstance(node.value, ast.Constant)
                    and isinstance(node.value.value, str)
                ):
                    found.setdefault(target.id, node.value.value)
        if found:
            break
    if not found:
        return None
    return f"{found.get('__author__', '')} <{found.get('__email__', '')}>"


def _pypi_author(directory: Path) -> str | None:
    """Combined maintainer-identity signal for a PyPI package tree.

    Deliberately combines, rather than short-circuits between, three
    independent sources -- PEP 621 ``pyproject.toml`` authors, a static
    setup.py ``author=`` read, and module-level ``__author__``/``__email__``
    dunders in a top-level .py file -- because a package can carry more
    than one of these at once, unchanged, while the *other* one is exactly
    what an attacker touched. That's not hypothetical: dataset/malicious/ctx/
    is a real 2022 incident whose setup.py ``author=`` kwarg was left
    untouched while ctx.py's ``__author__`` dunder was silently rewritten --
    an ``or``-based "use whichever source exists first" check would have
    picked the unchanged setup.py value for both sides and missed it
    entirely. Returns None only when *no* source declares authorship on
    this side, so the caller can still apply the same "both sides must have
    a value" conservatism the npm check uses.
    """
    parts = [
        _pyproject_authors(directory / "pyproject.toml"),
        _setup_py_author(directory / "setup.py"),
        _module_dunder_author(directory),
    ]
    if not any(parts):
        return None
    return "|".join(p or "" for p in parts)


_NATIVE_ADDON_EXTS: frozenset[str] = frozenset(
    {".node", ".so", ".pyd", ".dylib", ".dll", ".pyx"}
)


def _has_native_addons(directory: Path) -> bool:
    """True if the directory shows native-addon indicators (compiled or buildable)."""
    for path in directory.rglob("*"):
        if not path.is_file():
            continue
        if path.name == "binding.gyp":
            return True
        if path.suffix.lower() in _NATIVE_ADDON_EXTS:
            return True
    setup_py = directory / "setup.py"
    if setup_py.is_file():
        try:
            src = setup_py.read_text(errors="replace")
        except OSError:
            return False
        if "ext_modules" in src or "Extension(" in src:
            return True
    return False
