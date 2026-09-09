"""
Unit tests for chainwatch.lockfile

Pure parsing logic — no network, no API calls.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from chainwatch.lockfile import LockedDependency, parse_lockfile
from chainwatch.models import Ecosystem

# ── npm: lockfileVersion 2/3 ("packages" schema) ────────────────────────────────


class TestNpmPackagesSchema:
    def _write(self, tmp_path: Path, packages: dict) -> Path:
        path = tmp_path / "package-lock.json"
        path.write_text(json.dumps({
            "name": "test-project",
            "lockfileVersion": 3,
            "packages": packages,
        }))
        return path

    def test_basic_parse(self, tmp_path):
        path = self._write(tmp_path, {
            "": {"name": "test-project", "version": "1.0.0"},
            "node_modules/lodash": {"version": "4.17.21"},
            "node_modules/husky": {"version": "5.1.0"},
        })
        eco, deps = parse_lockfile(path)
        assert eco == Ecosystem.npm
        assert LockedDependency("lodash", "4.17.21") in deps
        assert LockedDependency("husky", "5.1.0") in deps
        # The root entry ("") must not appear as a dependency.
        assert not any(d.name == "test-project" for d in deps)

    def test_scoped_package_name(self, tmp_path):
        path = self._write(tmp_path, {
            "": {"name": "test-project"},
            "node_modules/@babel/core": {"version": "7.24.0"},
        })
        _, deps = parse_lockfile(path)
        assert LockedDependency("@babel/core", "7.24.0") in deps

    def test_nested_deduped_dependency(self, tmp_path):
        """A package hoisted at top level and pinned differently deep in the tree."""
        path = self._write(tmp_path, {
            "": {},
            "node_modules/semver": {"version": "7.6.0"},
            "node_modules/@babel/core/node_modules/semver": {"version": "6.3.1"},
        })
        _, deps = parse_lockfile(path)
        assert LockedDependency("semver", "7.6.0") in deps
        assert LockedDependency("semver", "6.3.1") in deps

    def test_workspace_link_skipped(self, tmp_path):
        path = self._write(tmp_path, {
            "": {},
            "node_modules/my-workspace-pkg": {"resolved": "packages/foo", "link": True},
            "node_modules/lodash": {"version": "4.17.21"},
        })
        _, deps = parse_lockfile(path)
        assert not any(d.name == "my-workspace-pkg" for d in deps)
        assert LockedDependency("lodash", "4.17.21") in deps

    def test_entry_without_version_skipped(self, tmp_path):
        path = self._write(tmp_path, {
            "": {},
            "node_modules/git-dep": {"resolved": "git+https://example.com/x.git"},
        })
        _, deps = parse_lockfile(path)
        assert deps == []

    def test_result_sorted_by_name(self, tmp_path):
        path = self._write(tmp_path, {
            "": {},
            "node_modules/zebra": {"version": "1.0.0"},
            "node_modules/apple": {"version": "1.0.0"},
        })
        _, deps = parse_lockfile(path)
        assert [d.name for d in deps] == ["apple", "zebra"]


# ── npm: legacy lockfileVersion 1 ("dependencies" tree) ─────────────────────────


class TestNpmDependenciesSchema:
    def test_flat_dependencies(self, tmp_path):
        path = tmp_path / "package-lock.json"
        path.write_text(json.dumps({
            "lockfileVersion": 1,
            "dependencies": {
                "lodash": {"version": "4.17.21"},
                "husky": {"version": "5.1.0"},
            },
        }))
        eco, deps = parse_lockfile(path)
        assert eco == Ecosystem.npm
        assert LockedDependency("lodash", "4.17.21") in deps
        assert LockedDependency("husky", "5.1.0") in deps

    def test_nested_dependencies_walked_recursively(self, tmp_path):
        path = tmp_path / "package-lock.json"
        path.write_text(json.dumps({
            "lockfileVersion": 1,
            "dependencies": {
                "husky": {
                    "version": "5.1.0",
                    "dependencies": {
                        "chalk": {"version": "4.1.2"},
                    },
                },
            },
        }))
        _, deps = parse_lockfile(path)
        assert LockedDependency("husky", "5.1.0") in deps
        assert LockedDependency("chalk", "4.1.2") in deps


# ── npm: malformed input ─────────────────────────────────────────────────────────


class TestNpmMalformed:
    def test_invalid_json_raises(self, tmp_path):
        path = tmp_path / "package-lock.json"
        path.write_text("{ not valid json")
        with pytest.raises(ValueError, match="not valid JSON"):
            parse_lockfile(path)

    def test_neither_packages_nor_dependencies_raises(self, tmp_path):
        path = tmp_path / "package-lock.json"
        path.write_text(json.dumps({"name": "empty-lockfile"}))
        with pytest.raises(ValueError, match="not a recognisable lockfile"):
            parse_lockfile(path)

    def test_json_array_raises(self, tmp_path):
        path = tmp_path / "package-lock.json"
        path.write_text("[]")
        with pytest.raises(ValueError, match="does not contain a JSON object"):
            parse_lockfile(path)


# ── PyPI: requirements.txt ──────────────────────────────────────────────────────


class TestRequirementsTxt:
    def test_exact_pins_parsed(self, tmp_path):
        path = tmp_path / "requirements.txt"
        path.write_text("requests==2.32.0\nclick==8.1.7\n")
        eco, deps = parse_lockfile(path)
        assert eco == Ecosystem.pypi
        assert LockedDependency("requests", "2.32.0") in deps
        assert LockedDependency("click", "8.1.7") in deps

    def test_range_specifiers_skipped(self, tmp_path):
        path = tmp_path / "requirements.txt"
        path.write_text("numpy>=1.20\ndjango~=4.2\nunpinned\n")
        _, deps = parse_lockfile(path)
        assert deps == []

    def test_extras_stripped_from_name(self, tmp_path):
        path = tmp_path / "requirements.txt"
        path.write_text("flask[async]==3.0.0\n")
        _, deps = parse_lockfile(path)
        assert LockedDependency("flask", "3.0.0") in deps

    def test_environment_marker_stripped(self, tmp_path):
        path = tmp_path / "requirements.txt"
        path.write_text('click==8.1.7 ; python_version >= "3.8"\n')
        _, deps = parse_lockfile(path)
        assert LockedDependency("click", "8.1.7") in deps

    def test_comments_and_blank_lines_ignored(self, tmp_path):
        path = tmp_path / "requirements.txt"
        path.write_text("# a comment\n\nrequests==2.32.0  # inline comment\n")
        _, deps = parse_lockfile(path)
        assert deps == [LockedDependency("requests", "2.32.0")]

    def test_pip_options_skipped(self, tmp_path):
        path = tmp_path / "requirements.txt"
        path.write_text("-r other-requirements.txt\n--hash=sha256:abcdef\nrequests==2.32.0\n")
        _, deps = parse_lockfile(path)
        assert deps == [LockedDependency("requests", "2.32.0")]

    def test_duplicate_pin_deduped(self, tmp_path):
        path = tmp_path / "requirements.txt"
        path.write_text("requests==2.32.0\nrequests==2.32.0\n")
        _, deps = parse_lockfile(path)
        assert deps == [LockedDependency("requests", "2.32.0")]

    def test_requirements_dev_txt_also_detected(self, tmp_path):
        """Filenames like requirements-dev.txt should still be detected as pypi."""
        path = tmp_path / "requirements-dev.txt"
        path.write_text("pytest==8.1.0\n")
        eco, deps = parse_lockfile(path)
        assert eco == Ecosystem.pypi
        assert deps == [LockedDependency("pytest", "8.1.0")]


# ── npm: yarn.lock ───────────────────────────────────────────────────────────────

_YARN_V1 = """\
# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.
# yarn lockfile v1


"@babel/code-frame@^7.0.0", "@babel/code-frame@^7.10.4":
  version "7.12.11"
  resolved "https://registry.yarnpkg.com/@babel/code-frame/-/code-frame-7.12.11.tgz#f4ad435a"
  integrity sha512-Zt/placeholder==
  dependencies:
    "@babel/highlight" "^7.10.4"

lodash@^4.17.15, lodash@^4.17.20:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz#679591c5"
  integrity sha512-v2/placeholder==

"my-git-dep@git+https://github.com/example/dep.git":
  version "1.0.0"
  resolved "git+https://github.com/example/dep.git#abc123"

"local-dep@file:../local-dep":
  version "0.1.0"

version@^1.0.0:
  version "1.2.3"
  resolved "https://registry.yarnpkg.com/version/-/version-1.2.3.tgz#deadbeef"

chalk@^4.1.0:
  version "4.1.2"
  resolved "https://registry.yarnpkg.com/chalk/-/chalk-4.1.2.tgz#aac4e2b7"
  dependencies:
    version "^1.0.0"
"""

_YARN_BERRY = """\
# This file is generated by running "yarn install" inside your project.
# Manual changes might be lost - proceed with caution!

__metadata:
  version: 6
  cacheKey: 8

"@babel/code-frame@npm:^7.0.0, @babel/code-frame@npm:^7.10.4":
  version: 7.12.11
  resolution: "@babel/code-frame@npm:7.12.11"
  dependencies:
    "@babel/highlight": ^7.10.4
  checksum: 3a/placeholder
  languageName: node
  linkType: hard

"lodash@npm:^4.17.21":
  version: 4.17.21
  resolution: "lodash@npm:4.17.21"
  checksum: 4b/placeholder
  languageName: node
  linkType: hard

"my-app@workspace:.":
  version: 0.0.0-use.local
  resolution: "my-app@workspace:."
  dependencies:
    lodash: ^4.17.21
  languageName: unknown
  linkType: soft

"string-width-cjs@npm:string-width@^4.2.0":
  version: 4.2.3
  resolution: "string-width@npm:4.2.3"
  languageName: node
  linkType: hard

"left-pad@patch:left-pad@npm%3A1.3.0#./.yarn/patches/left-pad.patch":
  version: 1.3.0
  resolution: "left-pad@patch:left-pad@npm%3A1.3.0#./.yarn/patches/left-pad.patch"
"""


class TestYarnLock:
    def test_v1_registry_entries_parsed(self, tmp_path):
        path = tmp_path / "yarn.lock"
        path.write_text(_YARN_V1)
        eco, deps = parse_lockfile(path)
        assert eco == Ecosystem.npm
        assert LockedDependency("@babel/code-frame", "7.12.11") in deps
        assert LockedDependency("lodash", "4.17.21") in deps
        assert LockedDependency("chalk", "4.1.2") in deps

    def test_v1_multiple_specifiers_collapse_to_one_dependency(self, tmp_path):
        path = tmp_path / "yarn.lock"
        path.write_text(_YARN_V1)
        _, deps = parse_lockfile(path)
        assert [d for d in deps if d.name == "lodash"] == [LockedDependency("lodash", "4.17.21")]

    def test_v1_non_registry_entries_skipped(self, tmp_path):
        path = tmp_path / "yarn.lock"
        path.write_text(_YARN_V1)
        _, deps = parse_lockfile(path)
        names = {d.name for d in deps}
        assert "my-git-dep" not in names
        assert "local-dep" not in names

    def test_v1_package_named_version_is_not_confused_with_the_version_field(self, tmp_path):
        """A real npm package is called `version`; a dependency on it must not
        overwrite the enclosing entry's own version (it sits at deeper indent
        and its value is a range, not a version)."""
        path = tmp_path / "yarn.lock"
        path.write_text(_YARN_V1)
        _, deps = parse_lockfile(path)
        assert LockedDependency("version", "1.2.3") in deps
        assert not any(d.version.startswith("^") for d in deps)
        assert LockedDependency("chalk", "4.1.2") in deps

    def test_berry_registry_entries_parsed(self, tmp_path):
        path = tmp_path / "yarn.lock"
        path.write_text(_YARN_BERRY)
        eco, deps = parse_lockfile(path)
        assert eco == Ecosystem.npm
        assert LockedDependency("@babel/code-frame", "7.12.11") in deps
        assert LockedDependency("lodash", "4.17.21") in deps

    def test_berry_metadata_block_and_workspace_skipped(self, tmp_path):
        path = tmp_path / "yarn.lock"
        path.write_text(_YARN_BERRY)
        _, deps = parse_lockfile(path)
        names = {d.name for d in deps}
        assert "__metadata" not in names
        assert "my-app" not in names
        assert not any(d.version == "6" for d in deps)

    def test_berry_alias_resolves_to_real_package_name(self, tmp_path):
        path = tmp_path / "yarn.lock"
        path.write_text(_YARN_BERRY)
        _, deps = parse_lockfile(path)
        assert LockedDependency("string-width", "4.2.3") in deps
        assert not any(d.name == "string-width-cjs" for d in deps)

    def test_berry_patched_dependency_skipped(self, tmp_path):
        path = tmp_path / "yarn.lock"
        path.write_text(_YARN_BERRY)
        _, deps = parse_lockfile(path)
        assert not any(d.name == "left-pad" for d in deps)

    def test_header_only_file_yields_no_dependencies(self, tmp_path):
        path = tmp_path / "yarn.lock"
        path.write_text("# yarn lockfile v1\n")
        eco, deps = parse_lockfile(path)
        assert eco == Ecosystem.npm
        assert deps == []

    def test_result_sorted_by_name(self, tmp_path):
        path = tmp_path / "yarn.lock"
        path.write_text(_YARN_V1)
        _, deps = parse_lockfile(path)
        assert [d.name for d in deps] == sorted(d.name for d in deps)


# ── Unsupported / unrecognised formats ───────────────────────────────────────────


class TestUnsupportedFormats:
    def test_unrecognised_filename_raises(self, tmp_path):
        path = tmp_path / "Pipfile.lock"
        path.write_text("{}")
        with pytest.raises(ValueError, match="Unrecognised lockfile"):
            parse_lockfile(path)
