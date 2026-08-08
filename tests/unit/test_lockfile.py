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


# ── Unsupported / unrecognised formats ───────────────────────────────────────────


class TestUnsupportedFormats:
    def test_yarn_lock_raises_clear_error(self, tmp_path):
        path = tmp_path / "yarn.lock"
        path.write_text("# yarn lockfile v1\n")
        with pytest.raises(ValueError, match="not yet supported"):
            parse_lockfile(path)

    def test_unrecognised_filename_raises(self, tmp_path):
        path = tmp_path / "Pipfile.lock"
        path.write_text("{}")
        with pytest.raises(ValueError, match="Unrecognised lockfile"):
            parse_lockfile(path)
