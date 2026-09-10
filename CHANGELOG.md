# Changelog

All notable changes to chainwatch are recorded here. Every release is
archived on Zenodo under the concept DOI
[10.5281/zenodo.21908505](https://doi.org/10.5281/zenodo.21908505); the
version-specific DOI is listed per release once Zenodo mints it.

## [0.2.0] — 2026-09-10

Version DOI: [10.5281/zenodo.21923286](https://doi.org/10.5281/zenodo.21923286)

### Added

- **Report schema 0.3.0.** Reports carry `timings` (per-stage wall-clock
  seconds), `caveats[]` (plain-language statements about evidence the LLM
  did not see, built from the diff summary only, never from LLM text), and
  diff-visibility fields on `diff_summary`: `truncated_files`,
  `skipped_files`, `large_files_split`, `split_files`, `comments_stripped`,
  `comment_lines_stripped`. All additive with defaults; 0.1.0 and 0.2.0
  reports still validate.
- **`--strip-comments`** on `diff` and `scan`: removes whole-line and block
  comments before the LLM sees the diff — the narrative-leakage control
  from `dataset/findings/README.md` recommendation #8 as a one-flag rerun.
  Never strips a line it cannot verify is a comment.
- **`--split-large-files`** on `diff` and `scan`: sends an oversized file
  diff in consecutive parts instead of cutting it head-first at the token
  budget, with giant single lines hard-split. Parts per file are capped by
  the new `CHAINWATCH_MAX_SPLIT_PARTS_PER_FILE` setting (default 16). Off
  by default so existing corpus numbers keep their meaning.
- **yarn.lock** support in `scan`: classic v1 and Yarn Berry; registry
  packages only; Berry aliases resolve to the real package name.
- A committed `uv.lock`, and this changelog.

### Changed

- The chunker's truncation notice now tells the LLM how many characters
  were omitted, and the Rich report renders a CAVEATS section plus stage
  timings in the provenance footer.
- `.gitignore` no longer carries two dead trailing-comment lines that were
  meant to exempt `uv.lock` and `.python-version`.
- Report timestamps across `dataset/` are normalised to `T00:00:00Z` on
  the run date, as `dataset/README.md` already stated; 30 of 34 files had
  kept real times.

### Research corpus

- **coa/rc**: a third condition — the narrated placeholder trees run with
  `--strip-comments` — plus one repeat run. Attributes 12.5–13.5 of the
  20–28.5 point narrated-vs-silent gap to the prose itself, and names two
  further leakage paths from the tool's own notices (`(no diff content)`
  and the stripped-comments preamble line). Filed as `inconclusive-*`;
  no precision/recall figure changes.
- **lodash 4.17.20 → 4.17.21**: baseline rerun reproduces the August base
  score exactly; `--strip-comments` (base 4.0 → 3.0) and
  `--split-large-files` (4.0 → 3.5) deltas recorded; first `timings` data
  points. Filed as `experiment-*`.

## [0.1.0] — 2026-08-12

Version DOI: [10.5281/zenodo.21908506](https://doi.org/10.5281/zenodo.21908506)

First release. `diff`, `scan`, and `report` CLI for npm and PyPI; six
weighted risk dimensions plus a dimension floor for single-vector attacks
and an OSV malicious-advisory floor; four concurrent feeds (OSV,
Rekor/Sigstore for npm and PyPI PEP 740, OpenSSF Scorecard, and a
new-dependency provenance heuristic); bounded-concurrency LLM chunk
analysis and lockfile scanning; a ground-truth corpus of six real,
independently sourced incidents plus nine benign controls, with the full
write-up, precision/recall analysis, and overfitting caveat in
`dataset/findings/README.md`.
