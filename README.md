# chainwatch

**LLM-assisted supply chain diff analyzer for detecting malicious package updates.**

chainwatch is a research tool that combines semantic diff analysis (powered by Claude) with live threat intelligence feeds to detect novel supply chain attacks — covering the detection gap between attack publication and signature-based tool coverage.

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌──────────────────┐
│   Package    │────▶│  Diff Engine │────▶│   LLM Analyzer   │
│   Fetcher    │     │  + Chunker   │     │  (Claude API)    │
└─────────────┘     └──────────────┘     └────────┬─────────┘
                                                   │
                    ┌──────────────┐               │
                    │ Feed Clients │               │
                    │ OSV · Rekor  │───────────────┤
                    │ · Scorecard  │               │
                    └──────────────┘               ▼
                                          ┌──────────────────┐
                                          │  Risk Aggregator  │
                                          │  → RiskReport     │
                                          └──────────────────┘
```

### Pipeline Stages

1. **Package Fetcher** — Downloads two versions from npm or PyPI registries
2. **Diff Engine** — Computes structured diffs filtered to source files
3. **Metadata Analyzer** — Surfaces dependency changes, install hooks, maintainer changes
4. **LLM Risk Analyzer** — Claude scores 6 risk dimensions (0–10 each)
5. **Feed Integrations** — OSV.dev, Sigstore/Rekor, OpenSSF Scorecard (parallel with LLM)
6. **Risk Aggregator** — Composite 0–100 score with severity bucket

### Risk Dimensions

| Dimension | Weight | What it detects |
|---|---|---|
| Network calls | 20% | New HTTP/DNS/socket connections |
| Obfuscation | 20% | base64, eval, dynamic require patterns |
| Resource exhaustion | 20% | Unbounded loops/recursion, unthrottled blocking calls (denial-of-service) |
| Install hooks | 15% | New postinstall/preinstall scripts |
| Env conditionals | 15% | CI detection, platform gating |
| Dependency changes | 10% | New transitive dependencies |

`resource_exhaustion` was added after the `colors` corpus entry
(`dataset/malicious/colors/`) showed a real denial-of-service attack
scoring LOW under the original five dimensions — none of them had any
concept of "this code never returns." See
`dataset/findings/README.md` recommendation #1.

## Quick Start

```bash
# Install
pip install -e ".[dev]"

# Set API key
export ANTHROPIC_API_KEY=sk-ant-...

# Analyse a package diff
chainwatch diff npm event-stream 3.3.4 3.3.5
chainwatch diff pypi requests 2.31.0 2.32.0

# JSON output for scripting
chainwatch --json diff npm lodash 4.17.20 4.17.21

# CI mode: exit 1 if score exceeds threshold
chainwatch diff npm lodash 4.17.20 4.17.21 --threshold 50

# Skip feed lookups (faster, offline-friendly)
chainwatch diff npm lodash 4.17.20 4.17.21 --no-feeds

# Scan a lockfile: diff every pinned dependency against its predecessor
# ("was the bump that put this exact version in my lockfile itself
# suspicious?"). Supports package-lock.json (npm) and requirements.txt
# (PyPI, exact `==` pins only) — yarn.lock is not yet supported.
chainwatch scan package-lock.json
chainwatch scan requirements.txt --threshold 50   # CI mode
chainwatch scan package-lock.json --limit 0        # no cap (default: 25 deps)

# Re-render a saved report without re-running the pipeline
chainwatch report dataset/malicious/event-stream/report-3.3.4-to-3.3.5.json
```

## Ground Truth Corpus

Five historical incidents, each with a `SOURCING.md` (why these versions),
`FINDINGS.md` (per-pair analysis), and real pipeline-run reports. In four
of the five, the actual malicious release was unpublished (or, for `ctx`,
deleted outright) before this project could diff it at the registry level —
see each `SOURCING.md` for what was recovered from git history / CDN
archives / independent archives / public writeups instead (`evidence/` in
each directory), and each `FINDINGS.md` for what the available
registry-diffable pairs actually scored.

| Package | Pair(s) run | Attack type | Registry-diffable? | Actual result |
|---|---|---|---|---|
| event-stream | 3.3.4→3.3.5, 3.3.5→4.0.0 | Maintainer handoff, crypto theft (2018) | No — `3.3.6` unpublished | LOW (benign-adjacent control) |
| flatmap-stream | 0.1.0→0.1.1 *(reconstructed)* | Same incident, the actual transitive payload | No — unpublished (npm serves only a security-holding placeholder for every version string); rebuilt from CDN-archaeology evidence (Wayback-cached, cross-validated against a paper's companion dataset) and diffed locally (never packaged/served) | **HIGH, 60.0/100** |
| ua-parser-js | 0.7.28→0.7.30, 0.7.30→0.7.31 | Account compromise, cryptominer (2021) | No — malicious versions unpublished | LOW (benign-adjacent control) |
| ua-parser-js | 0.7.28→0.7.29 *(reconstructed)* | Same incident, the complete miner/credential-stealer attack | No — unpublished; rebuilt on a real, still-published `0.7.28` base with recovered `preinstall` scripts spliced in and diffed locally (never packaged/served) | **HIGH, 67.0/100** — the corpus's highest score, reached over three runs (42.5 → 60.0 → 67.0) as two separate code gaps were found and fixed |
| colors | 1.3.3→1.4.0 | Maintainer protest-ware, infinite loop (2022) | No — sabotage never republished | LOW (benign-adjacent control) |
| colors | 1.4.0→1.4.44-liberty-2 *(reconstructed)* | Same incident, the complete sabotage | No — unpublished; rebuilt from the exact verified git commit and diffed locally (never packaged/served) | **MEDIUM, 35.0/100** — originally 7.5/LOW, missed outright; fixed by two code changes (see below) |
| node-ipc | 10.1.0→11.0.0 | Maintainer protest-ware, destructive wiper (2022) | **Yes** — compromised `peacenotwar` dep still on registry | **MEDIUM, 30.0/100** — originally 29.5/LOW, 0.5 points under MEDIUM; crossed by the same two fixes that resolved `colors` |
| node-ipc | 10.1.0→10.1.1 *(reconstructed)* | Same incident, the complete wiper | No — unpublished; rebuilt from the exact verified git commit and diffed locally (never packaged/served) | **HIGH, 62.5/100** (originally 69.0; rerun under the current weight matrix — still comfortably HIGH) |
| ctx (PyPI) | 0.1.2→0.1.2-1 *(reconstructed)* | Account takeover, environment-variable exfiltration (2022) | No — the entire PyPI project was deleted, not just the malicious versions; both sides rebuilt from independent archives (Software Heritage + Wayback Machine) and diffed locally | **MEDIUM, 41.5/100** — entirely LLM-driven, zero feed contribution |
| ctx (PyPI) | 0.1.2→0.2.5 *(reconstructed)* | Same incident, the final/complete malicious release | Same as above | **MEDIUM, 52.0/100** — entirely LLM-driven, zero feed contribution; the corpus's first ground-truth positive sourced independently of every fix built to catch it |

**As of 2026-08-11, every one of these seven malicious-labelled pairs
scores above LOW — 100% precision, 100% recall on this specific corpus** —
but read that as "every gap this corpus surfaced has a fix," not as a
general detection guarantee. node-ipc's complete attack scores far more
severely than its diluted registry remnant (LOW → HIGH) purely by having
the complete artifact — no code changed, reconstruction alone fixed it,
and the result is carried entirely by the LLM layer. flatmap-stream's
complete attack also reaches HIGH, but leans partly on a rare OSV
`malicious_floor` hit (the one time it fires anywhere in this corpus).
ua-parser-js's complete attack needed one code fix — chainwatch's diff
engine didn't recognise `.sh`/`.bat` as source files, so the two scripts
carrying the actual payload were never enumerated; widening
`SOURCE_EXTENSIONS` closed that gap. colors and node-ipc's diluted
registry pair both needed *two* further code changes: a sixth risk
dimension, `resource_exhaustion` (necessary — the model then scores
colors's infinite loop a perfect 10/10 — but not sufficient on its own,
since the weighted-sum formula caps what one dimension can contribute),
plus a new aggregator rule, `_apply_dimension_floor` (floors the score to
MEDIUM when any one dimension is both near-maximal and near-certain).
**Both of those fixes were designed by observing this exact corpus's
failures and validated only against this exact corpus.** `ctx` (PyPI,
added 2026-08-11) is a real, independently-sourced counter-check on that
caveat — reconstructed after both fixes already existed — and it
classifies correctly using neither of them: its attack shape (import-time
credential exfiltration, no install hook, no DoS component) never engages
`resource_exhaustion` or `_apply_dimension_floor` at all, so both of its
scores come entirely from the original five dimensions. That's real
evidence the rest of the pipeline generalises; it is **not** evidence that
those two specific mechanisms do — see `dataset/findings/README.md`'s
"overfitting caveat" and recommendation #7 before treating 100% recall as
more than "every known gap in this n=16 corpus is closed, and one
out-of-corpus check on the rest of the pipeline passed." Not every miss
had the same fix, and not every hit is carried the same way. A follow-up
attempt to source a real attack that would actually exercise
`resource_exhaustion`/`_apply_dimension_floor` (`coa`/`rc`, npm 2021) hit
a genuine sourcing wall — the real payload was never publicly recovered by
anyone — and is deliberately **not** counted among these seven; a
controlled experiment on the resulting placeholder files found that
20–28.5 points of the score came from descriptive prose alone (stripping
it to genuinely empty stub files dropped both pairs from HIGH to MEDIUM),
a separate finding about the LLM layer worth reading before trusting any
of these numbers on a famous, heavily-written-about incident
(`dataset/malicious/coa-rc/`).
A false-positive baseline (4 benign pairs, zero severity-level false
positives) lives in
`dataset/benign/`. Full detail, raw JSON reports, and reproduction
commands: `dataset/README.md`.

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Type checking
mypy src/

# Linting
ruff check src/ tests/
```

## Research Context

This tool is the empirical foundation for a security research publication examining:

1. Which detection layer (LLM, feeds, or both) catches each known attack
2. The time delta between attack publication and feed coverage (the "detection gap")
3. False positive rates on benign packages with suspicious-looking patterns
4. Comparison with signature-based classifiers on the same ground truth

## License

MIT
