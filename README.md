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
4. **LLM Risk Analyzer** — Claude scores 5 risk dimensions (0–10 each)
5. **Feed Integrations** — OSV.dev, Sigstore/Rekor, OpenSSF Scorecard (parallel with LLM)
6. **Risk Aggregator** — Composite 0–100 score with severity bucket

### Risk Dimensions

| Dimension | Weight | What it detects |
|---|---|---|
| Network calls | 25% | New HTTP/DNS/socket connections |
| Obfuscation | 25% | base64, eval, dynamic require patterns |
| Install hooks | 20% | New postinstall/preinstall scripts |
| Env conditionals | 15% | CI detection, platform gating |
| Dependency changes | 15% | New transitive dependencies |

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

Four historical incidents, each with a `SOURCING.md` (why these versions),
`FINDINGS.md` (per-pair analysis), and real pipeline-run reports. In three
of the four, the actual malicious release was unpublished from npm before
this project could diff it at the registry level — see each `SOURCING.md`
for what was recovered from git history / CDN archives / public writeups
instead (`evidence/` in each directory), and each `FINDINGS.md` for what the
available registry-diffable pairs actually scored.

| Package | Pair(s) run | Attack type | Registry-diffable? | Actual result |
|---|---|---|---|---|
| event-stream | 3.3.4→3.3.5, 3.3.5→4.0.0 | Maintainer handoff, crypto theft (2018) | No — `3.3.6` unpublished | LOW (benign-adjacent control) |
| flatmap-stream | 0.1.0→0.1.1 *(reconstructed)* | Same incident, the actual transitive payload | No — unpublished (npm serves only a security-holding placeholder for every version string); rebuilt from CDN-archaeology evidence (Wayback-cached, cross-validated against a paper's companion dataset) and diffed locally (never packaged/served) | **HIGH, 60.0/100** |
| ua-parser-js | 0.7.28→0.7.30, 0.7.30→0.7.31 | Account compromise, cryptominer (2021) | No — malicious versions unpublished | LOW (benign-adjacent control) |
| ua-parser-js | 0.7.28→0.7.29 *(reconstructed)* | Same incident, the complete miner/credential-stealer attack | No — unpublished; rebuilt on a real, still-published `0.7.28` base with recovered `preinstall` scripts spliced in and diffed locally (never packaged/served) | **HIGH, 60.0/100** — first scored MEDIUM (42.5), held short by a diff-engine file-extension gap fixed the same day; this is the post-fix rerun |
| colors | 1.3.3→1.4.0 | Maintainer protest-ware, infinite loop (2022) | No — sabotage never republished | LOW (benign-adjacent control) |
| colors | 1.4.0→1.4.44-liberty-2 *(reconstructed)* | Same incident, the complete sabotage | No — unpublished; rebuilt from the exact verified git commit and diffed locally (never packaged/served) | **LOW, 7.5/100 — still missed, even complete** |
| node-ipc | 10.1.0→11.0.0 | Maintainer protest-ware, destructive wiper (2022) | **Yes** — compromised `peacenotwar` dep still on registry | LOW, 29.5/100 — 0.5 points under MEDIUM |
| node-ipc | 10.1.0→10.1.1 *(reconstructed)* | Same incident, the complete wiper | No — unpublished; rebuilt from the exact verified git commit and diffed locally (never packaged/served) | **HIGH, 69.0/100** |

node-ipc, colors, event-stream/flatmap-stream, and ua-parser-js are the four
incidents with a real, complete attack diff run through the pipeline via
reconstruction — node-ipc and colors from verified git history,
flatmap-stream from CDN-archaeology evidence (that incident was an account
hijack, never pushed to git, with no live base tarball either),
ua-parser-js from a real still-published pre-incident base tarball with
vendor-writeup-recovered payload scripts spliced on — and they disagree in
useful ways. node-ipc's complete attack scores far more severely than its
diluted registry remnant (LOW → HIGH), carried entirely by the LLM layer:
the miscalibration was in what the registry-fetch layer could see, not in
the model's judgement, and reconstruction fixes it. flatmap-stream's
complete attack also reaches HIGH, but leans partly on a rare OSV
`malicious_floor` hit (the one time it fires anywhere in this corpus)
rather than the LLM layer alone. ua-parser-js's complete attack first
reached only MEDIUM — not because the LLM or feeds missed anything they
were shown, but because chainwatch's diff engine didn't recognise
`.sh`/`.bat` as source files, so the two scripts carrying the actual
payload were never enumerated. That gap was diagnosed, isolated with a
controlled experiment, and fixed the same day (`SOURCE_EXTENSIONS` now
includes `.sh`/`.bat`/`.ps1`/`.cmd`) — an independent rerun against the
real fixed code reaches HIGH on the identical attack. colors's complete
attack scores LOW regardless of completeness, because it's a
denial-of-service payload (an infinite loop) and none of chainwatch's five
risk dimensions — network calls, obfuscation, install hooks, env
conditionals, dependency changes — are built to detect that, even though
the LLM's free-text summary correctly identifies the incident, and no
same-day fix is available for this one. Not every miss has the same fix,
and not every hit is carried the same way. A false-positive baseline (4
benign pairs, zero severity-level false positives) lives in
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
