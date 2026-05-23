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
```

## Ground Truth Corpus

| Package | Versions | Attack Type | Expected Score |
|---|---|---|---|
| event-stream | 3.3.4 → 3.3.5 | Maintainer handoff, crypto theft | HIGH–CRITICAL |
| ua-parser-js | 0.7.28 → 0.7.29 | Account compromise, cryptominer | HIGH–CRITICAL |
| colors | 1.4.0 → 1.4.1 | Protest-ware, infinite loop | MEDIUM–HIGH |
| node-ipc | 10.1.0 → 10.1.1 | Protest-ware, destructive payload | HIGH–CRITICAL |

The `dataset/` directory contains full reports for all analysed packages, both malicious and benign, enabling reproducible evaluation.

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
