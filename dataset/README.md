# chainwatch research dataset

Ground-truth corpus of `chainwatch` risk reports, used to evaluate detection
performance and false-positive behaviour. Each report is a full, self-contained
JSON document (schema `0.2.0`) produced by the pipeline for a single
version-to-version package diff.

## Layout

```
dataset/
├── malicious/           # known supply-chain incidents (ground truth: malicious)
│   ├── event-stream/
│   │   ├── SOURCING.md          # provenance + why specific versions were used
│   │   ├── FINDINGS.md          # per-pair analysis and cross-cutting notes
│   │   └── report-<from>-to-<to>.json
│   └── ua-parser-js/
├── benign/              # false-positive baseline (ground truth: benign) — pending
└── findings/            # cross-corpus write-ups (precision/recall, latency) — pending
```

## Report schema (0.2.0)

Every report validates against `chainwatch.models.RiskReport`. Key fields:

| Field | Meaning |
|---|---|
| `schema_version` | Report schema version. Bumped to `0.2.0` when the score-decomposition fields were added. |
| `risk_score` / `severity` | Composite 0–100 score and its bucket (`LOW`/`MEDIUM`/`HIGH`/`CRITICAL`). |
| `llm_base_score` | The 0–100 score from the LLM dimensions **alone**, before any feed adjustment. |
| `dimensions[]` | Five per-dimension LLM scores (0–10) with `weight`, `reasoning`, and `confidence` (0–1). |
| `score_modifiers[]` | Every feed-driven adjustment applied, as `{source, rule, delta, note}`. |
| `feed_results[]` | Normalised OSV / Rekor / Scorecard results. |
| `diff_summary` | Structured diff: added/removed/modified files, dependency and hook changes, truncation flag. |
| `from_version_sha256` / `to_version_sha256` | Integrity hashes of the analysed tarballs. |
| `llm_model`, `timestamp` | Provenance. |

### Score is fully decomposable

The composite score reconstructs from the report alone:

```
risk_score == clamp(llm_base_score + sum(m.delta for m in score_modifiers), 0, 100)
```

so a reviewer can retune the weight matrix or the feed-modifier table post-hoc
without re-running the LLM. Example (`ua-parser-js` 0.7.30 → 0.7.31):
`llm_base_score = 15.2`, one modifier `scorecard_good = -5.0`, `risk_score = 10.2`.

> **Historical reports.** The committed reports predate the `0.2.0` schema and
> were enriched in place: `llm_base_score` and `score_modifiers` were recomputed
> from data already present in each report (dimension scores and feed results),
> and verified to reconstruct the stored `risk_score`. Per-dimension `confidence`
> is `null` for these runs — the model was not asked for it at the time.

## Reproducing a run

Reports are generated with the JSON emitter:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
chainwatch --json diff npm event-stream 3.3.4 3.3.5 \
  > dataset/malicious/event-stream/report-3.3.4-to-3.3.5.json
```

The `*_sha256` fields let you confirm you fetched the same artifacts. LLM scores
are not bit-for-bit reproducible (model non-determinism), but the structured
diff, feed results, and score arithmetic are. See each package's `SOURCING.md`
for why specific version pairs were chosen.

### Redaction

Report timestamps are normalised to `T00:00:00Z` on the run date so the corpus
records *when* a run happened without preserving minute-level local timing.

## Ground truth

| Package | Pair(s) analysed | Incident | Malicious version analysable? |
|---|---|---|---|
| event-stream | 3.3.4→3.3.5, 3.3.5→4.0.0 | Maintainer handoff → crypto theft (2018) | No — malicious `3.3.6` unpublished |
| ua-parser-js | 0.7.28→0.7.30, 0.7.30→0.7.31 | Account compromise → cryptominer (2021) | No — malicious `0.7.29`/`0.8.0`/`1.0.0` unpublished |
| colors | — | Protest-ware, infinite loop | pending acquisition |
| node-ipc | — | Protest-ware, destructive payload | pending acquisition |

A recurring finding (see the per-package `FINDINGS.md`): for the highest-profile
npm incidents the malicious release has been unpublished from the registry, so
registry-level diffing validates *non*-false-positive behaviour on the benign
neighbours rather than direct detection. The precision/recall table (Figure 1 of
the write-up) and the benign false-positive baseline are the next dataset
deliverables.
