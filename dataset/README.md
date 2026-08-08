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
│   │   ├── evidence/             # recovered payload code, not runnable via chainwatch
│   │   └── report-<from>-to-<to>.json
│   ├── ua-parser-js/            # same layout
│   ├── colors/                  # same layout
│   └── node-ipc/                # same layout — the one registry-diffable real attack
├── benign/              # false-positive baseline (ground truth: benign)
│   ├── SOURCING.md               # selection methodology for all 4 pairs
│   ├── FINDINGS.md               # per-pair analysis and cross-cutting notes
│   ├── husky/report-<from>-to-<to>.json
│   ├── lodash/report-<from>-to-<to>.json
│   ├── esbuild/report-<from>-to-<to>.json
│   └── requests/report-<from>-to-<to>.json
└── findings/            # cross-corpus write-ups
    └── README.md              # precision/recall, detection gap, RQ1-4 synthesis
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

### Malicious (or malicious-adjacent)

| Package | Pair(s) analysed | Incident | Malicious version analysable? |
|---|---|---|---|
| event-stream | 3.3.4→3.3.5, 3.3.5→4.0.0 | Maintainer handoff → crypto theft (2018) | No via the registry pipeline — `3.3.6` unpublished. Payload code recovered from secondary sources, see `evidence/` |
| ua-parser-js | 0.7.28→0.7.30, 0.7.30→0.7.31 | Account compromise → cryptominer (2021) | No via the registry pipeline — `0.7.29`/`0.8.0`/`1.0.0` unpublished. Payload code recovered from secondary sources, see `evidence/` |
| colors | 1.3.3→1.4.0 | Maintainer protest-ware, infinite loop (2022) | No via the registry pipeline — sabotage never republished (`1.4.0` is still `latest`). Payload recovered directly from git history, see `evidence/` |
| node-ipc | 10.1.0→11.0.0 | Maintainer protest-ware, destructive wiper (2022) | **Partially — yes.** The destructive wiper (`10.1.1`–`10.1.3`) is unpublished, but the compromised `peacenotwar` dependency is still present in `11.0.0`, which is on the registry today. This is the one incident in the corpus chainwatch can diff for real — see `node-ipc/FINDINGS.md` for the result (correctly identified by the LLM, scored 29.5/LOW — 0.5 points under the MEDIUM threshold). |

A recurring finding (see the per-package `FINDINGS.md`): for most of the
highest-profile npm incidents the malicious release has been unpublished
from the registry, so registry-level diffing only validates *non*-false-positive
behaviour on the benign neighbours rather than direct detection. `node-ipc`
is the exception, and its result — a correct, high-confidence LLM
identification that still buckets to LOW — is the dataset's most important
finding on aggregation/bucketing calibration so far.

### Benign (false-positive baseline)

| Package | Pair analysed | Pattern under test | Result |
|---|---|---|---|
| husky | 5.0.9→5.1.0 | new install hook | LOW (3.0) |
| lodash | 4.17.20→4.17.21 | minified dist / real ReDoS fix | LOW (0.0) |
| esbuild | 0.27.4→0.27.5 | network calls + env conditional | LOW (0.0) |
| requests (PyPI) | 2.31.0→2.32.0 | large diff / dependency churn | LOW (2.5) |

Each pair was chosen specifically because it hits a pattern that looks like
one of the five risk dimensions on paper but is legitimate — see
`benign/SOURCING.md` for methodology and `benign/FINDINGS.md` for full
per-pair analysis. Zero severity-level false positives across all four.

## Cross-corpus findings

The precision/recall table, detection-gap analysis, and full RQ1–4 synthesis
across all ten reports live in [`dataset/findings/README.md`](findings/README.md).
Headline result: 0% severity-level false positives across nine benign pairs,
but the corpus's one real attack diff (node-ipc) also scored LOW — a
bucketing-threshold finding, not an "LLM missed it" finding. See that
document before citing either number in isolation.

## Still pending

`colors` and `node-ipc` acquisition is at the "recovered evidence, not yet
reconstructed into a runnable diff" stage (see each `evidence/README.md`) —
widening the real-positive sample beyond n=1 is the clearest next step, per
`findings/README.md`'s recommendations.
