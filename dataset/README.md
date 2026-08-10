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
| event-stream | 3.3.4→3.3.5, 3.3.5→4.0.0 (registry) + flatmap-stream 0.1.0→0.1.1 (reconstructed) | Maintainer handoff → crypto theft (2018) | No via the registry pipeline — `3.3.6` unpublished. The actual transitive payload (`flatmap-stream@0.1.1`) was reconstructed from CDN-archaeology evidence (Wayback-cached, cross-validated against a paper's companion dataset) and run directly through the pipeline — scored **60.0/HIGH**. See `event-stream/FINDINGS.md`. |
| ua-parser-js | 0.7.28→0.7.30, 0.7.30→0.7.31 | Account compromise → cryptominer (2021) | No via the registry pipeline — `0.7.29`/`0.8.0`/`1.0.0` unpublished. Payload code recovered from secondary sources (see `evidence/`) but not yet reconstructed-and-run. |
| colors | 1.3.3→1.4.0 (control) + 1.4.0→1.4.44-liberty-2 (reconstructed) | Maintainer protest-ware, infinite loop (2022) | No via the registry pipeline — sabotage never republished (`1.4.0` is still `latest`). The actual sabotage commit was reconstructed from verified git history and run directly through the pipeline — scored **7.5/LOW despite being the complete attack**. See `colors/FINDINGS.md`. |
| node-ipc | 10.1.0→11.0.0 (registry) + 10.1.0→10.1.1 (reconstructed) | Maintainer protest-ware, destructive wiper (2022) | **Yes, both ways.** The compromised `peacenotwar` dependency is still present in `11.0.0` (registry-diffable today, scored 29.5/LOW). The actual destructive wiper (`10.1.1`, unpublished) was reconstructed from its exact verified git commit and run directly through the pipeline — scored **69.0/HIGH**. See `node-ipc/FINDINGS.md`. |

A recurring finding (see the per-package `FINDINGS.md`): for most of the
highest-profile npm incidents the malicious release has been unpublished
from the registry, so registry-level diffing only validates *non*-false-positive
behaviour on the benign neighbours rather than direct detection. node-ipc,
colors, and event-stream/flatmap-stream are the exceptions: each had its
complete attack reconstructed and run for real — node-ipc and colors from
verified git history, event-stream/flatmap-stream from CDN-archaeology
evidence instead (that incident was an account hijack, never pushed to
git) — and the three results don't all agree, in an informative way.
node-ipc shows a correct, high-confidence LLM identification that buckets
to LOW when the attack is diluted and to HIGH when it isn't — a
fetching-completeness story with a happy ending. flatmap-stream also
reaches HIGH, but leans partly on a rare OSV `malicious_floor` hit rather
than the LLM layer alone. colors shows the complete, real attack scoring
LOW regardless — a denial-of-service payload that none of chainwatch's five
risk dimensions are built to detect, regardless of how completely it's
presented. Together they're the dataset's most important finding: not
every miss has the same fix, and not every hit is carried the same way.

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
across all thirteen reports live in [`dataset/findings/README.md`](findings/README.md).
Headline result: 0% severity-level false positives across nine benign pairs;
100% precision / 50% recall across four positive pairs, split into three
different kinds of result — node-ipc's diluted registry pair (fixed by
reconstructing the complete attack, which scored HIGH, carried entirely by
the LLM layer), flatmap-stream's reconstructed complete attack (also HIGH,
but leaning partly on a rare OSV `malicious_floor` hit rather than the LLM
layer alone), and colors's reconstructed complete attack (still LOW — a
taxonomy gap, not a fetching gap; none of chainwatch's five risk dimensions
detect denial-of-service payloads). See that document before citing any of
these numbers in isolation.

## Still pending

`ua-parser-js` is the one incident in this corpus not yet reconstructed and
run for real — its payload scripts are already recovered in `evidence/`,
only the run is missing (lowest-effort remaining item, per
`findings/README.md`'s recommendation #5). Beyond that, widening the
real-positive sample past these four pairs is the clearest next step, along
with the write-up's highest-priority recommendation: a sixth risk dimension
for denial-of-service / resource-exhaustion patterns, the one change that
would have caught colors.
