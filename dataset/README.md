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
│   ├── node-ipc/                # same layout — the one registry-diffable real attack
│   ├── ctx/                     # same layout — no live tarball on either side; PyPI, not npm
│   └── coa-rc/                  # NOT a canonical entry — placeholder reconstruction, see its SOURCING.md
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
| `dimensions[]` | Per-dimension LLM scores (0–10) with `weight`, `reasoning`, and `confidence` (0–1). Six dimensions as of 2026-08-10 (`resource_exhaustion` added — see `findings/README.md` recommendation #1); reports generated before then have five, and both validate, since the schema only requires the stored weights to sum to 1.0, not a fixed dimension count. |
| `score_modifiers[]` | Every adjustment applied to `llm_base_score`, feed-driven (`source` = `osv`/`rekor`/`scorecard`) or, as of 2026-08-10, LLM-dimension-driven (`source` = `llm`, rule `definitive_dimension_floor`) — as `{source, rule, delta, note}`. |
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
| ua-parser-js | 0.7.28→0.7.30, 0.7.30→0.7.31 (registry) + 0.7.28→0.7.29 (reconstructed) | Account compromise → cryptominer (2021) | No via the registry pipeline — `0.7.29`/`0.8.0`/`1.0.0` unpublished. The actual attack was reconstructed onto a real, still-published `0.7.28` base with the recovered `preinstall.js`/`.sh`/`.bat` spliced in — first scored 42.5/MEDIUM, held short of HIGH by a diff-engine file-extension gap fixed the same day, then rerun again after a second fix to reach **67.0/HIGH**, the highest score in the corpus. See `ua-parser-js/FINDINGS.md`. |
| colors | 1.3.3→1.4.0 (control) + 1.4.0→1.4.44-liberty-2 (reconstructed) | Maintainer protest-ware, infinite loop (2022) | No via the registry pipeline — sabotage never republished (`1.4.0` is still `latest`). The actual sabotage commit was reconstructed from verified git history and run directly through the pipeline — first scored 7.5/LOW despite being the complete attack, then **35.0/MEDIUM** after two code fixes (see below). See `colors/FINDINGS.md`. |
| node-ipc | 10.1.0→11.0.0 (registry) + 10.1.0→10.1.1 (reconstructed) | Maintainer protest-ware, destructive wiper (2022) | **Yes, both ways.** The compromised `peacenotwar` dependency is still present in `11.0.0` (registry-diffable today) — originally scored 29.5/LOW, now **30.0/MEDIUM** after the same code fixes that resolved `colors`. The actual destructive wiper (`10.1.1`, unpublished) was reconstructed from its exact verified git commit and run directly through the pipeline — **62.5/HIGH** (originally 69.0; rerun under the current weight matrix). See `node-ipc/FINDINGS.md`. |
| ctx | 0.1.2→0.1.2-1 (reconstructed) + 0.1.2→0.2.5 (reconstructed) | PyPI account takeover, environment-variable exfiltration (2022) | No via any live fetch — the entire PyPI project was deleted, not just the malicious versions (`GET .../pypi/ctx/json` → 404). Both sides reconstructed from independent archives (Software Heritage for the real 2014 original, the Wayback Machine for both real uploaded malicious sdists) and run directly through the pipeline — **41.5/MEDIUM** (first, simplest malicious release) and **52.0/MEDIUM** (final, complete release), both entirely LLM-driven with zero feed-modifier contribution. See `ctx/FINDINGS.md`. |

A recurring finding (see the per-package `FINDINGS.md`): for most of the
highest-profile npm/PyPI incidents the malicious release has been
unpublished from the registry, so registry-level diffing only validates
*non*-false-positive behaviour on the benign neighbours rather than direct
detection. All five incidents in this corpus are now exceptions: each has
had its complete attack reconstructed and run for real — node-ipc and
colors from verified git history, event-stream/flatmap-stream from
CDN-archaeology evidence (that incident was an account hijack, never
pushed to git, with no live base tarball either), ua-parser-js from a
real, still-published pre-incident base tarball with
vendor-writeup-recovered payload scripts spliced on, and ctx from two
independent archives with no live tarball on either side.

**As of 2026-08-11, all seven resulting malicious-labelled pairs score
above LOW** — 0% false positives, 100% recall on this specific corpus —
but they got there by five structurally different mechanisms, which
matters more than the headline number (see the caveat immediately below).
node-ipc's reconstructed wiper is a fetching-completeness story with a
happy ending: LOW when diluted, HIGH when complete, carried entirely by
the LLM layer. flatmap-stream reaches HIGH too, but leans partly on a rare
OSV `malicious_floor` hit. ua-parser-js needed a diff-engine code fix
(`SOURCE_EXTENSIONS` didn't recognise `.sh`/`.bat`, so the actual payload
files were invisible to the LLM) to go from MEDIUM to HIGH. colors and
node-ipc's diluted pair both needed two *further* code changes — a sixth
risk dimension (`resource_exhaustion`) plus a new aggregator rule
(`definitive_dimension_floor`, floors the score to MEDIUM when any one
dimension is both near-maximal and near-certain) — to move from LOW to
MEDIUM. ctx needed none of the above: both its pairs classify correctly
using only the original five dimensions, unmodified, with no feed
contribution at all — the corpus's first genuinely independent check on
whether detection generalises past the incidents that shaped it.

**Read `findings/README.md`'s "overfitting caveat" before citing 100%
recall as a general result.** ctx is a real, independently-sourced
positive, but its attack shape doesn't happen to exercise either of the
two mechanisms built this week (`resource_exhaustion`,
`_apply_dimension_floor`) — those two were designed by directly observing
this corpus's own failures and, as of this update, are still validated
only against the four incidents that produced them. That's real
validation, but it isn't independent validation for those two mechanisms
specifically — see recommendation #7's (partial) resolution there.

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
across all sixteen reports live in [`dataset/findings/README.md`](findings/README.md).
**Headline result, as of 2026-08-11: 0% false positives across nine benign
pairs, 100% precision / 100% recall across seven positive pairs** — every
malicious-labelled pair in this corpus now scores above LOW. Read that
document's "overfitting caveat" before citing the recall number on its
own: two of the fixes that closed four of the corpus's incidents (a sixth
risk dimension for denial-of-service patterns, plus an aggregator rule that
floors the score when one dimension is near-certain and near-maximal) were
designed by observing those incidents' failures and are still validated
only against them. The fifth incident, `ctx` (PyPI, added 2026-08-11), is
the corpus's first genuinely independent check — sourced and reconstructed
after both fixes existed — and it classifies correctly using neither of
them, which is reassuring about the rest of the pipeline but doesn't
actually test the two newest mechanisms (its attack shape never engages
either one). The seven positive examples split into five different
*mechanisms* of detection — LLM-carried, feed-carried,
diff-engine-fix-carried, aggregator-fix-carried, and (ctx) unmodified-
five-dimension-carried — which is the more durable finding than the single
recall number. See that document before citing any of these numbers in
isolation.

## Still pending

Reconstruction-and-run is now done for all five incidents in this corpus —
there's no remaining "not yet run" case — and every resulting pair has been
rerun against the fully-fixed code, twice in some cases, for corpus-wide
consistency. Three real code fixes shipped 2026-08-10:
`chainwatch.diff.engine.SOURCE_EXTENSIONS` now recognises
`.sh`/`.bat`/`.ps1`/`.cmd`; `models.DIMENSIONS` gained a sixth entry,
`resource_exhaustion`; and `analyzer/aggregator.py` gained
`_apply_dimension_floor`. `ctx` (2026-08-11) is the first step on
`findings/README.md`'s recommendation #7 — a real, independently-sourced
positive — but it's a partial answer, not a full one: its attack shape
doesn't happen to exercise either of the two mechanisms above, so whether
`resource_exhaustion` and `_apply_dimension_floor` actually generalise past
the four incidents that shaped them is **still open**. `ctx`'s own
reconstruction also surfaced two narrower, unfixed gaps on the PyPI side
(`requirements.txt` isn't parsed for dependencies; `maintainer_changed`
detection is npm-only) — see `findings/README.md` recommendations #9 and
#10. A follow-up attempt at exactly the sixth incident recommendation #7
still calls for — `coa`/`rc` (npm, 2021), picked to land `install_hooks`
near the floor rule's trigger — hit a real sourcing wall instead: the
actual payload was never publicly recovered by anyone, in any form more
concrete than prose description (see `malicious/coa-rc/SOURCING.md`). The
resulting placeholder-file experiment is **not** a corpus entry (filenamed
`inconclusive-*`, excluded from every count in this document), but it
surfaced a second, genuinely useful finding on its own: description
embedded in a diff can drive a HIGH score without any real payload present
— see `findings/README.md` recommendation #8. Recommendation #7 itself
remains open.
