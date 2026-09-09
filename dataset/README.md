# chainwatch research dataset

Ground-truth corpus of `chainwatch` risk reports, used to evaluate detection
performance and false-positive behaviour. Each report is a full, self-contained
JSON document (schema `0.2.0` for every report committed so far; the current
code emits `0.3.0`, an additive superset) produced by the pipeline for a single
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
│   ├── lucide-proxy/             # same layout — no tarball either side; real payload fragments, synthetic scaffold
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

## Report schema (0.3.0)

Every report validates against `chainwatch.models.RiskReport`. Key fields:

| Field | Meaning |
|---|---|
| `schema_version` | Report schema version. Bumped to `0.2.0` when the score-decomposition fields were added, and to `0.3.0` (2026-09-09) when `timings`, `caveats[]`, and the diff-visibility fields below were added. Every bump so far has been additive with defaults, so `0.1.0` and `0.2.0` reports still validate against the current schema. |
| `risk_score` / `severity` | Composite 0–100 score and its bucket (`LOW`/`MEDIUM`/`HIGH`/`CRITICAL`). |
| `llm_base_score` | The 0–100 score from the LLM dimensions **alone**, before any feed adjustment. |
| `dimensions[]` | Per-dimension LLM scores (0–10) with `weight`, `reasoning`, and `confidence` (0–1). Six dimensions as of 2026-08-10 (`resource_exhaustion` added — see `findings/README.md` recommendation #1); reports generated before then have five, and both validate, since the schema only requires the stored weights to sum to 1.0, not a fixed dimension count. |
| `score_modifiers[]` | Every adjustment applied to `llm_base_score`, feed-driven (`source` = `osv`/`rekor`/`scorecard`/`new_deps`, the last as of 2026-08-12) or, as of 2026-08-10, LLM-dimension-driven (`source` = `llm`, rule `definitive_dimension_floor`) — as `{source, rule, delta, note}`. |
| `feed_results[]` | Normalised OSV / Rekor / Scorecard / new-dependency-provenance results. Four as of 2026-08-12 (`new_deps` added — see `findings/README.md` recommendation #12); reports generated before then have three, and both validate for the same reason dimension count isn't fixed above. |
| `diff_summary` | Structured diff: added/removed/modified files, dependency and hook changes, truncation flag. |
| `diff_summary.truncated_files` / `skipped_files` | Which files the LLM saw only the head of (cut at the per-chunk token budget) and which it never saw at all (over `CHAINWATCH_MAX_DIFF_FILE_BYTES`). `0.3.0`+; empty on older reports, which carried only the `diff_truncated` boolean — the gap the ua-parser-js and requests write-ups both flagged. |
| `diff_summary.comments_stripped` / `comment_lines_stripped` | Whether `--strip-comments` removed whole-line comments before analysis, and how many diff lines it removed. This is the narrative-leakage control from `findings/README.md` recommendation #8, turned into a one-flag rerun: same code, no prose. `0.3.0`+. |
| `caveats[]` | Plain-language statements, built from `diff_summary` (never from LLM text), about evidence the LLM did not see or scored under a known limitation: skipped files, head-truncated files, multi-chunk max-aggregation, stripped comments. Empty when the whole diff was visible in one chunk. `0.3.0`+. |
| `timings` | Per-stage wall-clock seconds (`fetch`, `diff`, `llm`, `feeds`, `analysis`, `total`) for the run that produced the report — observational, not a benchmark. `0.3.0`+; `null` on older reports and on anything re-rendered via `chainwatch report`. |
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
| ctx | 0.1.2→0.1.2-1 (reconstructed) + 0.1.2→0.2.5 (reconstructed) | PyPI account takeover, environment-variable exfiltration (2022) | No via any live fetch — the entire PyPI project was deleted, not just the malicious versions (`GET .../pypi/ctx/json` → 404). Both sides reconstructed from independent archives (Software Heritage for the real 2014 original, the Wayback Machine for both real uploaded malicious sdists) and run directly through the pipeline — **42.5/MEDIUM** (first, simplest malicious release) and **56.5/HIGH** (final, complete release, crossed from MEDIUM after this incident's own reconstruction motivated a same-day diff-engine fix), both entirely LLM-driven with zero feed-modifier contribution. See `ctx/FINDINGS.md`. |
| Lucide Proxy (`ilovefemboys`) | 1.1.3→2.0.0, cdn.js only (reconstructed) + 1.1.3→2.0.0, cdn.js+sw.js (reconstructed) | npm browser-recruited DDoS botnet, malicious-from-inception (2026) | No via any live fetch — none of this campaign's 148 packages have a live or archived tarball on either side. Real payload fragments (not narration) recovered independently from the campaign's own external C2 repositories via the Wayback Machine, layered onto an explicitly-synthetic package scaffold — **55.0/HIGH** on both pairs. Chosen specifically to test `resource_exhaustion` on a DoS shape unlike `colors`'s: it scored 8.0–6.0/10 on a real, unbounded *asynchronous* polling loop, the dimension's first out-of-corpus validation — but the final score is entirely floor-imposed by a fast, real OSV `MAL-*` hit, not by that dimension or `_apply_dimension_floor` (which still didn't fire). See `lucide-proxy/FINDINGS.md`. |

A recurring finding (see the per-package `FINDINGS.md`): for most of the
highest-profile npm/PyPI incidents the malicious release has been
unpublished from the registry, so registry-level diffing only validates
*non*-false-positive behaviour on the benign neighbours rather than direct
detection. All six incidents in this corpus are now exceptions: each has
had its complete (or, for `Lucide Proxy`, partial but real) attack
reconstructed and run for real — node-ipc and colors from verified git
history, event-stream/flatmap-stream from CDN-archaeology evidence (that
incident was an account hijack, never pushed to git, with no live base
tarball either), ua-parser-js from a real, still-published pre-incident
base tarball with vendor-writeup-recovered payload scripts spliced on, ctx
from two independent archives with no live tarball on either side, and
Lucide Proxy from real payload fragments recovered from the campaign's own
external infrastructure onto a synthetic scaffold (no legitimate
predecessor exists to reconstruct against — these packages were malicious
from first publish).

**As of 2026-08-11, all nine resulting malicious-labelled pairs score
above LOW** — 0% false positives, 100% recall on this specific corpus —
but they got there by six structurally different mechanisms, which
matters more than the headline number (see the caveat immediately below).
node-ipc's reconstructed wiper is a fetching-completeness story with a
happy ending: LOW when diluted, HIGH when complete, carried entirely by
the LLM layer. flatmap-stream reaches HIGH too, but leans partly on a rare,
years-late OSV `malicious_floor` hit. ua-parser-js needed a diff-engine
code fix (`SOURCE_EXTENSIONS` didn't recognise `.sh`/`.bat`, so the actual
payload files were invisible to the LLM) to go from MEDIUM to HIGH. colors
and node-ipc's diluted pair both needed two *further* code changes — a
sixth risk dimension (`resource_exhaustion`) plus a new aggregator rule
(`definitive_dimension_floor`, floors the score to MEDIUM when any one
dimension is both near-maximal and near-certain) — to move from LOW to
MEDIUM. ctx needed neither of *those* two mechanisms — both its pairs
classify correctly using only the original five dimensions, with no feed
contribution at all — but its more complete pair still needed a same-day
diff-engine metadata fix (`requirements.txt`/`maintainer_changed`
parsing, motivated by this exact incident) to cross from MEDIUM into HIGH.
Lucide Proxy is a sixth, distinct mechanism: `resource_exhaustion` gave a
real, independent, out-of-corpus positive signal for the first time (8.0
and 6.0/10 on a genuinely different DoS shape) — but the final HIGH
bucket is decided by a *fast* OSV `MAL-*` hit, not by that dimension or
`_apply_dimension_floor`, making it the mirror image of `flatmap-stream`'s
slow feed-carried case. ctx is the corpus's first genuinely independent
check on whether detection generalises past the incidents that shaped it,
and the only fix in this corpus validated against the exact incident that
surfaced it rather than a different one; Lucide Proxy is the first
incident chosen specifically to stress-test `resource_exhaustion` from
outside the corpus that built it, and it passed.

**Read `findings/README.md`'s "overfitting caveat" before citing 100%
recall as a general result.** ctx and Lucide Proxy are both real,
independently-sourced positives, but between them they only close half of
what recommendation #7 asked for: `resource_exhaustion` now has genuine
out-of-corpus support, while `_apply_dimension_floor` — designed by
directly observing this corpus's own failures — remains validated only
against the two incidents that produced it. That's real
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
across all eighteen reports live in [`dataset/findings/README.md`](findings/README.md).
**Headline result, as of 2026-08-11: 0% false positives across nine benign
pairs, 100% precision / 100% recall across nine positive pairs** — every
malicious-labelled pair in this corpus now scores above LOW. Read that
document's "overfitting caveat" before citing the recall number on its
own: two of the fixes that closed four of the corpus's incidents (a sixth
risk dimension for denial-of-service patterns, plus an aggregator rule that
floors the score when one dimension is near-certain and near-maximal) were
designed by observing those incidents' failures and, for the aggregator
rule, remain validated only against them. The dimension itself no longer
is: `ctx` (PyPI) and `Lucide Proxy` (npm), both added 2026-08-11 after
both fixes already existed, are the corpus's first genuinely independent
checks. `ctx` classifies correctly using neither mechanism — reassuring
about the rest of the pipeline, but its attack shape never engages either
one. `Lucide Proxy`, chosen specifically for a DoS shape unlike the one
`resource_exhaustion` was built from, gives that dimension real
out-of-corpus support (8.0/10 on a genuinely different, unbounded
asynchronous pattern) — but its final HIGH classification turns out to be
feed-determined, not floor-rule-determined, so `_apply_dimension_floor`
remains untested outside the two incidents that built it. The nine
positive examples split into six different *mechanisms* of detection —
LLM-carried, feed-carried (slow and fast), diff-engine-fix-carried,
aggregator-fix-carried, unmodified-five-dimension-carried (`ctx`), and
`resource_exhaustion`-carried-but-feed-decided (`Lucide Proxy`) — which is
the more durable finding than the single recall number. See that document
before citing any of these numbers in isolation.

## Still pending

Reconstruction-and-run is now done for all six incidents in this corpus —
there's no remaining "not yet run" case — and every resulting pair has been
rerun against the fully-fixed code, twice in some cases, for corpus-wide
consistency. Three real code fixes shipped 2026-08-10:
`chainwatch.diff.engine.SOURCE_EXTENSIONS` now recognises
`.sh`/`.bat`/`.ps1`/`.cmd`; `models.DIMENSIONS` gained a sixth entry,
`resource_exhaustion`; and `analyzer/aggregator.py` gained
`_apply_dimension_floor`. `ctx` and `Lucide Proxy` (both 2026-08-11) are
the two steps taken so far on `findings/README.md`'s recommendation #7 —
together they answer half of it. `resource_exhaustion` now has real,
independent, out-of-corpus support (`Lucide Proxy`'s 8.0/10 on a DoS shape
unlike `colors`'s); `_apply_dimension_floor` still doesn't — every firing
of that rule anywhere in this corpus remains one of the two incidents that
built it, and this **remains open**. `ctx`'s own reconstruction separately
surfaced two further diff-engine gaps on the PyPI side (`requirements.txt`
wasn't parsed for dependencies; `maintainer_changed` detection was
npm-only), plus a documentation gap (`env_conditional`'s stated definition
undersold what it actually, correctly, scored) — all three fixed the same
session (`findings/README.md` recommendations #9 and #10), the first two
reconfirmed on a rerun against `ctx` itself, which is what moved its
`0.2.5` pair from MEDIUM to HIGH. A follow-up attempt at the narrower
target recommendation #7 still calls for — `coa`/`rc` (npm, 2021), picked
to land `install_hooks` near the floor rule's trigger — hit a real
sourcing wall instead: the actual payload was never publicly recovered by
anyone, in any form more concrete than prose description (see
`malicious/coa-rc/SOURCING.md`). The resulting placeholder-file experiment
is **not** a corpus entry (filenamed `inconclusive-*`, excluded from every
count in this document), but a controlled follow-up turned it into a
second, genuinely useful, quantified finding: stripping the placeholder
comments down to genuinely empty stub files dropped both pairs from HIGH
to MEDIUM (20–28.5 points) — direct evidence that descriptive prose
embedded in a diff drives a measurable part of the score, independent of
any real payload — see `findings/README.md` recommendation #8.
Recommendation #7 itself is more than half-closed, but remains open.
