# Cross-corpus findings: precision, recall, and detection gaps

This is "the write-up" referenced throughout `dataset/README.md` — the
synthesis across all ten reports in the corpus, addressing the four
research questions from the top-level `README.md`:

1. Which detection layer (LLM, feeds, or both) catches each known attack
2. The time delta between attack publication and feed coverage (the "detection gap")
3. False positive rates on benign packages with suspicious-looking patterns
4. Comparison with signature-based classifiers on the same ground truth

**Read the limitations section before citing any number here.** The
headline result — 0/1 recall at the default severity threshold — is real,
but it rests on a single positive example, for a structural reason
explained below, not because chainwatch is uniquely bad at this incident.

All tables are computed directly from the ten committed `report-*.json`
files plus live OSV queries; see "Reproducing this analysis" at the end.

## The corpus's central limitation, stated up front

Of the four incidents in `dataset/malicious/`, **three had their actual
malicious release unpublished from npm** before this project could fetch
and diff it (event-stream, ua-parser-js, colors — see each `SOURCING.md`).
Every report for those three packages is therefore a diff of an *adjacent*
version pair, not the attack itself — useful for validating non-false-positive
behaviour, useless for measuring recall.

**node-ipc is the exception.** Its compromised `peacenotwar` dependency was
never unpublished from the `11.0.0` release, so `10.1.0 → 11.0.0` is a real,
registry-diffable attack diff. It is the corpus's only ground-truth-positive
data point that actually went through the pipeline.

**One positive example is not a statistically meaningful sample.** Every
recall number below is technically "0/1" or "1/1" — both are literally true
and both are too small to generalise. Where useful, we widen the lens using
live feed queries against the *actual* malicious version strings (which
needs no tarball — feed clients take a version string, not package bytes),
giving four data points instead of one for the detection-gap and
signature-comparison questions.

## Corpus overview

| Package | Pair | Ground truth | Risk score | Severity |
|---|---|---|---|---|
| esbuild | 0.27.4→0.27.5 | benign | 0.0 | LOW |
| husky | 5.0.9→5.1.0 | benign | 3.0 | LOW |
| lodash | 4.17.20→4.17.21 | benign | 0.0 | LOW |
| requests | 2.31.0→2.32.0 | benign | 2.5 | LOW |
| colors | 1.3.3→1.4.0 | benign (pre-incident control) | 5.0 | LOW |
| event-stream | 3.3.4→3.3.5 | benign (pre-incident control) | 5.0 | LOW |
| event-stream | 3.3.5→4.0.0 | benign (post-incident control) | 5.0 | LOW |
| ua-parser-js | 0.7.28→0.7.30 | benign (brackets, doesn't contain attack) | 0.0 | LOW |
| ua-parser-js | 0.7.30→0.7.31 | benign (post-incident control) | 10.2 | LOW |
| **node-ipc** | **10.1.0→11.0.0** | **malicious** (real compromised dependency) | **29.5** | **LOW** |

## Precision / recall (Figure 1)

Confusion matrix at the default classification rule — **flagged = severity
≠ LOW**:

| | Predicted malicious | Predicted benign |
|---|---|---|
| **Actually malicious** | TP = 0 | FN = 1 (node-ipc) |
| **Actually benign** | FP = 0 | TN = 9 |

- **Precision:** 0/0, undefined (no positive predictions were made at all)
- **Recall:** 0/1 = **0%**
- **Specificity / true-negative rate:** 9/9 = **100%**
- **False-positive rate:** 0/9 = **0%**

Read plainly: nothing in this corpus was ever bucketed above LOW severity,
including the one real attack. Zero false positives, zero true positives.
The 0% recall is real and worth sitting with — but it is a bucketing-threshold
finding, not a "the LLM didn't notice" finding. See below.

### The severity bucket hid a signal the model actually found

node-ipc's `dependency_changes` dimension scored **9.0/10** — the highest
score on *any* dimension across all ten reports (next-highest: ua-parser-js
`0.7.30→0.7.31` at 6.5, from legitimate `@babel/parser`/`@babel/traverse`
test dependencies). Its `env_conditional` score (4.0) is also the corpus
maximum. The free-text `llm_summary` names the 2022 incident directly with
stated high confidence (quoted in full in `malicious/node-ipc/FINDINGS.md`).

Two alternative classification rules, evaluated post-hoc against this same
corpus:

| Rule | TP | FN | FP | Recall | Specificity |
|---|---|---|---|---|---|
| severity ≠ LOW *(current default)* | 0 | 1 | 0 | 0% | 100% |
| risk_score > 25 *(a `--threshold 25` CI gate)* | 1 | 0 | 0 | **100%** | 100% |
| any single dimension ≥ 7 | 1 | 0 | 0 | **100%** | 100% |

Both alternative rules achieve perfect separation on this corpus. **This is
a hypothesis, not a validated threshold** — with n=1 positive, any rule that
happens to clear 29.5 or that happens to notice a 9.0 will "work" here by
construction; the honest claim is only that the *default* bucketing (LOW
0–29) sits uncomfortably close on the one real case available, close enough
that `--threshold 25` (already a supported flag) would have caught it. See
`malicious/node-ipc/FINDINGS.md` for the full breakdown of why
`dependency_changes`'s 15% weight caps what a 9/10 finding can contribute.

## RQ1 — which detection layer catches each known attack

For the three incidents whose attack diff isn't registry-fetchable, "LLM
layer" performance can't be measured directly — but the feed layer can, by
querying OSV directly for the *actual* malicious version strings (no
tarball needed). Results, live-queried for this write-up:

| Incident | LLM layer (on best available diff) | OSV feed (queried against the real malicious version) | Ever `MAL-*`? |
|---|---|---|---|
| event-stream / flatmap-stream | Not tested — attack diff unavailable | `GHSA-mh6f-8j2x-4483` (event-stream); `GHSA-9x64-5r7x-2q53` + **`MAL-2025-20690`** (flatmap-stream) | **Yes — flatmap-stream only, and only since 2025-08-14** |
| ua-parser-js | Not tested — attack diff unavailable | `GHSA-pjwm-rvh2-c87w` | No, never |
| colors | Not tested — attack diff unavailable | `GHSA-5rqg-jm4f-cqx7`, `GHSA-gh88-3pxp-6fm8` | No, never |
| node-ipc | **Tested for real:** `dependency_changes=9.0`, free-text names the incident, base score 29.5 | `GHSA-97m3-w2cp-4xx6` (10.1.x), `GHSA-3mpp-xfvh-qh37` (11.0.0), `GHSA-8gr3-2gjw-jj7g` (9.2.2) | No, never |

**The one finding that generalises across all four incidents, not just the
one we could pipeline-test:** chainwatch's aggregator only floors the score
to the HIGH range when a feed reports `malicious` — which chainwatch maps
from an OSV `MAL-*` prefix specifically (`analyzer/feeds.py`). Of four
confirmed, publicly-documented supply-chain attacks, **only one has ever
received a `MAL-*` classification, and that happened three and a half years
after disclosure.** Even a chainwatch instance polling OSV in real time
today would still get `suspicious`, not `malicious`, for three of these four
incidents — the feed-floor rule's practical hit rate on this corpus's ground
truth is 1-in-4, and even that one hit took years.

## RQ2 — detection gap

Malicious-publish timestamp → first public advisory, both taken from the
npm registry's own `time` metadata and OSV's `published` field (live-queried
for this write-up, not estimated):

| Incident | Malicious version published | First advisory | Gap | Advisory ID |
|---|---|---|---|---|
| event-stream/flatmap-stream | 2018-09-09 08:28:59 UTC | 2018-11-26 23:58:21 UTC | **78d 15h** | GHSA-mh6f-8j2x-4483 |
| ua-parser-js | 2021-10-22 12:15:21 UTC | 2021-10-22 20:38:14 UTC | **8h 23m** | GHSA-pjwm-rvh2-c87w |
| colors | 2022-01-08 04:24:16 UTC | 2022-01-10 17:29:53 UTC | **2d 13h** | GHSA-5rqg-jm4f-cqx7 |
| node-ipc (10.1.1, wiper) | 2022-03-07 11:03:59 UTC | 2022-03-16 23:54:32 UTC | **9d 13h** | GHSA-97m3-w2cp-4xx6 |
| node-ipc (11.0.0, notice-only) | 2022-03-08 17:25:35 UTC | 2022-03-16 23:54:35 UTC | **8d 6h** | GHSA-3mpp-xfvh-qh37 |
| node-ipc (9.2.2, notice-only) | 2022-03-15 05:40:26 UTC | 2022-03-16 23:54:33 UTC | **1d 18h** | GHSA-8gr3-2gjw-jj7g |

Gaps range from under nine hours to eleven weeks, with no obvious trend by
year (2022's colors incident closed in 2.5 days; 2021's ua-parser-js closed
in under nine hours; 2018's event-stream took eleven weeks). **A diff-level
LLM scanner's structural advantage is that it doesn't wait for any of this —
it can score a release the moment it's published, at the cost of the
severity-bucketing miss documented above.** The upper bound on what
chainwatch could contribute on an incident shaped like ua-parser-js's is
closing an 8-hour gap to single-digit minutes; on event-stream's, closing
an 11-week gap to the same.

## RQ3 — false positive rate

9/9 benign-labelled pairs in this corpus (4 in `dataset/benign/`, 5 adjacent
pairs across the three unpublished-attack incidents) scored LOW. **0%
false-positive rate at the severity level**, across pairs specifically
selected to be "suspicious-looking but legitimate" — a new install hook
(husky), a real CVE fix (lodash), platform-conditional native-binary logic
(esbuild), a 5,900-line refactor (requests). Full per-pair reasoning in
`benign/FINDINGS.md`.

## RQ4 — comparison with a signature-based classifier

OSV is the natural signature-based baseline here: it's a curated advisory
database, the same category of tool as the classifiers this question asks
chainwatch to be compared against, and it's already wired into every
report. Scored against this corpus's four incidents:

- **Eventual coverage: 4/4 (100%).** Every incident got at least one
  advisory, eventually.
- **Confirmed-malware (`MAL-*`) coverage: 1/4 (25%), and slow.** Only
  flatmap-stream has ever been reclassified from a generic GHSA advisory to
  a `MAL-*` entry, three and a half years after disclosure (see RQ1).
- **Speed: highly variable, 8 hours to 11 weeks** (see RQ2), with no
  advisory ever available at the moment of attack publication.

The comparison isn't "OSV vs. chainwatch" — chainwatch *uses* OSV as one of
three feed inputs. The more useful framing: **OSV is reliable but slow, and
rarely reaches the confidence tier (`MAL-*`) that chainwatch's own
aggregator treats as decisive.** The LLM layer's structural advantage over
a pure signature database is availability at publish time; its structural
disadvantage, per this corpus's one real test case, is that its strongest
per-dimension finding (9.0/10) still doesn't clear the aggregate severity
bar on its own.

## Latency (observational, not a benchmark)

Not systematically instrumented — report JSON doesn't record wall-clock
duration — but worth noting qualitatively from directly-observed runs this
session: single-chunk diffs (most benign pairs, most malicious-corpus
control pairs) completed in roughly 10–20 seconds end-to-end (fetch + diff +
LLM + feeds). The `requests` pair — 10 chunks after chunking a ~5,900-line
diff — took roughly 2.5 minutes, scaling with chunk count since chunks are
sent to the LLM sequentially per `analyzer/llm.py`. A proper latency study
(controlled runs, repeated trials, network variance isolated) is future
work, not attempted here.

## Recommendations arising from this data

1. **`dependency_changes`'s 15% weight is worth revisiting**, or a
   "known-compromised transitive dependency" special-case modifier worth
   adding — both already flagged in `malicious/node-ipc/FINDINGS.md`, and
   the only corpus-wide finding here that would directly change the one
   real miss.
2. **CI users relying on `--threshold` should not assume the MEDIUM
   boundary (30) is a safe default** — `--threshold 25` would have caught
   this corpus's one real attack; the default severity-only view would not.
3. **The feed-floor rule's dependence on OSV's `MAL-*` prefix specifically
   (not `GHSA-*`) means it will rarely fire in practice**, per RQ1/RQ4 — a
   tool relying on chainwatch's `malicious_floor` modifier as its primary
   safety net would have missed 3 of 4 incidents in this corpus even with
   live feeds, for years in some cases.
4. **The ground-truth corpus needs more real positives.** n=1 is a
   demonstration, not a validated recall measurement. The clearest path
   forward, flagged but deliberately not pursued this session (a
   "document only" scope decision — see `malicious/colors/evidence/` and
   `malicious/node-ipc/evidence/`): for the two maintainer-sabotage
   incidents where the actual payload was recovered from git history,
   reconstructing a runnable synthetic tarball and serving it through a
   local mock registry (`CHAINWATCH_NPM_REGISTRY` override, following the
   pattern in `tests/fixtures/npm_registry.py`) would let the real pipeline
   run against colors's and node-ipc's actual attack commits, not just
   adjacent pairs.

## Reproducing this analysis

The corpus table and dimension breakdown:

```bash
python3 -c "
import json, glob
for path in sorted(glob.glob('dataset/**/report-*.json', recursive=True)):
    d = json.load(open(path))
    print(d['package'], d['from_version'], '->', d['to_version'],
          d['risk_score'], d['severity'])
"
```

The live OSV queries (no tarball fetch needed — feed clients take a version
string):

```bash
curl -s -X POST https://api.osv.dev/v1/query \
  -H "Content-Type: application/json" \
  -d '{"version":"0.7.29","package":{"name":"ua-parser-js","ecosystem":"npm"}}'
```

npm registry publish timestamps (`time` field) were fetched from
`https://registry.npmjs.org/{package}` directly; see each incident's
`SOURCING.md` for the exact commit/version provenance those timestamps
attach to.
