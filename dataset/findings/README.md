# Cross-corpus findings: precision, recall, and detection gaps

This is "the write-up" referenced throughout `dataset/README.md` — the
synthesis across all eleven reports in the corpus, addressing the four
research questions from the top-level `README.md`:

1. Which detection layer (LLM, feeds, or both) catches each known attack
2. The time delta between attack publication and feed coverage (the "detection gap")
3. False positive rates on benign packages with suspicious-looking patterns
4. Comparison with signature-based classifiers on the same ground truth

**Read the limitations section before citing any number here.** This
corpus has two positive examples, not one, and they tell different halves
of the same story: a registry-fetched pair that misses at the severity
bucket (`node-ipc@11.0.0`, LOW), and a reconstructed pair — the actual
destructive payload, never published to a real package tarball, run
directly against chainwatch's diff/LLM/feed pipeline via local directories
— that scores decisively HIGH (69.0). Read together, they separate two
different questions that a single number would blur: *does the
detection logic work* (yes, given the real attack) and *can chainwatch's
registry-based fetching autonomously find that attack in the wild* (no,
because npm's unpublish policy destroys the evidence before any
registry-diffing scanner — chainwatch or otherwise — could see it).

All tables are computed directly from the eleven committed `report-*.json`
files plus live OSV queries; see "Reproducing this analysis" at the end.

## The corpus's central limitation, stated up front

Of the four incidents in `dataset/malicious/`, **three had their actual
malicious release unpublished from npm** before this project could fetch
and diff it (event-stream, ua-parser-js, colors — see each `SOURCING.md`).
Every registry-fetched report for those three packages is therefore a diff
of an *adjacent* version pair, not the attack itself — useful for validating
non-false-positive behaviour, useless for measuring recall.

**node-ipc has two positive data points, each answering a different
question.** Its `peacenotwar` dependency was never unpublished from the
`11.0.0` release, so `10.1.0 → 11.0.0` is a real, *autonomously*
registry-diffable attack diff — what a deployed scanner would actually see
in the wild, no manual intervention required. Separately, the actual
destructive wiper (`10.1.1`, never published to a fetchable tarball) was
reconstructed from its exact verified git commit and run through the same
diff/LLM/feed pipeline directly against two local directories — see
`malicious/node-ipc/SOURCING.md` for exactly how, and why it was never
packaged into something installable. That pair answers "does the underlying
detection logic work, given the real signal" — a different question from
"can chainwatch's registry-based fetching find that signal on its own,"
which the `11.0.0` pair answers.

**Two positive examples is still a small sample.** The numbers below are
literal, not projectable to a general false-negative rate. Where useful, we
widen the lens using live feed queries against the *actual* malicious
version strings (no tarball needed — feed clients take a version string),
giving four data points instead of two for the detection-gap and
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
| node-ipc | 10.1.0→11.0.0 | malicious (real compromised dependency, registry-fetched) | 29.5 | LOW |
| **node-ipc** | **10.1.0→10.1.1** *(reconstructed)* | **malicious** (the actual wiper) | **69.0** | **HIGH** |

## Precision / recall (Figure 1)

Confusion matrix at the default classification rule — **flagged = severity
≠ LOW**:

| | Predicted malicious | Predicted benign |
|---|---|---|
| **Actually malicious** | TP = 1 (node-ipc, reconstructed) | FN = 1 (node-ipc, registry-fetched) |
| **Actually benign** | FP = 0 | TN = 9 |

- **Precision:** 1/1 = **100%**
- **Recall:** 1/2 = **50%**
- **Specificity / true-negative rate:** 9/9 = **100%**
- **False-positive rate:** 0/9 = **0%**

Read plainly: chainwatch never bucketed a benign diff above LOW, and it
correctly bucketed the one attack diff it saw in complete form as HIGH — but
it missed the one attack diff it saw in diluted, post-remediation form. That
split is the whole finding. It is not "the LLM missed the attack" (the
reconstructed run shows unambiguously that it doesn't, given the real
signal) and it is not "the bucketing threshold is wrong" in isolation either
(the `11.0.0` diff genuinely contains a milder signal than `10.1.1` does —
see the dimension breakdown below). It is a **fetching-completeness**
problem: chainwatch scored *correctly relative to what it could see*, and
what it could see, for the registry-fetched pair, was already-mitigated.

### What separates the hit from the near-miss, dimension by dimension

| dimension | `11.0.0` (peacenotwar remnant, missed — LOW) | `10.1.1` (full wiper, reconstructed — HIGH) |
|---|---|---|
| network_calls | 2.0 | **10.0** (corpus max) |
| obfuscation | 2.0 | **10.0** (corpus max) |
| env_conditional | 4.0 | **9.0** |
| install_hooks | 0.0 | 2.0 |
| dependency_changes | **9.0** (corpus max among benign-labelled pairs) | 1.0 |
| **llm_base_score** | 29.5 | **69.0** |

Both positives independently clear a **"any single dimension ≥ 7"** rule —
on *different* dimensions each time (`dependency_changes` for the diluted
pair, `network_calls`/`obfuscation` for the full attack) — while no
benign-labelled pair in the corpus ever exceeds 6.5 on any dimension. That
consistency, across two structurally different payloads from the same
incident, is more interesting than either result alone: it suggests the
per-dimension signal is more stable across attack variants than the
composite score is, though with n=2 positives this is a hypothesis to test
against a larger corpus, not a validated rule. Full breakdown of why
`dependency_changes`'s 15% weight caps the diluted pair's composite score in
`malicious/node-ipc/FINDINGS.md`.

## RQ1 — which detection layer catches each known attack

For the three incidents whose attack diff isn't fetchable or reconstructable
via git (event-stream, ua-parser-js, colors — see each `SOURCING.md`), "LLM
layer" performance can't be measured directly against the real payload —
but the feed layer can, by querying OSV directly for the *actual* malicious
version strings (no tarball needed). node-ipc's payload *was* recoverable
via git, so both layers were tested for real, on both the diluted and full
versions of the attack. Results, live-queried/run for this write-up:

| Incident | LLM layer | OSV feed (queried against the real malicious version) | Ever `MAL-*`? |
|---|---|---|---|
| event-stream / flatmap-stream | Not tested — attack diff unrecoverable even via git (account hijack, never pushed) | `GHSA-mh6f-8j2x-4483` (event-stream); `GHSA-9x64-5r7x-2q53` + **`MAL-2025-20690`** (flatmap-stream) | **Yes — flatmap-stream only, and only since 2025-08-14** |
| ua-parser-js | Not tested — same reason | `GHSA-pjwm-rvh2-c87w` | No, never |
| colors | Not tested — recoverable via git (`evidence/`) but not run through the pipeline this session | `GHSA-5rqg-jm4f-cqx7`, `GHSA-gh88-3pxp-6fm8` | No, never |
| node-ipc (registry-fetched, `11.0.0`) | Tested for real: `dependency_changes=9.0`, free-text names the incident, base score 29.5, **LOW** | `GHSA-3mpp-xfvh-qh37` | No, never |
| node-ipc (reconstructed, `10.1.1`) | **Tested for real:** `network_calls=10.0`, `obfuscation=10.0`, free-text: *"confirmed, unambiguous malicious payload"*, base score 69.0, **HIGH** | `GHSA-97m3-w2cp-4xx6` | No, never |

**The clearest single-incident result: given the complete attack, both
layers agree it's malicious, and the composite score reflects that (HIGH).**
Given only the post-remediation remnant, both layers still find real signal
(dependency_changes=9.0; a real if lower-severity GHSA) but the composite
stays LOW. The gap between those two rows is entirely about what got
fetched, not what the model or feeds are capable of recognising.

**The finding that generalises across all four incidents, not just the one
we could fully pipeline-test:** chainwatch's aggregator only floors the
score to the HIGH range when a feed reports `malicious` — which chainwatch
maps from an OSV `MAL-*` prefix specifically (`analyzer/feeds.py`). Of four
confirmed, publicly-documented supply-chain attacks, **only one has ever
received a `MAL-*` classification, and that happened three and a half years
after disclosure.** Even a chainwatch instance polling OSV in real time
today would still get `suspicious`, not `malicious`, for three of these four
incidents — the feed-floor rule's practical hit rate on this corpus's ground
truth is 1-in-4, and even that one hit took years. (Notably, node-ipc's HIGH
result above was reached *without* the feed-floor rule ever firing — OSV
returned `suspicious`, not `malicious`, for the reconstructed pair too. The
LLM layer alone carried that result.)

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
aggregator treats as decisive** — and never did for node-ipc, even for the
version chainwatch itself scored HIGH. The LLM layer's structural advantage
over a pure signature database is availability at publish time *and*, per
the reconstructed pair, the ability to reach a correct HIGH verdict entirely
on its own, without the feed-floor rule ever firing. Its structural
disadvantage is narrower than it looked before that pair was run: given the
*diluted* remnant of an attack, its strongest per-dimension finding (9.0/10)
didn't clear the aggregate severity bar; given the *complete* attack, two
dimensions hit the ceiling (10.0/10) and the composite followed correctly.

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

1. **`dependency_changes`'s 15% weight is worth revisiting for the diluted
   case specifically**, or a "known-compromised transitive dependency"
   special-case modifier — flagged in `malicious/node-ipc/FINDINGS.md`. Note
   this wouldn't have been needed for the *complete* attack (`10.1.1`
   reached HIGH on `network_calls`/`obfuscation` alone) — it's specifically
   about not under-scoring a post-remediation remnant that still carries a
   compromised dependency.
2. **CI users relying on `--threshold` should not assume the MEDIUM
   boundary (30) is a safe default** — `--threshold 25` would have caught
   the diluted `11.0.0` pair; the default severity-only view would not have.
   The complete attack (`10.1.1`) cleared HIGH regardless of threshold choice.
3. **The feed-floor rule's dependence on OSV's `MAL-*` prefix specifically
   (not `GHSA-*`) means it will rarely fire in practice**, per RQ1/RQ4 — a
   tool relying on chainwatch's `malicious_floor` modifier as its primary
   safety net would have missed 3 of 4 incidents in this corpus even with
   live feeds, for years in some cases, and *notably didn't need to fire*
   for the LLM layer to reach the correct HIGH verdict on the complete
   node-ipc attack — reinforcing that the LLM layer, not the feed floor, is
   carrying this tool's actual detection capability.
4. **Done for node-ipc, still open for colors.** This recommendation
   originally proposed exactly the reconstruction that produced the HIGH
   result above — done, via local-directory diffing rather than a mock
   registry (see `malicious/node-ipc/SOURCING.md` for why: a full mock-registry
   reconstruction would mean assembling an installable copy of a payload
   whose only dependency, a live geolocation API, plausibly still works,
   unlike event-stream/ua-parser-js's dead-C2 payloads). `colors`'s sabotage
   commit (`malicious/colors/evidence/`) is equally recoverable via git and
   has not yet been run through the pipeline this way — lower priority since
   its payload (an infinite loop) has a much lower severity ceiling than
   node-ipc's, so the marginal research value of reconstructing it is smaller.
5. **The ground-truth corpus still needs more real positives beyond
   node-ipc.** n=2, both from the same incident, is still a thin sample —
   real signal, not yet a validated recall measurement for the tool in
   general.

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

**One of the eleven reports — `node-ipc/report-10.1.0-to-10.1.1-RECONSTRUCTED.json`
— is not reproducible via `chainwatch diff`** (there is no real tarball to
fetch). It's reproducible by applying the exact diff at
`malicious/node-ipc/evidence/commit-847047cf7f81-relevant.diff` to a real,
still-published `node-ipc@10.1.0` tarball, then calling
`chainwatch.diff.engine.compute_diff()` directly on the two resulting
directories (bypassing the registry-fetch layer entirely, not mocking it) —
see `malicious/node-ipc/SOURCING.md` for the full method and why it was
built this way.
