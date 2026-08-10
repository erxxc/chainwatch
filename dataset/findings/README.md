# Cross-corpus findings: precision, recall, and detection gaps

This is "the write-up" referenced throughout `dataset/README.md` — the
synthesis across all fourteen reports in the corpus, addressing the four
research questions from the top-level `README.md`:

1. Which detection layer (LLM, feeds, or both) catches each known attack
2. The time delta between attack publication and feed coverage (the "detection gap")
3. False positive rates on benign packages with suspicious-looking patterns
4. Comparison with signature-based classifiers on the same ground truth

**Read the limitations section before citing any number here.** This
corpus has five positive examples, not one, and they split into four
categories that a single recall number would blur together:

- **A fetching-completeness miss, since fixed by reconstruction.**
  `node-ipc@11.0.0` (registry-fetched, the diluted post-remediation
  dependency) scores LOW. Reconstructing the complete attack
  (`node-ipc@10.1.1`, the actual wiper — never published to a fetchable
  tarball, rebuilt from its exact verified git commit and run directly
  against chainwatch's pipeline via local directories) flips the result to
  a decisive HIGH (69.0). Given the whole attack, detection works.
- **A taxonomy miss that survives reconstruction.** `colors`'s sabotage
  commit was reconstructed the same way — complete, real, byte-verified
  against a live base tarball — and it **still scores LOW (7.5)**, because
  it's a denial-of-service attack (an infinite loop) and none of
  chainwatch's five risk dimensions are shaped to detect that. This one
  isn't fixed by fetching more; it's a genuine blind spot in what the tool
  measures.
- **A hit, reconstructed from a different kind of evidence.**
  `flatmap-stream@0.1.1` (the transitive payload behind the `event-stream`
  incident — an account hijack, not a maintainer commit, so there's no git
  history to pull from) was instead reconstructed from CDN-archaeology
  evidence (a Wayback-cached unpkg copy, cross-validated against an
  academic paper's companion dataset) and run the same way: two local
  directories, real pipeline, no registry fetch. **Scores HIGH (60.0)** —
  detection works here too, though not purely on the LLM layer's strength
  alone (see below).
- **A second fetching/completeness-shaped gap, found and fixed the same
  day.** `ua-parser-js@0.7.29` (the real miner/credential-stealer preinstall
  attack) was reconstructed onto a real, still-published `0.7.28` base and
  first **scored MEDIUM (42.5)** — flagged, but the weakest hit in the
  corpus. Not because the LLM missed anything it was shown:
  `preinstall.sh`/`preinstall.bat`, where the actual payload logic lives,
  were never shown to it at all — chainwatch's diff engine only recognised
  a fixed set of source-file extensions, and `.sh`/`.bat` weren't in it. A
  controlled experiment adding just those two extensions confirmed the
  cause (**57.5, HIGH** on the identical attack), the fix was implemented
  for real (`SOURCE_EXTENSIONS` now includes `.sh`/`.bat`/`.ps1`/`.cmd`),
  and an independent, non-monkey-patched rerun against the real fixed code
  confirmed it: **60.0, HIGH.**

Read together: *does the detection logic work, given the real attack* is
"yes, with one confirmed exception" — data-exfiltration-shaped payloads are
caught whether reconstructed from git (node-ipc), CDN archaeology
(flatmap-stream), or a live base tarball plus recovered install scripts
(ua-parser-js, once the diff engine's file-type filter was widened to
actually show them to the model); a denial-of-service-shaped payload
(colors) is not, regardless of source completeness. *Can chainwatch's
registry-based fetching autonomously find these attacks in the wild* is no
for all four incidents, structurally, because npm's unpublish policy
destroys the evidence before any registry-diffing scanner — chainwatch or
otherwise — could see it.

All tables are computed directly from the fourteen committed `report-*.json`
files plus live OSV queries; see "Reproducing this analysis" at the end.
(Two report-shaped files are deliberately excluded from that count and from
every table below: ua-parser-js's pre-fix report, preserved for history at
`malicious/ua-parser-js/pre-fix-report-0.7.28-to-0.7.29-RECONSTRUCTED.json`,
and its full-visibility experiment. See "The reconstructed pair" in
`malicious/ua-parser-js/FINDINGS.md` for why.)

## The corpus's central limitation, stated up front

Of the four incidents in `dataset/malicious/`, **three had their actual
malicious release unpublished from npm** before this project could fetch
and diff it (event-stream/flatmap-stream, ua-parser-js, colors — see each
`SOURCING.md`). Every registry-fetched report for those three is therefore a
diff of an *adjacent* version pair, not the attack itself — useful for
validating non-false-positive behaviour, useless for measuring recall on
its own.

**All three of those incidents have since had their actual attack payload
recovered and run through the real pipeline as two local directories,
bypassing the registry-fetch layer entirely** — by three different sourcing
methods, not one, and all three are now exhausted for this corpus:

- **Git-commit reconstruction** (node-ipc, colors): both incidents were
  legitimate-maintainer self-sabotage, committed to a public repository, so
  the exact verified commit was applied to a real, still-published base
  tarball. See `malicious/node-ipc/SOURCING.md` / `malicious/colors/SOURCING.md`.
- **CDN-archaeology reconstruction** (event-stream/flatmap-stream): an
  account hijack, never pushed to git, and no live base tarball either —
  but the malicious `flatmap-stream` file was cached by unpkg's CDN before
  npm's takedown, recovered via the Wayback Machine, and cross-validated
  against an academic paper's companion dataset. See
  `malicious/event-stream/SOURCING.md`.
- **Live-tarball-plus-vendor-writeup splice** (ua-parser-js): also an
  account hijack, but unlike event-stream, the *pre-incident* version
  (`0.7.28`) is still published — so a real, still-live base tarball was
  fetched via chainwatch's own npm fetcher, and the recovered
  `preinstall.js`/`.sh`/`.bat` scripts (transcribed verbatim from a vendor
  writeup, cross-corroborated against three independent others) were
  spliced onto a copy of it, exactly as the real attack wired them in. See
  `malicious/ua-parser-js/SOURCING.md`.

**Five positive examples is still a small sample, and they don't all point
the same direction.** node-ipc's reconstruction flipped a miss into a hit;
flatmap-stream's reconstruction was a hit outright, but one that leans
partly on a feed rule rather than the LLM layer alone; ua-parser-js's
reconstruction *found* a gap in the diff engine itself (not the model) that
held it to a hit-by-technicality (MEDIUM, ≠ LOW but far from a clean HIGH)
— and that gap was diagnosed and fixed the same day, after which an
independent rerun against the real fixed code reached a clean HIGH too;
colors's reconstruction stayed a miss for a completely different reason
(see below), with no equivalent same-day fix available. None of this
generalises into a validated recall rate on five points. Where useful, we
widen the lens using live feed queries against the *actual* malicious
version strings (no tarball needed — feed clients take a version string),
giving more data points for the detection-gap and signature-comparison
questions than the reconstructed pairs alone.

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
| **colors** | **1.4.0→1.4.44-liberty-2** *(reconstructed)* | **malicious** (the actual sabotage) | **7.5** | **LOW** |
| **flatmap-stream** | **0.1.0→0.1.1** *(reconstructed)* | **malicious** (the actual bootstrap payload) | **60.0** | **HIGH** |
| **ua-parser-js** | **0.7.28→0.7.29** *(reconstructed)* | **malicious** (the actual miner/credential-stealer attack) | **60.0** | **HIGH** |

## Precision / recall (Figure 1)

Confusion matrix at the default classification rule — **flagged = severity
≠ LOW**:

| | Predicted malicious | Predicted benign |
|---|---|---|
| **Actually malicious** | TP = 3 (node-ipc, reconstructed; flatmap-stream, reconstructed; ua-parser-js, reconstructed) | FN = 2 (node-ipc registry-fetched; colors, reconstructed) |
| **Actually benign** | FP = 0 | TN = 9 |

- **Precision:** 3/3 = **100%**
- **Recall:** 3/5 = **60%**
- **Specificity / true-negative rate:** 9/9 = **100%**
- **False-positive rate:** 0/9 = **0%**

Read plainly: chainwatch never bucketed a benign diff above LOW, and it
correctly flagged three of the five real attacks it saw in complete form —
all three cleanly as HIGH (node-ipc, exfiltration-shaped; flatmap-stream,
obfuscation/env-gated; ua-parser-js, install-hook/miner-shaped, as of the
`SOURCE_EXTENSIONS` fix below). It missed the diluted node-ipc remnant and
the complete colors attack entirely. **None of these five outcomes are the
same finding** — collapsing them into one recall number would hide the more
useful result:

- **node-ipc's miss is a fetching-completeness problem, demonstrated
  fixed.** chainwatch scored *correctly relative to what it could see*, and
  what it could see, for the registry-fetched pair, was already-mitigated.
  Given the complete attack, it scores HIGH — carried entirely by the LLM
  layer, no feed rule needed.
- **flatmap-stream's hit is real, but not purely an LLM-layer story.** The
  complete attack was recoverable (via CDN archaeology, not git) and scores
  HIGH — but the LLM base score alone (51.5) only reaches MEDIUM. The
  composite crosses into HIGH because OSV's `malicious_floor` rule fires for
  this specific advisory (`MAL-2025-20690`), the only time it fires anywhere
  in this corpus. Swap in a hypothetical world where that reclassification
  hadn't happened yet (true for all but the last year of this incident's
  seven-year history) and the result still lands HIGH here, but only just
  (56.5, on the Scorecard modifier alone) — a much thinner margin than
  node-ipc's LLM-carried 69.0. See `malicious/event-stream/FINDINGS.md`.
- **ua-parser-js's hit was a technicality — until a same-day code fix made
  it a clean one.** The complete attack, reconstructed onto a real base
  tarball and wired in exactly as it shipped, first reached only MEDIUM
  (42.5), because chainwatch's own `SOURCE_EXTENSIONS` allowlist never
  enumerated `preinstall.sh`/`.bat` — the two files carrying the actual
  payload — so the LLM only ever saw the dispatcher that calls them. This
  wasn't a taxonomy gap (`install_hooks`/`env_conditional` fired correctly
  on what they *were* shown) and wasn't a fetching gap (the base tarball
  was real and complete) — it was the diff engine's file-type filter
  specifically, and unlike colors's gap, it was a one-line fix:
  `SOURCE_EXTENSIONS` now includes `.sh`/`.bat`/`.ps1`/`.cmd`. An
  independent rerun against the real fixed code (not a monkey-patch)
  reaches **60.0, HIGH** on the identical attack. See
  `malicious/ua-parser-js/FINDINGS.md` for the full before/after.
- **colors's miss is a taxonomy problem.** The complete, real attack was
  presented to the model and it still scored LOW, because a denial-of-service
  payload (an infinite loop) doesn't match any of chainwatch's five risk
  dimensions (network calls, obfuscation, install hooks, env conditionals,
  dependency changes) — all five scored at or near zero, correctly, because
  none of those patterns are present. The free-text summary *does* correctly
  call it "malicious in effect" — the miss is specifically in how that
  recognition does or doesn't propagate into the scored dimensions. Not
  fixable by better fetching; would need a sixth dimension or a taxonomy
  change. See `malicious/colors/FINDINGS.md`.

### What separates a fetching miss from a taxonomy miss, dimension by dimension

| dimension | node-ipc `11.0.0` (fetching miss — LOW) | node-ipc `10.1.1` (reconstructed — HIGH) | flatmap-stream `0.1.1` (reconstructed — HIGH) | ua-parser-js `0.7.29` (reconstructed, post-fix — HIGH) | colors (reconstructed — still LOW) |
|---|---|---|---|---|---|
| network_calls | 2.0 | **10.0** (corpus max) | 3.0 | **10.0** (corpus max) | 0.0 |
| obfuscation | 2.0 | **10.0** (corpus max) | **10.0** (corpus max) | 2.0 | 1.0 |
| env_conditional | 4.0 | **9.0** | **9.0** | **9.0** | 0.0 |
| install_hooks | 0.0 | 2.0 | 2.0 | **10.0** (corpus max) | 0.0 |
| dependency_changes | **9.0** | 1.0 | 1.0 | 1.0 | 0.0 |
| **llm_base_score** | 29.5 | **69.0** | **51.5** | **65.0** | **2.5** |
| **risk_score (feed-adjusted)** | 29.5 | 69.0 | **60.0** | **60.0** | 7.5 |

An earlier draft of this write-up, written after only node-ipc's two
positives existed, proposed **"any single dimension ≥ 7"** as a candidate
rule — it happened to hold for both node-ipc pairs, on different dimensions
each time, and it holds for flatmap-stream (`obfuscation`/`env_conditional`
both ≥ 9) and ua-parser-js (`network_calls`/`install_hooks` both at the
corpus max, post-fix) too. **colors refutes it: its highest dimension score
is 1.0.** That correction is worth keeping visible rather than quietly
fixing — it's the clearest demonstration in this write-up of why n=2 wasn't
enough to generalise from, and n=5 still isn't (four points consistent with
a rule and one clean counterexample is not a validated rule). The dimension
set's blind spot for denial-of-service attacks isn't a threshold-tuning
problem; no per-dimension or composite-score rule built from these five
dimensions can catch colors, because none of the five ever fire on it. Full
breakdown of the `dependency_changes` weight-capping issue specifically
(which *is* a threshold/weighting problem, for node-ipc's diluted pair
only) in `malicious/node-ipc/FINDINGS.md`.

Worth flagging separately: flatmap-stream's `llm_base_score` (51.5) clears
the "any dimension ≥ 7" bar comfortably but does *not* clear the
55-point HIGH severity threshold on its own — it takes the feed-adjusted
`risk_score` (60.0, after the OSV and Scorecard modifiers) to cross into
HIGH. A per-dimension or raw-LLM-score rule would still correctly flag this
one as suspicious even without the feed boost; the *severity bucket*
specifically is where the feed layer's contribution shows up. See
`malicious/event-stream/FINDINGS.md` for the full modifier trace.

**ua-parser-js's column tells a before/after story the table alone can't
show.** Pre-fix, `install_hooks` was already 9.0 — the single
highest-confidence dimension score in that run (0.95), correctly reflecting
a real new `preinstall` hook, scored *without the LLM ever seeing the
actual payload*, purely from the dispatcher script plus the `package.json`
metadata diff. That's the dimension set doing exactly what it's designed to
do, on partial evidence. What it couldn't do was compensate for
`network_calls` (pre-fix: 6.0, confidence 0.4 — the lowest confidence
recorded anywhere in this write-up) and `env_conditional` (pre-fix: 7.0)
staying muted, because the diff engine withheld the two files
(`preinstall.sh`/`.bat`) that would have driven those higher. The numbers
in the table above are the post-fix rerun — `network_calls` and
`install_hooks` both now hit the corpus max (10.0) with confidence 1.0. See
`malicious/ua-parser-js/FINDINGS.md` for the full pre-fix/post-fix
comparison.

## RQ1 — which detection layer catches each known attack

All four incidents in this corpus have now had their real attack payload
tested for real against the LLM layer — node-ipc and colors via git-commit
reconstruction, event-stream/flatmap-stream via CDN archaeology, and
ua-parser-js via a real base tarball with the recovered `preinstall`
scripts spliced on. Results, live-queried/run for this write-up:

| Incident | LLM layer | OSV feed (queried against the real malicious version) | Ever `MAL-*`? |
|---|---|---|---|
| event-stream / flatmap-stream (reconstructed, `0.1.1`) | **Tested for real:** `obfuscation=10.0`, `env_conditional=9.0`, free-text: *"a definitive, confirmed malicious supply chain attack"*, base score 51.5 (MEDIUM on its own), feed-adjusted **60.0, HIGH** | `GHSA-mh6f-8j2x-4483`, `GHSA-9x64-5r7x-2q53`, **`MAL-2025-20690`** | **Yes — flatmap-stream only, and only since 2025-08-14** |
| ua-parser-js (reconstructed, `0.7.29`, post-fix) | **Tested for real:** `network_calls=10.0`, `install_hooks=10.0`, `env_conditional=9.0`, free-text names the incident by CVE, base score 65.0, feed-adjusted **60.0, HIGH**. Pre-fix (a diff-engine file-extension gap, `.sh`/`.bat` not enumerated) this same attack scored only 42.5, MEDIUM — see `malicious/ua-parser-js/FINDINGS.md` | `GHSA-pjwm-rvh2-c87w` | No, never |
| colors (reconstructed, `1.4.44-liberty-2`) | **Tested for real:** all 5 dimensions ≤1.0, free-text correctly names the incident but calls it "malicious in effect" without that reaching any dimension, base score 2.5, **LOW** | `GHSA-5rqg-jm4f-cqx7`, `GHSA-gh88-3pxp-6fm8` | No, never |
| node-ipc (registry-fetched, `11.0.0`) | Tested for real: `dependency_changes=9.0`, free-text names the incident, base score 29.5, **LOW** | `GHSA-3mpp-xfvh-qh37` | No, never |
| node-ipc (reconstructed, `10.1.1`) | **Tested for real:** `network_calls=10.0`, `obfuscation=10.0`, free-text: *"confirmed, unambiguous malicious payload"*, base score 69.0, **HIGH** | `GHSA-97m3-w2cp-4xx6` | No, never |

**The result that most needed the complete attack to become visible: given
node-ipc's full payload, both layers agree it's malicious and the composite
score reflects that (HIGH), carried by the LLM layer alone.** Given only
node-ipc's post-remediation remnant, both layers still find real signal
(dependency_changes=9.0; a real if lower-severity GHSA) but the composite
stays LOW — a fetching-completeness gap, demonstrated fixed by
reconstruction. **flatmap-stream's complete attack also reaches HIGH, but
through a different mechanism**: the LLM layer finds strong signal
(obfuscation and env-gating both correctly scored ≥9) yet its base score
alone only clears MEDIUM — it's the OSV feed, reporting `malicious` on this
one advisory, that pushes the composite over the HIGH threshold.
**ua-parser-js's complete attack needed a code fix to reach HIGH, and once
it did, neither layer was ever the bottleneck**: the LLM correctly
identified the incident and scored the dimensions it was shown strongly
even before the fix, and OSV correctly returned the real advisory
throughout — the pre-fix shortfall was entirely upstream of both layers, in
the diff engine's file enumeration step, and a same-day widening of
`SOURCE_EXTENSIONS` closed it, confirmed by an independent rerun.
**colors shows that "complete attack" isn't sufficient on its own**: even
with the full, real sabotage commit, the LLM layer's free-text correctly
recognises it while its scored dimensions don't, and the OSV feed finds
real advisories that (like every advisory in this corpus except one) never
reach `MAL-*`. Both layers "know" about colors in some sense; neither
translates that knowledge into a flagged composite score — and unlike
ua-parser-js's gap, there's no single-line fix available for this one; see
recommendation #1.

**The finding that generalises across all four incidents:** chainwatch's
aggregator only floors the score to the HIGH range when a feed reports
`malicious` — which chainwatch maps from an OSV `MAL-*` prefix specifically
(`analyzer/feeds.py`). Of four confirmed, publicly-documented supply-chain
attacks, **only one has ever received a `MAL-*` classification, and that
happened nearly seven years after disclosure** (2018-11-20 → 2025-08-14,
live-verified against OSV's own `published` field for this write-up — an
earlier draft of this document mis-stated this gap as "three and a half
years"; corrected here). Even a chainwatch instance polling OSV in real
time today would still get `suspicious`, not `malicious`, for three of
these four incidents — the feed-floor rule's practical hit rate on this
corpus's ground truth is 1-in-4, and even that one hit took most of a
decade. Notably, node-ipc's HIGH result above was reached *without* the
feed-floor rule ever firing — OSV returned `suspicious`, not `malicious`,
for the reconstructed pair too, and the LLM layer alone carried that
result. **flatmap-stream's HIGH result is the opposite case**: it's the one
pair in this corpus where the feed-floor rule's rare, years-late hit
actually mattered to the outcome — run this same query before 2025-08-14
and the composite would have landed at 56.5 (still HIGH, but on the
Scorecard modifier's back, not OSV's). **ua-parser-js sits apart from
both**: OSV never reaches `MAL-*` for it at all, so the feed layer never
contributed to pushing this one higher, before or after the fix — the
entire pre-fix shortfall, and its resolution, lived in the diff engine, not
in either detection layer.

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
  a `MAL-*` entry, nearly seven years after disclosure (see RQ1).
- **Speed: highly variable, 8 hours to 11 weeks** (see RQ2), with no
  advisory ever available at the moment of attack publication.

The comparison isn't "OSV vs. chainwatch" — chainwatch *uses* OSV as one of
three feed inputs. The more useful framing: **OSV is reliable but slow, and
rarely reaches the confidence tier (`MAL-*`) that chainwatch's own
aggregator treats as decisive** — in this corpus, only for flatmap-stream,
and only years after the fact. The one case where it *did* reach `MAL-*` in
time to matter (flatmap-stream, queried live for this write-up) shows what
that tier is worth when it fires: it's the difference between a thin
56.5-MEDIUM-adjacent HIGH and a more comfortable 60.0 HIGH — a real but
modest contribution, not the load-bearing signal. The LLM layer's
structural advantage over a pure signature database is availability at
publish time *and*, per node-ipc's reconstructed pair, the ability to reach
a correct HIGH verdict entirely on its own, without the feed-floor rule ever
firing — flatmap-stream shows that same layer finding strong signal
(obfuscation/env-gating both ≥9) even where it *doesn't* single-handedly
carry the severity bucket. Its structural disadvantage had three distinct
shapes, not one, and one of them is now closed: given a *diluted* remnant
of an exfiltration-shaped attack (node-ipc `11.0.0`), the strongest
per-dimension finding (9.0/10) didn't clear the aggregate severity bar, but
*did* once fetching improved via reconstruction. Given a *complete*
install-hook attack whose payload lived in `.sh`/`.bat` files
(ua-parser-js), a signature database sidestepped the diff engine's
extension gap entirely — OSV's advisory doesn't care what file extension
the payload shipped in, so this was, briefly, the one place in this
comparison where a pure signature lookup had a structural edge over
chainwatch. That edge closed the same day the gap was found:
`SOURCE_EXTENSIONS` now recognises `.sh`/`.bat`/`.ps1`/`.cmd`, and OSV's
edge here reduces to what it is everywhere else in this comparison — slower
and less available. Given a *complete* denial-of-service-shaped attack
(colors), no amount of better fetching helps — the dimension set itself has
no concept of "this never returns," and a signature database is no better
positioned here either (colors's two GHSA advisories exist and are just as
un-actionable as chainwatch's own score). This is the one gap in the
corpus with no signature-database workaround and no diff-engine fix
available — see recommendation #1.

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

1. **A sixth risk dimension for denial-of-service / resource-exhaustion
   patterns is worth adding.** It's the only change that would have altered
   colors's result, and colors is the one positive in this corpus where the
   miss survives having the complete attack in hand *and* full diff
   visibility (contrast with #2). Candidate signal: does the diff introduce
   unbounded loops, recursion, or blocking operations gated on nothing (no
   timeout, no exit condition, no rate limit)? The free-text summary already
   reliably notices this pattern qualitatively (see
   `malicious/colors/FINDINGS.md`) — the gap is purely that nothing routes
   it into a score.
2. **✅ Implemented (2026-08-10).** `SOURCE_EXTENSIONS`
   (`src/chainwatch/diff/engine.py`) now includes `.sh`, `.bat`, `.ps1`,
   and `.cmd` alongside the original JS/TS/Python types. This was the
   lowest-effort, most concretely-demonstrated fix in this write-up — not a
   hypothesis about what *would* help, but a controlled, real rerun:
   ua-parser-js's reconstructed attack scored MEDIUM (42.5) as chainwatch
   behaved before the fix, because `preinstall.sh`/`.bat` (where the real
   payload lives) were never enumerated by the diff engine at all. Adding
   exactly those two extensions to the allowlist, changing nothing else,
   reached HIGH (57.5) on the identical attack in a controlled experiment —
   and after the real fix landed, an independent, non-monkey-patched rerun
   confirmed it: **60.0, HIGH**. A regression test
   (`tests/unit/test_diff_engine.py::test_install_scripts_are_enumerated`)
   guards against this regressing. Install-time attacks shipping a
   `.sh`/`.bat`/`.ps1`/`.cmd` payload alongside a thin JS dispatcher are a
   common, well-documented pattern (this incident is a canonical example)
   — this fix plausibly generalises well beyond this one corpus entry. See
   `malicious/ua-parser-js/FINDINGS.md` for the full before/after.
3. **`dependency_changes`'s 15% weight is worth revisiting for diluted
   exfiltration-shaped attacks specifically**, or a "known-compromised
   transitive dependency" special-case modifier — flagged in
   `malicious/node-ipc/FINDINGS.md`. This is a narrower, lower-priority fix
   than #1/#2: it only helps node-ipc's diluted pair (the complete attack
   already reached HIGH without it) and does nothing for colors's category
   of gap (ua-parser-js's category is now fixed — see #2).
4. **CI users relying on `--threshold` should not assume the MEDIUM
   boundary (30) is a safe default — but should also not assume a lower
   threshold is a complete fix.** `--threshold 25` would have caught
   node-ipc's diluted `11.0.0` pair. Pre-fix, `--threshold 40` would have
   been needed to catch ua-parser-js's reconstructed attack (42.5); post-fix
   it clears the default HIGH bar (60.0) with no special threshold needed.
   No `--threshold` value catches colors's reconstructed attack (LLM base
   score 2.5) without also flagging essentially every benign diff in the
   corpus — this is a taxonomy gap, not a threshold-tuning problem, and #1
   is the actual fix.
5. **The feed-floor rule's dependence on OSV's `MAL-*` prefix specifically
   (not `GHSA-*`) means it will rarely fire in practice**, per RQ1/RQ4 — a
   tool relying on chainwatch's `malicious_floor` modifier as its primary
   safety net would have missed 3 of 4 incidents in this corpus even with
   live feeds, for years in some cases, and does nothing at all for
   ua-parser-js (never `MAL-*`, ever, before or after the diff-engine fix).
   It *notably didn't need to fire* for the LLM layer to reach the correct
   HIGH verdict on the complete node-ipc or (post-fix) ua-parser-js attacks,
   but flatmap-stream shows the opposite side of the same coin: the one
   time it *did* fire, it was the difference between a comfortable HIGH and
   a thin one (60.0 vs. a hypothetical 56.5 without it) — reinforcing that
   the LLM layer, not the feed floor, is carrying this tool's primary
   detection capability, with the feed floor as an occasional, unreliably-
   timed assist rather than a mechanism to depend on.
6. **Reconstruction-and-run is now done for all four incidents in this
   corpus, via three different sourcing methods — and one of the two gaps
   it surfaced has already been fixed.** node-ipc and colors were
   legitimate-maintainer self-sabotage with the payload surviving in git.
   event-stream/flatmap-stream was an account hijack with no git history and
   no live base tarball, but the payload survived in a CDN's edge cache long
   enough for the Wayback Machine to crawl it. ua-parser-js was also an
   account hijack, but its *pre*-incident version is still published, so a
   real base tarball plus vendor-writeup-recovered payload scripts
   sufficed — and doing so found the `SOURCE_EXTENSIONS` gap fixed in #2.
   **This corpus's currently-scoped incidents are now exhausted** — every
   incident in `dataset/malicious/` has had its real attack tested for real
   against both detection layers, and two of the four (node-ipc,
   ua-parser-js) have already driven a real fix. See each incident's
   `SOURCING.md`.
7. **The ground-truth corpus still needs real positives from incidents
   beyond these four.** n=5 across four incidents — now three clean HIGH
   hits (one LLM-carried, one partly feed-carried, one that needed a
   same-day diff-engine fix to get there) and one miss that survives
   complete reconstruction and full diff visibility — is real signal about
   *what kinds* of gaps and successes exist across three different
   sourcing methods, but still not a validated recall measurement for the
   tool in general. The three sourcing methods identified here
   ("maintainer-sabotage-with-git-history",
   "account-hijack-with-CDN-recoverable-payload-and-no-live-base",
   "account-hijack-with-a-live-pre-incident-base") cover every incident
   currently in scope; broadening the corpus now requires finding *new*
   incidents, not re-mining these four.

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

**Four of the fourteen reports are not reproducible via `chainwatch diff`**
(there's no real *malicious-version* tarball to fetch for any of the four —
though for ua-parser-js, the *baseline* side is a real fetch):

- `node-ipc/report-10.1.0-to-10.1.1-RECONSTRUCTED.json` — apply
  `malicious/node-ipc/evidence/commit-847047cf7f81-relevant.diff` to a real,
  still-published `node-ipc@10.1.0` tarball.
- `colors/report-1.4.0-to-1.4.44-liberty-2-RECONSTRUCTED.json` — apply
  `malicious/colors/evidence/commit-074a0f8ed0c3.diff` (or just copy in
  `evidence/american.js` and `evidence/index.js` directly, which are
  already the exact post-sabotage file contents) to a real, still-published
  `colors@1.4.0` tarball.
- `event-stream/report-flatmap-stream-0.1.0-to-0.1.1-RECONSTRUCTED.json` —
  no base tarball exists to apply anything to (npm serves only a
  security-holding placeholder for every `flatmap-stream` version string,
  confirmed via direct registry check). Instead, copy
  `malicious/event-stream/evidence/flatmap-stream-0.1.0-index.min.js` into
  an `0.1.0/index.min.js` directory as the "from" side, and
  `flatmap-stream-0.1.1-index.min.js` + `test-data.js` (as
  `0.1.1/index.min.js` + `0.1.1/test/data.js`) as the "to" side.
- `ua-parser-js/report-0.7.28-to-0.7.29-RECONSTRUCTED.json` — fetch the
  real, still-published `ua-parser-js@0.7.28` tarball (via chainwatch's own
  npm fetcher, or `chainwatch diff npm ua-parser-js 0.7.28 0.7.28` and take
  either side) as *both* directories, then in the "to" copy add
  `malicious/ua-parser-js/evidence/preinstall.js`/`.sh`/`.bat` to the
  package root and set `package.json`'s `scripts.preinstall` to
  `"start /B node preinstall.js & node preinstall.js"`. This reproduces
  against the *current* codebase (`SOURCE_EXTENSIONS` includes `.sh`/`.bat`
  as of 2026-08-10) — no patching needed any more. Two companion files
  preserve the pre-fix state for history, not part of this count:
  `malicious/ua-parser-js/pre-fix-report-0.7.28-to-0.7.29-RECONSTRUCTED.json`
  (the same steps above, run against the codebase *before* the fix) and
  `malicious/ua-parser-js/experiment-full-visibility-0.7.28-to-0.7.29.json`
  (the pre-fix codebase with `SOURCE_EXTENSIONS` monkey-patched in-process
  — the diagnostic step that preceded the real fix).

All four are then reproducible by calling
`chainwatch.diff.engine.compute_diff()` directly on the two resulting
directories (bypassing the registry-fetch layer entirely, not mocking it) —
see each incident's `SOURCING.md` for the full method and why it was built
this way. Feed lookups (OSV/Rekor/Scorecard) still hit the real APIs in all
four cases; only the malicious-version tarball fetch is bypassed.
