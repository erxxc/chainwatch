# Cross-corpus findings: precision, recall, and detection gaps

This is "the write-up" referenced throughout `dataset/README.md` — the
synthesis across all eighteen reports in the corpus, addressing the four
research questions from the top-level `README.md`:

1. Which detection layer (LLM, feeds, or both) catches each known attack
2. The time delta between attack publication and feed coverage (the "detection gap")
3. False positive rates on benign packages with suspicious-looking patterns
4. Comparison with signature-based classifiers on the same ground truth

**Read this whole section before citing any number below — especially the
headline one.** As of 2026-08-11, every one of this corpus's nine
malicious-labelled examples scores above LOW: **100% precision, 100%
recall** at the default classification rule. That number is real — it's
computed directly from the eighteen committed `report-*.json` files, not
estimated — but it comes with a methodological caveat serious enough to
state before anything else: **two of the code changes that produced it
were derived by directly observing failures in four of these six
incidents, and verified not to cause false positives only against that same
corpus.** That's about as close to "tuned on the test set" as empirical
work gets. Two incidents added after both fixes existed, specifically to
check whether they generalise, tell two different parts of that story.
`ctx` validates that the *rest* of the pipeline (the original five
dimensions, working without either new mechanism) correctly classifies a
real attack shaped differently from anything that came before it, but
never engages `resource_exhaustion` or `_apply_dimension_floor` at all.
`Lucide Proxy` (added 2026-08-11) goes one step further: it's a real DoS
attack, shaped nothing like `colors`'s infinite loop (an async, unbounded
polling beacon instead of a synchronous blocking one), and
`resource_exhaustion` correctly recognises it — 8.0/10 at confidence 0.95,
the first out-of-corpus validation this specific dimension has had.
`_apply_dimension_floor` still doesn't fire (8.0 falls short of its ≥9.0
trigger), and the final score is floored to HIGH by a fast, real OSV
`MAL-*` hit regardless of what either LLM mechanism does — so this is real
progress on recommendation #7, not a full resolution of it. See "The
overfitting caveat, stated as plainly as possible" below, and
recommendation #7's (still partial) resolution. A separate attempt to
source an attack specifically to stress-test the floor rule (`coa`/`rc`)
hit a real sourcing wall and produced an inconclusive result — not counted
in the eighteen — that a deliberate follow-up then turned into a second,
distinct, *quantified* validity concern: 20–28.5
points of a report's score can come from descriptive prose sitting inside
a diff rather than from any code being analysed. See "A second, distinct
caveat: narrative leakage" below before treating this write-up's numbers
as fully settled.

## How the corpus got here — three gaps, four fixes, all in one day

Every one of the four incidents in `dataset/malicious/` was, at some point
in this project's history, either a false negative or a weaker true
positive than it should have been. All three gaps have since been closed —
one via a fetching/reconstruction method change, three via real code
changes (the third gap needed two):

- **A fetching-completeness miss, fixed by reconstruction.**
  `node-ipc@11.0.0` (registry-fetched, the diluted post-remediation
  dependency) originally scored LOW. Reconstructing the complete attack
  (`node-ipc@10.1.1`, the actual wiper — never published to a fetchable
  tarball, rebuilt from its exact verified git commit and run directly
  against chainwatch's pipeline via local directories) flipped the result
  to a decisive HIGH. No code changed; the fetch/reconstruction layer did
  its job once given the complete artifact.
- **A diff-engine file-type filter, fixed with a one-line code change.**
  `ua-parser-js@0.7.29` (the real miner/credential-stealer preinstall
  attack), reconstructed onto a real, still-published `0.7.28` base, first
  scored MEDIUM — flagged, but weak — because `chainwatch.diff.engine
  .SOURCE_EXTENSIONS` didn't recognise `.sh`/`.bat`, so the two files
  carrying the actual payload were never shown to the LLM at all. Fixed by
  widening the allowlist (`src/chainwatch/diff/engine.py`); a same-day
  regression test guards against it regressing.
- **A taxonomy gap plus an aggregation-formula gap, fixed with two code
  changes.** `colors@1.4.44-liberty-2` (the real sabotage commit — an
  unconditional infinite loop) scored LOW even at full reconstruction
  fidelity, because none of the original five risk dimensions had any
  concept of denial-of-service. Adding a sixth dimension
  (`resource_exhaustion`) was *necessary* — the model then correctly scores
  it 10.0/10 at full confidence — but *not sufficient*: the weighted-sum
  formula caps what one dimension alone can contribute (20 points out of
  100 at this dimension's weight), so the composite still landed at 25,
  still LOW. A second fix, `_apply_dimension_floor` in
  `analyzer/aggregator.py` (any dimension scoring ≥9.0 at confidence ≥0.9
  floors the composite to MEDIUM), closed the remaining gap. That second
  rule turned out to mechanically apply to `node-ipc@11.0.0`'s
  `dependency_changes=9.0` too, flipping that pair from LOW to MEDIUM as a
  side effect — a genuine reclassification the corpus had been flagging as
  a near-miss since it was first run (see recommendation #3's resolution).

All three malicious-package reconstructions previously scoring HIGH
(node-ipc `10.1.1`, flatmap-stream `0.1.1`, ua-parser-js `0.7.29`) were
rerun against the fully-fixed code for corpus-wide consistency — none
changed severity bucket, though their exact scores shifted (see the
dimension table below). See each incident's own `FINDINGS.md`/`SOURCING.md`
for the full before/after narrative and every intermediate number.

**A fifth incident, `ctx` (PyPI, added 2026-08-11), is different in kind
from the four above: it wasn't reconstructed to close a gap chainwatch
surfaced, it was reconstructed *because* every known gap had already been
closed** — the direct answer to recommendation #7's call for ground-truth
positives sourced independently of the incidents that shaped
`resource_exhaustion`/`_apply_dimension_floor`. Both of its pairs score
MEDIUM/HIGH (42.5 and 56.5, after a same-day rerun described below) using
only the original five dimensions — neither new mechanism fires on either
pair, and both scores are pure `llm_base_score` with zero feed-modifier
contribution, the cleanest "LLM layer alone" result in the corpus. `ctx`'s
own reconstruction then surfaced two further, narrower diff-engine gaps
(`requirements.txt` unparsed, PyPI `maintainer_changed` missing) — unlike
the three fixes above, these didn't cause a misclassification, but they
were fixed the same day anyway (recommendation #10) and reconfirmed on a
rerun against this exact incident, which is what moved its scores from the
originally-reported 41.5/52.0 to the current 42.5/56.5 — the `0.2.5` pair
crossed from MEDIUM into HIGH as a direct result. A third, unrelated
observation from the same incident (recommendation #9, `env_conditional`'s
scope) remains open, undecided by design rather than left broken. See
`malicious/ctx/FINDINGS.md` for the full breakdown.

**A sixth incident, `Lucide Proxy` (npm, added 2026-08-11), was chosen
specifically to test what `ctx` didn't: a real DoS attack, shaped
differently from `colors`'s synchronous infinite loop.** 148 npm packages
disguised as student web-proxy tools silently recruited visiting browsers
into a DDoS botnet; the recoverable fragment of that payload (an
unconditional, asynchronous `setInterval` polling loop with no exit
condition — see `malicious/lucide-proxy/`) is structurally nothing like
`colors`'s blocking `for` loop. `resource_exhaustion` scored it 8.0/10 at
confidence 0.95 — real, independent, out-of-corpus validation that the
dimension generalises past the one shape it was designed around.
`_apply_dimension_floor` still didn't fire (8.0 falls short of its ≥9.0
trigger), and the final composite score (55.0, HIGH on both of its two
pairs) is entirely floor-imposed by a real, unusually *fast* OSV `MAL-*`
hit — not by either LLM mechanism. Read this as partial, honest progress
on recommendation #7, not its resolution: one of its two open questions
now has a real answer, the other still doesn't. Unlike every other
incident in this corpus, no live or archived tarball exists on either
side — what's real here is two independently-recovered payload fragments
from the campaign's own external infrastructure, layered onto an
explicitly synthetic package scaffold. See `malicious/lucide-proxy/
FINDINGS.md` for the full breakdown, including why `resource_exhaustion`
scored *lower* (6.0, not 8.0) when a second, unrelated real payload file
was added alongside it — a genuinely new, unresolved calibration question.

All tables are computed directly from the eighteen committed `report-*.json`
files plus live OSV queries; see "Reproducing this analysis" at the end.
Several report-shaped files are deliberately excluded from that count and
every table below: pre-fix snapshots preserved for history
(`malicious/ua-parser-js/pre-fix-report-0.7.28-to-0.7.29-RECONSTRUCTED.json`,
`malicious/colors/pre-dos-fix-report-1.4.0-to-1.4.44-liberty-2-RECONSTRUCTED.json`,
`malicious/node-ipc/pre-dos-fix-report-10.1.0-to-11.0.0.json`,
`malicious/ctx/pre-pypi-fix-report-0.1.2-to-0.1.2-1-RECONSTRUCTED.json`,
`malicious/ctx/pre-pypi-fix-report-0.1.2-to-0.2.5-RECONSTRUCTED.json`) and
ua-parser-js's diagnostic full-visibility experiment. See "Reproducing this
analysis" for the complete inventory.

## The overfitting caveat, stated as plainly as possible

Both `resource_exhaustion` and `_apply_dimension_floor` were designed,
implemented, and validated in direct response to one incident (`colors`)
and checked against the *existing* corpus before being called safe. That
process looked like this:

1. Observe: `colors`'s complete, real attack scores LOW.
2. Hypothesise a fix: add a dimension for the exact pattern that's missing.
3. Implement it, rerun, observe it's *still* LOW (25 — necessary, not
   sufficient).
4. Hypothesise a second fix: a floor rule for near-certain, near-maximal
   single-dimension findings.
5. Before shipping, check: does this fire on any of the 9 benign-labelled
   reports already in the corpus? No. Does it fire on any malicious-labelled
   report? Yes — `colors` (intended) and `node-ipc@11.0.0` (a bonus,
   correctly-directed reclassification).
6. Ship it. `colors` now scores MEDIUM.

Step 5 is a real validation step — it's not nothing — but the validation
set *is the same corpus the write-up reports precision/recall against*.
A rule tuned to fire on exactly the malicious examples already known and
verified not to fire on exactly the benign examples already known will,
definitionally, improve measured precision/recall on that same set, and
this says comparatively little about how it behaves on an attack shaped
differently from anything in this corpus's five examples. The
`resource_exhaustion` scoring guide's explicit language — *"an infinite
loop... is a 10 even with zero network calls"* — was written with `colors`
specifically in mind. It generalises plausibly (bounded loops in real code
are common and the model already distinguishes them correctly, see RQ3),
but "plausibly" is doing real work in that sentence.

**Update, 2026-08-11: recommendation #7 has been partially executed, not
fully.** `ctx` (PyPI) is the corpus's first ground-truth positive sourced
and reconstructed after both `resource_exhaustion` and
`_apply_dimension_floor` already existed, specifically to check whether
they generalise past the four incidents that shaped them. The honest
result: **it doesn't test them at all.** `ctx`'s attack shape (environment-
variable exfiltration at import time) never engages `resource_exhaustion`
(correctly scores 0.0 — there's no DoS component) and never needs the floor
rule (the original five dimensions alone already clear MEDIUM). What it
*does* validate is narrower but still real: the original five-dimension
scoring, unmodified since before any 2026-08-10 fix, correctly classifies a
genuinely novel attack shape it was never tuned against, with zero feed
contribution to lean on. That's meaningful — it says the pipeline's core
detection isn't fragile to shapes outside its original design set — but it
is not evidence about the two mechanisms this caveat is actually worried
about.

**Second update, same day: `Lucide Proxy` closes half of what `ctx` left
open.** Chosen specifically for a DoS shape unlike `colors`'s — an
asynchronous, unbounded polling loop rather than a synchronous blocking
one — recovered as real, byte-verified code from the attack campaign's own
external infrastructure (see `malicious/lucide-proxy/`).
`resource_exhaustion` scored it 8.0/10 at confidence 0.95, correctly
naming the pattern ("no termination condition, no stop mechanism, and no
rate limit") on an attack it had no way to have been tuned against. **This
is real: the dimension itself is no longer validated only against
`colors`.** `_apply_dimension_floor` is a different story — 8.0 falls
short of the ≥9.0 trigger the rule requires, so it still hasn't fired
outside the two cases (`colors`, node-ipc's diluted registry pair) that
built it, across every out-of-corpus attempt made so far. **The single
highest-value next step is now narrower than it was before `Lucide Proxy`:
find a ground-truth positive where a dimension lands specifically in the
9-10/confidence ≥0.9 range without being one of the two cases the floor
rule was built from** — `resource_exhaustion` generalising is no longer
the open half of this question; the floor rule generalising still is.

## A second, distinct caveat: narrative leakage, surfaced by an inconclusive attempt

Three candidates were investigated to close the gap the previous section
leaves open: `coa`/`rc` (npm, 2021), a Phantom Bot DDoS-botnet campaign
(npm, 2026), and `torchtriton` (PyPI, 2022). All three failed for
different, real reasons — see `dataset/malicious/coa-rc/SOURCING.md` for
the full investigation. `coa`/`rc`'s malicious versions were live on npm
for only ~72 minutes, too narrow a window for any archive to have caught
the real payload, and no vendor writeup ever quoted it verbatim. The
Phantom Bot campaign has the same recoverability problem and is explicitly
characterised by its own investigators as a "Shai-Hulud clone" — not a
line worth approaching from another angle. `torchtriton`'s payload is a
compiled native binary, structurally invisible to a source-diffing tool
regardless of sourcing.

Rather than fabricate plausible malicious code for `coa`/`rc` and present
it as a reconstruction — which would break the "never invent, always
verify" norm every other incident in this corpus holds to — the attempt
used explicitly-labeled *placeholder* files instead: real, verified facts
(the exact `preinstall` hook, exact filenames, exact IOCs, the malware
family) stated as header-comment prose, with no fabricated payload logic.
The prediction going in was that this would score artificially low, since
there'd be no real malicious code for the LLM to read. **That prediction
was wrong — both pairs scored HIGH (56.0, 60.0) — and the reason why is a
more useful finding than either "high" or "low" would have been alone.**

The LLM's own reasoning text says explicitly, dimension by dimension, that
it is scoring *the placeholder comments' description of the attack*, not
any code ("the placeholder comments describe...", "explicitly state...").
**A diff whose only evidence of maliciousness is descriptive prose — even
prose that plainly labels itself a placeholder — is sufficient to drive a
HIGH severity score, with no real payload present at all.** This is a
different validity concern than the tuning caveat above: that one is about
two *scoring rules* being validated only against the corpus that produced
them; this one is about whether the *evaluation method itself* — diffing
code and asking an LLM to score it — can be quietly driven by narrative
content sitting inside the diff rather than by the code being analysed.

**A follow-up (also 2026-08-11) turned that suspicion into a controlled,
quantified measurement.** Same two directories, but `compile.js`/
`compile.bat`/`sdd.dll` were replaced with genuinely empty (0-byte) stub
files — no comments, no description of any kind — isolating narration as
the only variable. Both pairs dropped from HIGH to MEDIUM: `coa` 56.0 →
36.0 (−20.0), `rc` 60.0 → 31.5 (−28.5). That's the narration's
directly-measured contribution — large enough to flip the severity bucket
both times. It isn't the whole signal, though: the silent-stub condition
still scored `install_hooks=8.0` at confidence 0.7 (down from 10.0/0.9),
and the model's own reasoning explains why without any narration to draw
on — a new preinstall hook pointing at unexplained, empty files, on a
package with no apparent reason to need either, is itself a real,
lower-confidence structural signal, correctly distinguished from the
narrated condition's much higher confidence. Full comparison table and
reasoning excerpts in `dataset/malicious/coa-rc/FINDINGS.md`.

Even this controlled comparison has a limit worth stating outright: every
canonical incident in this corpus is a famous, publicly-documented attack,
and the silent-stub condition removes the *comments* but not the model's
general background knowledge that `coa`/`rc` was compromised in 2021 — so
this still doesn't cleanly prove the effect is "reading our prose" rather
than "recognising a known incident regardless of what's on screen," only
that *something* beyond the visible, empty files is doing real, measurable
work. One reassuring detail either way: the model didn't treat every
dimension identically in either condition — it reserved its highest
confidence for the one fact it could verify directly from diff structure
(`install_hooks`) and kept every inferred dimension at lower confidence, a
real discrimination between "I can see this" and "I'm told this" (or "I
recall this"), even though all of it pushed in the same direction.

**None of this is part of this corpus's statistics.** All four reports
(`inconclusive-report-coa-2.0.2-to-2.0.3-PARTIAL.json`,
`inconclusive-report-rc-1.2.8-to-1.2.9-PARTIAL.json`, and their
`-SILENT-STUB` counterparts) are filenamed to be excluded from every
`report-*.json` glob used throughout this document and are not counted in
the corpus overview table or confusion matrix below. One thing this does
confirm, consistent with `ctx`: `install_hooks=10.0` at confidence 0.9
(narrated condition only — the silent-stub condition doesn't even reach
the trigger) meets `_apply_dimension_floor`'s trigger condition, and the
floor rule still never fires, because the base score already clears 30
without it. Across all six out-of-corpus runs attempted so far (`ctx`'s
two pairs; `coa`/`rc`'s narrated and silent conditions, two packages
each), `_apply_dimension_floor` has fired exactly zero times outside the
two cases it was built from.

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
| **node-ipc** | **10.1.0→11.0.0** *(rerun post-fix)* | **malicious** (real compromised dependency, registry-fetched) | **30.0** | **MEDIUM** |
| **node-ipc** | **10.1.0→10.1.1** *(reconstructed, rerun post-fix)* | **malicious** (the actual wiper) | **62.5** | **HIGH** |
| **colors** | **1.4.0→1.4.44-liberty-2** *(reconstructed, post-fix)* | **malicious** (the actual sabotage) | **35.0** | **MEDIUM** |
| **flatmap-stream** | **0.1.0→0.1.1** *(reconstructed, rerun post-fix)* | **malicious** (the actual bootstrap payload) | **60.0** | **HIGH** |
| **ua-parser-js** | **0.7.28→0.7.29** *(reconstructed, post-fix)* | **malicious** (the actual miner/credential-stealer attack) | **67.0** | **HIGH** |
| **ctx** | **0.1.2→0.1.2-1** *(reconstructed, rerun post-fix)* | **malicious** (first malicious release, plain-text exfil) | **42.5** | **MEDIUM** |
| **ctx** | **0.1.2→0.2.5** *(reconstructed, rerun post-fix)* | **malicious** (final malicious release, base64 full-env exfil) | **56.5** | **HIGH** |
| **Lucide Proxy** | **ilovefemboys 1.1.3→2.0.0, cdn.js only** *(reconstructed)* | **malicious** (real DDoS-beacon fragment, browser-recruitment campaign) | **55.0** | **HIGH** |
| **Lucide Proxy** | **ilovefemboys 1.1.3→2.0.0, cdn.js+sw.js** *(reconstructed)* | **malicious** (same campaign, + real ad-hijack service worker) | **55.0** | **HIGH** |

## Precision / recall (Figure 1)

Confusion matrix at the default classification rule — **flagged = severity
≠ LOW**:

| | Predicted malicious | Predicted benign |
|---|---|---|
| **Actually malicious** | TP = 9 (all nine malicious-labelled pairs) | FN = 0 |
| **Actually benign** | FP = 0 | TN = 9 |

- **Precision:** 9/9 = **100%**
- **Recall:** 9/9 = **100%**
- **Specificity / true-negative rate:** 9/9 = **100%**
- **False-positive rate:** 0/9 = **0%**

Read this table next to "The overfitting caveat" above, not instead of it.
Read plainly and *with* that caveat: chainwatch never bucketed a benign
diff above LOW, and — as of the fixes landed this session — it now
correctly flags every real attack in this corpus, at three different
severities that roughly track real severity:

- **Six HIGHs, carried by four different mechanisms.** node-ipc's
  reconstructed wiper (62.5) is carried entirely by the LLM layer —
  `network_calls`/`obfuscation` both hit the corpus max, no feed rule
  needed. flatmap-stream's reconstructed bootstrap payload (60.0) leans
  partly on a feed rule: its LLM base score alone (38.5) only reaches
  MEDIUM, and it's OSV's `malicious_floor` firing on `MAL-2025-20690` — the
  only *slow* time that happens anywhere in this corpus — that pushes it
  into HIGH. ua-parser-js's reconstructed miner attack (67.0) is the
  highest score in the corpus, needing one code fix (`SOURCE_EXTENSIONS`)
  to even reach its payload files and benefiting, perhaps coincidentally,
  from `resource_exhaustion` reading its cryptominer as resource abuse.
  `ctx`'s complete-attack pair (56.5) is carried entirely by the original
  five dimensions, no feed contribution at all, and only reaches HIGH
  after this session's `requirements.txt`/`maintainer_changed`
  diff-engine fixes gave `dependency_changes`/`env_conditional` the
  structured signal they'd been missing (see `malicious/ctx/FINDINGS.md`).
  Lucide Proxy's two pairs (55.0 each) are the newest arrivals and a
  fourth distinct mechanism again: `resource_exhaustion` genuinely fires
  (8.0/6.0, real signal on a real DoS shape unlike `colors`'s) but falls
  short of the floor rule's threshold, and OSV's `malicious_floor` firing
  *fast* this time — days, not years — is what actually determines the
  final bucket (see `malicious/lucide-proxy/FINDINGS.md`).
- **Two MEDIUMs, both reached via the new floor rule, for different
  underlying reasons.** `colors` (35.0) is the case the floor rule was
  built for: a single dimension (`resource_exhaustion=10.0`) carries the
  entire signal because this really is a single-vector attack — every
  other dimension is a correct, legitimate 0.0. node-ipc's diluted registry
  pair (30.0) hits the same floor rule via a *different* dimension
  (`dependency_changes=9.0`) that was already scoring near-maximally before
  either 2026-08-10 fix existed — the floor rule just started acting on a
  signal that was always there.
- **One more MEDIUM, `ctx`'s simpler pair, reached without either new
  mechanism.** 42.5 is raw `llm_base_score` — no floor rule, no feed
  modifier, nothing but the original five dimensions responding to a real
  attack shaped like nothing else in this corpus (import-time credential
  exfiltration, no install hook, no DoS component). Its more complete
  sibling pair reaches HIGH instead (above) — the correct relative
  ordering, and the most direct evidence in this corpus that detection
  doesn't depend on the newest scoring machinery to work at all.
- **Zero misses, for the first time in this corpus's history** — but see
  the overfitting caveat above before treating that as fully validated.
  `resource_exhaustion` now has real, independent, out-of-corpus support
  (`Lucide Proxy`); `_apply_dimension_floor` still doesn't — every one of
  its firings across this whole corpus remains the two cases it was built
  from.

### What separates the floor-triggered MEDIUMs from the other HIGHs, dimension by dimension

All six values below are from the current, post-fix canonical reports —
i.e. what `chainwatch diff`/the reconstruction scripts actually produce
today, not historical snapshots:

| dimension | node-ipc `11.0.0` (MEDIUM, floor-triggered) | node-ipc `10.1.1` (HIGH) | flatmap-stream `0.1.1` (HIGH) | ua-parser-js `0.7.29` (HIGH) | colors (MEDIUM, floor-triggered) |
|---|---|---|---|---|---|
| network_calls | 1.0 | **10.0** (corpus max) | 2.0 | **10.0** (corpus max) | 0.0 |
| obfuscation | 2.0 | **10.0** (corpus max) | **10.0** (corpus max) | 2.0 | 0.0 |
| install_hooks | 0.0 | 2.0 | 0.0 | **10.0** (corpus max) | 0.0 |
| env_conditional | 3.0 | 7.0 | **9.0** | 8.0 | 0.0 |
| dependency_changes | **9.0** | 1.0 | 1.0 | 1.0 | 0.0 |
| resource_exhaustion | 0.0 | 4.0 | 0.0 | **10.0** (corpus max) | **10.0** (corpus max) |
| **llm_base_score** | 19.5 | **62.5** | **38.5** | **72.0** | **20.0** |
| **risk_score (feed-adjusted)** | **30.0** | 62.5 | 60.0 | 67.0 | **35.0** |

Read the two floor-triggered rows carefully: node-ipc `11.0.0`'s
`llm_base_score` (19.5) is *lower* than its final `risk_score` (30.0) by
exactly the `definitive_dimension_floor` delta (+10.5); colors's
`llm_base_score` (20.0) reaches 30.0 the same way (+10.0) before the
Scorecard modifier adds another +5.0 on top. In both cases, one dimension
at ≥9.0/confidence ≥0.9 is doing essentially all the work — the other four
or five dimensions are legitimately quiet.

`ctx`'s two pairs sit apart from both groups above — one MEDIUM, one HIGH,
neither via the floor rule:

| dimension | ctx `0.1.2-1` (MEDIUM) | ctx `0.2.5` (HIGH) |
|---|---|---|
| network_calls | **10.0** (corpus max) | **10.0** (corpus max) |
| obfuscation | 1.0 | 8.0 |
| install_hooks | 0.0 | 0.0 |
| env_conditional | 9.0 | 9.0 |
| dependency_changes | 7.0 | 7.0 |
| resource_exhaustion | 0.0 | 0.0 |
| **llm_base_score** | **42.5** | **56.5** |
| **risk_score (feed-adjusted)** | **42.5** | **56.5** |

No row in this table required a *new* dimension or aggregator rule to
reach — `network_calls` maxes out the same way node-ipc's/ua-parser-js's
HIGH pairs do, `env_conditional` reaches the floor rule's ≥9.0 trigger on
both pairs but never needs to fire it, because the base score already
clears 30 (`0.1.2-1`) or 55 (`0.2.5`) without it. `resource_exhaustion`
correctly contributes nothing to either score — this attack has no DoS
component, and the model doesn't manufacture one. Two rows *did* require a
diff-engine fix this incident's own reconstruction motivated:
`dependency_changes` (6.0→7.0 on both pairs, confidence 0.9→1.0) once
`requirements.txt` was parsed for the real new `flask` dependency, and
`env_conditional` (8.0→9.0 on the `0.2.5` pair only) after PyPI
`maintainer_changed` detection started catching the real `__author__`
change — see `malicious/ctx/FINDINGS.md` "The fix, applied to the incident
that motivated it" for the full before/after. `risk_score ==
llm_base_score` exactly for both, unaffected by the fix — the only pairs in
the whole corpus with zero feed-modifier contribution of any kind (see
`malicious/ctx/FINDINGS.md` observation 5).

`Lucide Proxy`'s two pairs are the opposite case from `ctx`'s: real,
independent `resource_exhaustion` signal, but a composite score that ends
up entirely feed-determined anyway:

| dimension | Lucide Proxy, cdn.js only (HIGH) | Lucide Proxy, cdn.js+sw.js (HIGH) |
|---|---|---|
| network_calls | 8.5 | 8.0 |
| obfuscation | 3.0 | 2.0 |
| install_hooks | 2.0 | 1.0 |
| env_conditional | 1.0 | 1.0 |
| dependency_changes | 1.0 | 2.0 |
| resource_exhaustion | **8.0** | **6.0** |
| **llm_base_score** | 44.5 | 37.0 |
| **risk_score (feed-adjusted)** | **55.0** | **55.0** |

Both pairs land on the exact same final number (55.0) despite different
`llm_base_score`s, because OSV's `malicious_floor` rule floors to a flat
55 whenever it fires — `+10.5` and `+18.0` are different-sized corrections
converging on the same floor by construction, not agreement between the
two pairs. `resource_exhaustion`'s 8.0 (cdn.js alone) is this corpus's
first real evidence the dimension recognises a DoS shape it wasn't built
from — an unbounded *asynchronous* polling loop, not `colors`'s
synchronous blocking one — but it falls short of `_apply_dimension_floor`'s
≥9.0 trigger, so the floor rule plays no role in either pair; OSV's feed
rule alone determines the bucket here. See `malicious/lucide-proxy/
FINDINGS.md` observation 2 for why `resource_exhaustion` scored *lower*
(6.0, not 8.0) with a second real file present — a genuinely open
calibration question this corpus can name but not yet explain.

An earlier draft of this write-up, working from only node-ipc's two
positives, proposed **"any single dimension ≥ 7"** as a candidate
classification rule. It held for both node-ipc pairs, held for
flatmap-stream and ua-parser-js, and — before 2026-08-10 — was cleanly
refuted by colors (highest dimension score: 1.0). That refutation no
longer holds the same way: colors's highest dimension is now 10.0. This is
worth being honest about in both directions — the rule wasn't validated by
n=2, and its refutation wasn't validated by n=1 either. What actually
changed colors's classification wasn't a per-dimension threshold rule
discovered from data; it was two purpose-built code changes. The
`_apply_dimension_floor` rule *is*, functionally, a version of "any single
dimension ≥ 9 (at high confidence)" — but note it's a stricter bar (9, not
7) and floors to MEDIUM, not HIGH, which is why it doesn't unify cleanly
with the discarded ≥7 heuristic. See recommendation #7 for why this still
isn't a validated general rule.

## RQ1 — which detection layer catches each known attack

All six incidents in this corpus have had their real attack payload
tested for real against the LLM layer — node-ipc and colors via git-commit
reconstruction, event-stream/flatmap-stream via CDN archaeology,
ua-parser-js via a real base tarball with the recovered `preinstall`
scripts spliced on, ctx via independently cross-corroborated archives with
no live tarball on either side, Lucide Proxy via real payload fragments
recovered from the campaign's own external infrastructure — and, as of
2026-08-11, all nine resulting pairs are correctly flagged. Results,
live-queried/run for this write-up (post-fix numbers throughout):

| Incident | LLM layer | OSV feed (queried against the real malicious version) | Ever `MAL-*`? |
|---|---|---|---|
| node-ipc (reconstructed, `10.1.1`) | **Tested for real:** `network_calls=10.0`, `obfuscation=10.0`, free-text: *"confirmed, unambiguous malicious payload"*, base score 62.5, **HIGH** — carried entirely by the LLM layer | `GHSA-97m3-w2cp-4xx6` | No, never |
| flatmap-stream (reconstructed, `0.1.1`) | **Tested for real:** `obfuscation=10.0`, `env_conditional=9.0`, free-text: *"a definitive, confirmed malicious supply chain attack"*, base score 38.5 (MEDIUM on its own), feed-adjusted **60.0, HIGH** | `GHSA-mh6f-8j2x-4483`, `GHSA-9x64-5r7x-2q53`, **`MAL-2025-20690`** | **Yes — years late (see below)** |
| ua-parser-js (reconstructed, `0.7.29`) | **Tested for real:** `network_calls=10.0`, `install_hooks=10.0`, `resource_exhaustion=10.0`, free-text names the incident by CVE, base score 72.0, feed-adjusted **67.0, HIGH** — the corpus's highest score, needed a diff-engine fix to reach its payload files at all | `GHSA-pjwm-rvh2-c87w` | No, never |
| colors (reconstructed, `1.4.44-liberty-2`) | **Tested for real:** `resource_exhaustion=10.0` at confidence 1.0, every other dimension a correct 0.0, base score 20.0, feed-and-floor-adjusted **35.0, MEDIUM** — needed a new dimension *and* a floor rule to reach even this | `GHSA-5rqg-jm4f-cqx7`, `GHSA-gh88-3pxp-6fm8` | No, never |
| node-ipc (registry-fetched, `11.0.0`) | **Tested for real:** `dependency_changes=9.0` at confidence 1.0, free-text names the incident, base score 19.5, floor-adjusted **30.0, MEDIUM** | `GHSA-3mpp-xfvh-qh37` | No, never |
| ctx (reconstructed, `0.1.2-1`) | **Tested for real:** `network_calls=10.0`, `env_conditional=9.0`, free-text names the incident, base score **42.5, MEDIUM** — no floor rule, no feed modifier, original five dimensions plus one same-day diff-engine fix | `GHSA-4g82-3jcr-q52w`, `GHSA-67r3-h899-9w95`, `PYSEC-2022-199` | No, never |
| ctx (reconstructed, `0.2.5`) | **Tested for real:** `network_calls=10.0`, `obfuscation=8.0`, free-text names the incident, base score **56.5, HIGH** — needed a diff-engine fix (`requirements.txt`/`maintainer_changed` parsing) to cross from MEDIUM, zero feed contribution either way | `GHSA-67r3-h899-9w95`, `PYSEC-2022-199` | No, never |
| Lucide Proxy (reconstructed, cdn.js only) | **Tested for real:** `resource_exhaustion=8.0` at confidence 0.95 on a real, structurally different DoS shape, base score 44.5, feed-floored **55.0, HIGH** | `MAL-2026-10305` | **Yes — days, not years (see below)** |
| Lucide Proxy (reconstructed, cdn.js+sw.js) | **Tested for real:** `resource_exhaustion=6.0` at confidence 0.9 (lower with more real code present — see `malicious/lucide-proxy/FINDINGS.md`), base score 37.0, feed-floored **55.0, HIGH** | `MAL-2026-10305` | **Yes — same fast hit** |

**The finding that generalises across all nine pairs:** in every single
case, the LLM layer's free-text summary correctly named the real incident
— that was true before any 2026-08-10 fix and remains true after, and
holds for `ctx` too, an incident the model's training and the fixes it
motivated had no way to have been shaped by in tandem. (`Lucide Proxy` is
the one exception worth naming explicitly: the free text described the
attack accurately without ever naming the campaign — plausibly because
it's a far less famous incident than the rest of this corpus, with much
less training-data exposure to draw on; see `malicious/lucide-proxy/
FINDINGS.md` for the direct quote and a pointer to how this connects to
the `coa`/`rc` narrative-leakage finding.) What changed across the corpus
is whether that recognition propagated into a flagged *severity bucket*,
and the mechanism differed by case: node-ipc's reconstructed wiper needed
nothing but complete input (LLM-carried). flatmap-stream needed a rare,
years-late feed reclassification (feed-carried, slow). ua-parser-js needed
a diff-engine fix to see its own payload files (fetching/visibility-carried).
colors and node-ipc's diluted pair needed new aggregation logic that
didn't exist until this session (aggregator-carried). `ctx` needed neither
a new dimension nor a new aggregator rule — its `0.1.2-1` pair reached
MEDIUM on the original five dimensions alone — but its `0.2.5` pair still
needed a diff-engine metadata fix (`requirements.txt`/`maintainer_changed`
parsing, motivated by this exact incident) to cross from MEDIUM into HIGH,
putting it closer to `ua-parser-js`'s "fetching/visibility-carried"
category than to a clean zero-fix result. `Lucide Proxy` is a sixth,
distinct case: real, independent LLM-layer signal on `resource_exhaustion`
(unlike anything tried before, a positive result for that dimension
specifically) that nonetheless doesn't determine the final bucket — a
*fast* feed reclassification does that instead (feed-carried, fast, the
mirror image of `flatmap-stream`'s slow case). Six different mechanisms
produced nine correct outcomes — which is a real result, but also means
"chainwatch catches attacks" is really six much narrower, mechanism-specific
claims stacked together,
exactly as many previous drafts of this document argued before any of
them were true simultaneously.

**On `MAL-*` classification specifically:** chainwatch's aggregator floors
the score to the HIGH range when a feed reports `malicious` — which
chainwatch maps from an OSV `MAL-*` prefix specifically (`analyzer/
feeds.py`). Of six confirmed, publicly-documented supply-chain attacks,
**two have ever received a `MAL-*` classification, on opposite ends of the
speed spectrum.** `flatmap-stream`'s took nearly seven years after
disclosure (2018-11-20 → 2025-08-14, live-verified against OSV's own
`published` field for this write-up — an earlier draft of this document
mis-stated this gap as "three and a half years"; corrected here).
`Lucide Proxy`'s took **2 days 17 hours** (2026-07-10 → 2026-07-13,
credited to `amazon-inspector` automated scanning and `ghsa-malware`,
rather than a purely manual advisory process) — see `malicious/lucide-proxy/
SOURCING.md` for the full timeline and why this incident's "malicious
version published" timestamp is itself a looser concept than usual (the
payload was loaded from a mutable, non-integrity-checked remote reference,
not baked into the npm tarball). Even a chainwatch instance polling OSV in
real time today would still get `suspicious`, not `malicious`, for four
of these six incidents — the feed-floor rule's practical hit rate on this
corpus's ground truth is 2-in-6, one fast and one slow, not enough to
characterise a trend either way. node-ipc's reconstructed-wiper HIGH
result was reached *without* the feed-floor rule ever firing — the LLM
layer alone carried it. flatmap-stream's and `Lucide Proxy`'s HIGH results
are the opposite case: the two pairs in this corpus where the feed-floor
rule's hit actually determines the bucket — for flatmap-stream, run this
same query before 2025-08-14 and the composite would have landed at 43.5
(MEDIUM, not HIGH, under the current post-fix weight matrix — worse than
the 56.5-still-HIGH hypothetical an earlier draft of this document
reported, because the weight cuts that made room for `resource_exhaustion`
reduce `obfuscation`/`network_calls`'s ceiling too); for `Lucide Proxy`,
the feed rule was live from the start, so there's no meaningful
"pre-advisory" hypothetical to construct. colors, node-ipc's diluted pair,
and both `ctx` pairs never touch `MAL-*` at all — four of those six are
entirely a diff-engine-and-aggregator or pure-LLM story, with the feed
layer contributing nothing either way.

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
| ctx | 2022-05-14 19:18:36 UTC | 2022-05-24 17:55:00 UTC | **9d 23h** | PYSEC-2022-199 |
| Lucide Proxy | 2026-07-10 13:02:23 UTC *(npm publish — see caveat below)* | 2026-07-13 06:27:39 UTC | **2d 17h** | MAL-2026-10305 |

Gaps range from under nine hours to eleven weeks, with no obvious trend by
year (2022's colors incident closed in 2.5 days; 2021's ua-parser-js closed
in under nine hours; 2018's event-stream took eleven weeks; 2022's ctx —
despite a public researcher claiming responsibility within a day of
discovery — still took ten days to reach a formal advisory; 2026's Lucide
Proxy closed in under three days, the second-fastest in this corpus).
**Lucide Proxy's row needs a caveat the others don't**: its malicious
capability was loaded at runtime from a mutable, non-integrity-checked
remote reference (see `malicious/lucide-proxy/SOURCING.md`), not baked
into the npm tarball at publish time — so "malicious version published"
isn't quite the same well-defined event it is for every other row here.
The 2d 17h figure uses the npm publish timestamp for consistency with the
rest of this table, but the actual malicious capability may have gone
live earlier or later than that timestamp; the closest thing to a firm
"confirmed live" date is a 2026-05-18 Wayback capture of the payload, over
seven weeks before either the npm publish timestamp used here or the
advisory. **A diff-level
LLM scanner's structural advantage is that it doesn't wait for any of this —
it can score a release the moment it's published**, at the cost of the
mechanism-specific severity-bucketing gaps documented above (all now
closed for this corpus, per the overfitting caveat). The upper bound on
what chainwatch could contribute on an incident shaped like ua-parser-js's
is closing an 8-hour gap to single-digit minutes; on event-stream's,
closing an 11-week gap to the same.

## RQ3 — false positive rate

9/9 benign-labelled pairs in this corpus (4 in `dataset/benign/`, 5 adjacent
pairs across the three unpublished-attack incidents) scored LOW. **0%
false-positive rate at the severity level**, across pairs specifically
selected to be "suspicious-looking but legitimate" — a new install hook
(husky), a real CVE fix (lodash), platform-conditional native-binary logic
(esbuild), a 5,900-line refactor (requests). Full per-pair reasoning in
`benign/FINDINGS.md`.

**This held after the 2026-08-10 fixes, and was checked explicitly, not
assumed.** Two things could plausibly have broken it: `resource_exhaustion`
scoring real, legitimate loops as dangerous, or `_apply_dimension_floor`
firing on a benign report's dimension. Neither happened. On the former:
lodash's real `4.17.20→4.17.21` diff contains a genuinely bounded
`while (index-- && ...)` loop; rerun live for this write-up, it scores
`resource_exhaustion=1.0`, with the model's reasoning explicitly
distinguishing "bounded by string length, exits naturally" from an
unbounded pattern. On the latter: every report already committed to this
corpus before 2026-08-10 was checked for the `_apply_dimension_floor`
trigger condition (any dimension ≥9.0 at confidence ≥0.9) — it fired on
exactly the three malicious-labelled reports already HIGH (no-op) plus
`colors` and node-ipc's diluted pair (the intended and bonus
reclassifications), and zero benign-labelled reports. `ctx`, added after
this check was performed, doesn't change the count — its `0.1.2-1` pair
technically meets the trigger's score/confidence threshold
(`env_conditional=9.0`, confidence 1.0), but `_apply_dimension_floor`'s own
short-circuit (`base_score >= 30` returns unmodified, regardless of
`triggering`) makes it a no-op, since that pair's base score is already
42.5. See "The overfitting caveat" above for why this check, while real,
doesn't extend to attack shapes not already present in this corpus.

## RQ4 — comparison with a signature-based classifier

OSV is the natural signature-based baseline here: it's a curated advisory
database, the same category of tool as the classifiers this question asks
chainwatch to be compared against, and it's already wired into every
report. Scored against this corpus's six incidents:

- **Eventual coverage: 6/6 (100%).** Every incident got at least one
  advisory, eventually.
- **Confirmed-malware (`MAL-*`) coverage: 2/6 (33%), one slow and one
  fast.** `flatmap-stream` was reclassified from a generic GHSA advisory to
  a `MAL-*` entry nearly seven years after disclosure (see RQ1). `Lucide
  Proxy` got a `MAL-*` entry (`MAL-2026-10305`) within days — the first
  time this corpus has seen the fast path. `ctx` got three separate
  advisories (`GHSA-4g82-3jcr-q52w`, `GHSA-67r3-h899-9w95`,
  `PYSEC-2022-199`) and none of them ever `MAL-*`.
- **Speed: highly variable, 8 hours to 11 weeks, plus one outlier at under
  3 days** (see RQ2), with no advisory ever available at the moment of
  attack publication. `ctx` sits in the middle of the original range
  (9d 23h); `Lucide Proxy` (2d 17h) is the second-fastest in the whole
  corpus, behind only `ua-parser-js`'s 8h 23m.

The comparison isn't "OSV vs. chainwatch" — chainwatch *uses* OSV as one of
three feed inputs. The more useful framing, updated for the 2026-08-10
fixes: **a pure signature database has no equivalent to any of the three
mechanism-specific gaps this corpus surfaced, and therefore no equivalent
fix — but it also has no equivalent capability.** OSV doesn't care what
file extension a payload shipped in (so ua-parser-js's diff-engine gap
never affected it), doesn't need a "sixth dimension" concept to record that
an attack is DoS-shaped (so colors's taxonomy gap never affected it either)
— it just needed *any* human to write an advisory, which for `colors`
happened in 2.5 days (`GHSA-5rqg-jm4f-cqx7`) and for node-ipc's diluted
pair in 9 days (`GHSA-3mpp-xfvh-qh37`). Neither advisory has ever been
`MAL-*`, so neither would trigger a hypothetical "block on signature match"
gate at the confidence tier chainwatch's own `malicious_floor` rule
requires — the signature approach's structural advantage (no taxonomy to
be incomplete) is real, but its own confidence-tier problem (RQ1's 2-in-6
`MAL-*` hit rate) means it wouldn't have closed these particular gaps
either, just failed to have them in the first place. `ctx` sharpens this
point rather than complicating it: it needed no chainwatch code fix of any
kind for its `0.1.2-1` pair (see "Why this incident matters more than its
score" in `malicious/ctx/FINDINGS.md`), so for that one pair OSV's "just
needed a human to write an advisory" path and chainwatch's "just needed
the original five dimensions" path both worked without new engineering —
they simply worked on different timescales (chainwatch: the moment of
diffing; OSV: 9d 23h later). `Lucide Proxy` complicates this framing in a
useful way: here it's OSV's *fast* automated path — not a human writing an
advisory at all, but `amazon-inspector`'s scanning — that ends up
determining chainwatch's own final bucket, since `resource_exhaustion`'s
real 8.0 signal falls short of the floor rule's threshold on its own. The
signature-based layer and the LLM layer aren't cleanly separable
alternatives here; on this one incident, chainwatch's correct answer
*is* the signature-based layer's answer, arriving through chainwatch's own
`malicious_floor` feed integration. Both approaches now agree on all nine
malicious examples in this corpus (chainwatch: severity ≠ LOW; OSV: at
least one advisory) — but five of chainwatch's nine correct results
required new code paths built this session (four via the 2026-08-10 fixes,
one via the 2026-08-11 diff-engine fix that got `ctx`'s `0.2.5` pair to
HIGH), and OSV's agreement required nothing chainwatch controls at all —
sometimes years of nothing, sometimes days.

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

1. **✅ Implemented (2026-08-10), in two parts.** A sixth risk dimension,
   `resource_exhaustion` (`models.py`), was necessary but not sufficient —
   see "How the corpus got here" above. A `definitive_dimension_floor`
   aggregator rule (`analyzer/aggregator.py`: any dimension ≥9.0 at
   confidence ≥0.9 floors the composite to MEDIUM) closed the remaining
   gap. Together they flip `colors` from LOW (7.5) to MEDIUM (35.0) and, as
   a verified side effect, node-ipc's diluted registry pair from LOW (29.5)
   to MEDIUM (30.0). Checked against the full corpus before shipping: fires
   on zero benign-labelled reports. See "The overfitting caveat" above for
   why this is necessary-but-not-sufficient validation, and
   `malicious/colors/FINDINGS.md` for the full before/after.
2. **✅ Implemented (2026-08-10).** `SOURCE_EXTENSIONS`
   (`src/chainwatch/diff/engine.py`) now includes `.sh`, `.bat`, `.ps1`,
   and `.cmd` alongside the original JS/TS/Python types. Diagnosed via a
   controlled experiment (57.5 vs. 42.5 with the allowlist patched in
   isolation), confirmed via an independent, non-monkey-patched rerun after
   the real fix landed. A regression test
   (`tests/unit/test_diff_engine.py::test_install_scripts_are_enumerated`)
   guards it. See `malicious/ua-parser-js/FINDINGS.md` for the full
   before/after (three runs: 42.5 → 60.0 → 67.0, the last step from
   recommendation #1's fix).
3. **✅ Effectively resolved (2026-08-10), though not via the mechanism
   originally proposed.** This recommendation floated revisiting
   `dependency_changes`'s weight, or a "known-compromised transitive
   dependency" special case, for node-ipc's diluted pair specifically. What
   shipped instead was recommendation #1's floor rule, built for a
   different incident — `dependency_changes`'s weight was cut further
   (15%→10%), which alone would have made this pair's problem *worse*, but
   the floor rule reclassifies it correctly anyway (LOW→MEDIUM). Worth
   flagging as a data point on convergent fixes: a general mechanism aimed
   at one problem solved an unrelated one for free, and a narrower fix
   aimed directly at this problem was never built. See
   `malicious/node-ipc/FINDINGS.md`.
4. **CI users relying on `--threshold` should not assume the MEDIUM
   boundary (30) is a safe default.** As of 2026-08-11, the default
   threshold now catches all nine malicious examples in this corpus
   without any custom `--threshold` value — a meaningful change from
   before this session, when node-ipc's diluted pair (29.5) and colors's
   reconstructed attack (7.5) both required either a lower threshold or
   were uncatchable by threshold-tuning alone. `ctx`'s two pairs (42.5,
   56.5) and `Lucide Proxy`'s two pairs (55.0 each) clear the boundary
   comfortably, adding four more data points that didn't need the
   boundary itself to move. Whether this generalises past this corpus's
   nine examples is exactly the open question in "The overfitting caveat"
   above.
5. **The feed-floor rule's dependence on OSV's `MAL-*` prefix specifically
   (not `GHSA-*`) means it fires unpredictably** — sometimes not at all
   for years, occasionally within days, per RQ1/RQ4. A tool relying on
   chainwatch's `malicious_floor` modifier as its primary safety net would
   have missed 4 of 6 incidents in this corpus even with live feeds, for
   years in some cases, and does nothing at all for ua-parser-js,
   colors/node-ipc's diluted pair, or either `ctx` pair (never `MAL-*`,
   ever). But it's not purely slow either: `Lucide Proxy`'s `MAL-2026-10305`
   landed in under three days, credited to automated scanning
   (`amazon-inspector`) rather than a human-written advisory — and for that
   incident specifically, `malicious_floor` *is* the deciding factor (see
   recommendation #7 below), not merely additive. Two of this corpus's nine
   correct classifications as of 2026-08-11 depend on `malicious_floor` as
   the deciding factor (`flatmap-stream`, `Lucide Proxy`) — the rest are
   carried by the LLM layer and/or the new aggregator rules regardless of
   what OSV reports.
6. **Reconstruction-and-run is done for all six incidents in this
   corpus, via five different sourcing methods, and every resulting pair
   has now been rerun against the fully-fixed code for consistency.**
   node-ipc and colors were legitimate-maintainer self-sabotage with the
   payload surviving in git. event-stream/flatmap-stream was an account
   hijack with no git history and no live base tarball, but the payload
   survived in a CDN's edge cache. ua-parser-js was also an account
   hijack, but its pre-incident version is still published. ctx was also
   an account hijack, with neither side live but both independently
   recoverable from separate archives (Software Heritage for the benign
   base, the Wayback Machine for the real uploaded malicious sdists).
   `Lucide Proxy` is the first incident in this corpus that isn't an
   account hijack at all — malicious from first publish, no legitimate
   predecessor to recover — with no tarball recoverable on either side,
   but real payload fragments independently recoverable from the
   campaign's own external C2 infrastructure. **This corpus's
   currently-scoped incidents are now fully exhausted** — every incident
   has had its real attack tested for real against both detection layers,
   under the current code, with current numbers. See each incident's
   `SOURCING.md`.
7. **✅ Partially executed (2026-08-11), then further advanced the same
   day.** The ground-truth corpus needed real positives from incidents
   beyond the original four, specifically ones that would exercise
   `resource_exhaustion` or `_apply_dimension_floor`. Two incidents were
   added, answering two different halves of the question:

   - **`ctx` (PyPI, 2022)** was the first positive sourced and
     reconstructed after both mechanisms already existed — but its attack
     shape (import-time credential exfiltration) doesn't touch either one.
     It confirms the *rest* of the pipeline generalises to a genuinely new
     attack shape; it says nothing about the two mechanisms this
     recommendation is actually about.
   - **`Lucide Proxy` (npm, 2026)**, chosen specifically for a DoS shape
     unlike `colors`'s (asynchronous unbounded polling vs. synchronous
     blocking loop), **closes half of what `ctx` left open.**
     `resource_exhaustion` scored it 8.0/10 at confidence 0.95, correctly
     reasoning about "no termination condition, no stop mechanism, and no
     rate limit" on an attack shape the dimension was never tuned against.
     **`resource_exhaustion` is no longer validated only against
     `colors`.** `_apply_dimension_floor` remains the open half: 8.0 falls
     short of the rule's ≥9.0 trigger, so it still hasn't fired on
     anything outside the two cases (`colors`, node-ipc's diluted registry
     pair) that built it — and `Lucide Proxy`'s final HIGH classification
     turns out to be entirely feed-determined (a fast `MAL-*` hit) rather
     than floor-rule-determined, so this incident doesn't even indirectly
     pressure-test the floor rule's necessity the way `colors` did.

   **What's still open, narrower now than before:** find a ground-truth
   positive where a dimension lands specifically in the 9-10/confidence
   ≥0.9 band without being one of `colors`/node-ipc's diluted pair — a
   single-vector attack (not necessarily DoS-shaped anymore, since that
   half is answered) that happens to land there. The five sourcing methods
   identified here ("maintainer-sabotage-with-git-history",
   "account-hijack-with-CDN-recoverable-payload-and-no-live-base",
   "account-hijack-with-a-live-pre-incident-base",
   "account-hijack-with-neither-side-live-but-both-independently-archived",
   "malicious-from-inception-with-C2-fragments-independently-archived")
   cover every incident currently in scope; closing the remainder of this
   recommendation requires a *seventh* incident chosen specifically for
   that narrower target. **A follow-up attempt (also 2026-08-11) to source
   such an incident — `coa`/`rc` (npm, 2021), picked specifically to land
   `install_hooks` near the floor rule's trigger — hit a real sourcing wall
   instead: the actual payload was never publicly recovered by anyone (see
   `dataset/malicious/coa-rc/SOURCING.md`), and two other candidates (a
   2026 DDoS-botnet campaign later ruled out on separate grounds,
   `torchtriton`) failed for their own separate reasons before `Lucide
   Proxy` was found.** A second follow-up round (2026-08-12) checked five
   more candidates specifically for the install_hooks-dominant,
   single-vector shape this recommendation still needs: PhantomRaven (126
   npm packages, remote-dependency technique — the C2 domain was never
   crawled by any archive checked), `coinbase-wallet-utils`/`ethers-jss`
   (real `MAL-*` hits, but no tarball archived on either), the `axios`
   compromise's `plain-crypto-js` dependency (only npm's post-takedown
   security placeholder was ever archived), and `@acitons/artifact`
   (ruled out outright — GitHub confirmed this was an authorized internal
   red-team exercise, not a real attack, so it doesn't belong in a
   ground-truth-malicious corpus regardless of recoverability). None
   panned out. **This recommendation is more than half-closed, but still
   open — the remaining gap (a real, recoverable, single-vector attack
   landing one dimension at 9-10/confidence ≥0.9 without being one of the
   two cases the floor rule was built from) has now survived two dedicated
   search rounds.**
8. **✅ Tested (2026-08-11). Narrative leakage: description measurably
   substitutes for code in the LLM layer's scoring.** The `coa`/`rc`
   attempt above used explicitly-labeled placeholder files (no fabricated
   attacker logic, real verified facts stated as prose) in place of the
   unrecoverable real payload, on the prediction that this would score
   low. It scored HIGH on both pairs instead. A controlled follow-up
   (same two directories, but with the placeholder comments stripped down
   to genuinely empty 0-byte stub files) isolated the effect directly:
   both pairs dropped from HIGH to MEDIUM (`coa` 56.0→36.0, `rc`
   60.0→31.5) — 20 to 28.5 points attributable to narration alone. This is
   a distinct concern from recommendation #7/the overfitting caveat above:
   it's not about a scoring *rule* being tuned on this corpus, it's about
   whether prose sitting inside a diff can drive the LLM layer's score on
   its own, independent of whatever code is actually present — and now
   there's a measured effect size, not just a suspicion. What the
   follow-up still can't isolate: whether the residual signal in the
   silent-stub condition (still MEDIUM, not LOW — `install_hooks=8.0` at
   confidence 0.7 from structural evidence alone) reflects sound reasoning
   about an unexplained install hook, the model's background knowledge of
   this specific famous incident, or some mix of both. See
   `dataset/malicious/coa-rc/FINDINGS.md` for the full breakdown.
9. **✅ Implemented (2026-08-11). `env_conditional`'s stated definition
   widened to match its already-correct observed behavior; not split into
   two dimensions.** `models.py` previously described it as "conditional
   logic gated on env vars, platform, or CI detection" (control flow that
   *branches* on environment state), but `ctx`'s attack — which reads and
   exfiltrates environment variables without branching on them at all —
   scored 8-9/10 on this dimension anyway, with the model's own reasoning
   making clear it was rewarding "touches environment variables in a
   security-relevant way" more broadly than the docstring described. The
   label (`models.py`) and system prompt (`analyzer/llm.py`) now describe
   both patterns explicitly — control-flow branching *and*
   read/exfiltration — as the same dimension, rather than leaving the
   broader half implicit. **A split into two dimensions was considered and
   rejected**: the corpus's one benign control with real, non-malicious
   env-var-reading code (`requests`, `os.environ.get('NETRC')`/
   `CURL_CA_BUNDLE`) already scored this dimension a correct, low 1.5/10
   *before* the change, meaning the model was already discriminating
   "legitimate configuration read" from "credential harvesting" correctly
   within the single dimension — splitting would add a weight-rebalancing
   exercise and a corpus-wide rerun for a distinction the model already
   makes reliably. **Checked, not assumed:** rerun both after the change —
   `requests`'s `env_conditional` score is unchanged (1.5/10, identical
   reasoning style, confirmed no false-positive regression); `ctx`'s
   `0.2.5` pair's `env_conditional` moved from 9.0 to 10.0 (`llm_base_score`
   56.5→58.0, same HIGH bucket, no reclassification) — the widened prompt
   language made an already-correct signal slightly more confident, not
   differently shaped. Given no bucket changed and no committed report's
   correctness was invalidated, the canonical `ctx` reports were **not**
   re-archived a third time for this change; the two verification reruns
   are documented here and in `malicious/ctx/FINDINGS.md` observation 2
   instead. Regression risk on the rest of the corpus is low by the same
   logic that applied to `resource_exhaustion`'s rollout (RQ3) — this
   dimension's weight and every other dimension are unchanged.
10. **✅ Implemented (2026-08-11). Two narrow diff-engine blind spots on the
   PyPI side — neither caused a misclassification originally, but fixing
   them changed a real result anyway.** (a) `requirements.txt` was parsed
   by nothing in `src/chainwatch/diff/engine.py` — not a recognised
   `SOURCE_EXTENSIONS` suffix, not a `METADATA_FILES` entry — so a real,
   verified new dependency (`Flask==2.1.0`, added in every `ctx` malicious
   release) never reached `diff_summary.new_dependencies`; the LLM caught
   it anyway by reading the literal `import` lines in `ctx.py`'s own diff.
   (b) `maintainer_changed` detection (`_extract_metadata_diff`) only
   compared npm's `package.json` `author` field — there was no equivalent
   check for Python packages, despite `ctx`'s attacker changing exactly
   that category of signal (`'Robert Ledger'` → `'Yunus AYDIN'`, in
   `ctx.py`'s `__author__` dunder — notably, *not* in `setup.py`'s own
   `author=` kwarg, which the attacker never touched; a first-draft fix
   that checked `setup.py`/`pyproject.toml` only, without also checking
   module-level dunders, would have missed this incident's real change
   entirely). Both fixed the same day: `_requirements_txt_dependencies`
   and `_pypi_author` in `src/chainwatch/diff/engine.py`, the latter
   combining three independent author sources (PEP 621 `pyproject.toml`,
   `setup.py`, module dunders) rather than short-circuiting between them,
   specifically so an unchanged `setup.py` author can't mask a real change
   living somewhere else — a regression test for exactly that scenario is
   in `tests/unit/test_diff_engine.py::TestPyPIMaintainerChanged`. Rerun
   against the exact incident that motivated both fixes:
   `dependency_changes` moved from LLM-inferred (confidence 0.9) to
   structurally-confirmed (confidence 1.0, score 6.0→7.0) on both `ctx`
   pairs, and the `0.2.5` pair's composite score crossed from **MEDIUM
   (52.0) to HIGH (56.5)** as a direct result — the only diff-engine fix
   this session that was tested against the *exact* incident that
   surfaced it, rather than a different one. Pre-fix reports preserved at
   `malicious/ctx/pre-pypi-fix-report-*.json`. See `malicious/ctx/
   FINDINGS.md` observations 3-4 and "The fix, applied to the incident
   that motivated it" for the full before/after.

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

### Weight-matrix versioning — which reports reflect which code

As of 2026-08-10, `models.DIMENSIONS` has six entries, not five (see
`src/chainwatch/models.py` for the exact weights and the rationale
comment). All nine malicious-labelled reports **are** current,
six-dimension outputs — the original five were rerun and reconfirmed
against the fixed code, and `ctx`'s and `Lucide Proxy`'s four (combined)
were run directly against it (no five-dimension version of any of them
ever existed, since both were reconstructed after that particular fix
landed). `ctx`'s two reports were separately rerun again the following day
(2026-08-11) against the two diff-engine metadata fixes described in
recommendation #10 — that before/after *does* exist, at `malicious/ctx/
pre-pypi-fix-report-*.json`, and is unrelated to the dimension-count
question this paragraph is about. The nine benign-labelled reports (listed
in "Corpus overview" above) were **not** rerun — they were never
candidates for reclassification, since neither fix could plausibly move an
already-LOW report *upward* by design. Instead, RQ3's explicit
false-positive check validates the *current* code directly (a live
`resource_exhaustion` rerun on lodash; a corpus-wide sweep for the
floor-rule trigger condition) without needing to regenerate every benign
report from scratch.

**Eight of the eighteen reports are not reproducible via a single
`chainwatch diff` invocation** — the first four below (there's no real
*malicious-version* tarball to fetch for any of them) plus `ctx`'s two
pairs and `Lucide Proxy`'s two pairs (no live tarball on *either* side for
either incident). A ninth bullet is listed alongside them — node-ipc's
registry pair — not because it's unreproducible (it's a plain, real
fetch), but because its *classification*, not its reproducibility,
depends on a same-session fix:

- `node-ipc/report-10.1.0-to-10.1.1-RECONSTRUCTED.json` — apply
  `malicious/node-ipc/evidence/commit-847047cf7f81-relevant.diff` to a real,
  still-published `node-ipc@10.1.0` tarball.
- `colors/report-1.4.0-to-1.4.44-liberty-2-RECONSTRUCTED.json` — apply
  `malicious/colors/evidence/commit-074a0f8ed0c3.diff` (or just copy in
  `evidence/american.js` and `evidence/index.js` directly, which are
  already the exact post-sabotage file contents) to a real, still-published
  `colors@1.4.0` tarball. The pre-fix (five-dimension) run is preserved at
  `pre-dos-fix-report-1.4.0-to-1.4.44-liberty-2-RECONSTRUCTED.json`.
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
  against the current codebase directly — no patching needed. Two
  companion files preserve earlier states for history, not part of any
  corpus count: `pre-fix-report-0.7.28-to-0.7.29-RECONSTRUCTED.json` (the
  pre-`SOURCE_EXTENSIONS`-fix state) and
  `experiment-full-visibility-0.7.28-to-0.7.29.json` (the diagnostic
  monkey-patch experiment that preceded that fix).
- `node-ipc/report-10.1.0-to-11.0.0.json` — **this one *is* a plain,
  real registry fetch** (`chainwatch diff npm node-ipc 10.1.0 11.0.0`), no
  reconstruction needed; listed here only because its *classification*
  depends on the 2026-08-10 aggregator fix, not because the artifact itself
  is unreproducible. The pre-fix run is preserved at
  `pre-dos-fix-report-10.1.0-to-11.0.0.json`.
- `ctx/report-0.1.2-to-0.1.2-1-RECONSTRUCTED.json` and
  `ctx/report-0.1.2-to-0.2.5-RECONSTRUCTED.json` — **no live tarball on
  either side** (the whole `ctx` PyPI project was deleted, not just the
  malicious versions). Reproduce the "from" side by fetching each file in
  `malicious/ctx/evidence/README.md`'s Software Heritage table by content
  hash; reproduce each "to" side by fetching the corresponding Wayback
  Machine URL for the full `ctx-0.1.2-1.tar.gz`/`ctx-0.2.5.tar.gz` sdist
  and extracting it as-is. Full URLs, content hashes, and the exact file
  layout both directories need are in `malicious/ctx/evidence/README.md`.
  Reproduces against the current codebase directly. Pre-fix states (before
  `requirements.txt`/`maintainer_changed` parsing landed, recommendation
  #10) are preserved at `pre-pypi-fix-report-0.1.2-to-0.1.2-1-RECONSTRUCTED.json`
  and its `0.2.5` counterpart, not part of any corpus count.
- `lucide-proxy/report-lucide-proxy-cdn-only-RECONSTRUCTED.json` and
  `lucide-proxy/report-lucide-proxy-cdn-and-sw-RECONSTRUCTED.json` — **no
  live or archived tarball on either side, for any of this campaign's 148
  packages.** Reproduce the "to" side's real payload fragments by fetching
  `https://web.archive.org/web/20260518174009/https://raw.githubusercontent.com/canyoupleasesaysomething/cdn/refs/heads/main/cdn.js`
  and (for the second pair)
  `https://web.archive.org/web/20260426172256/https://raw.githubusercontent.com/lucideproxy/svg/refs/heads/main/sw.js`.
  The "from" side and the rest of the "to" side's `package.json` are an
  explicitly-synthetic scaffold (real package name/version strings, not a
  real recovered tarball — see `malicious/lucide-proxy/evidence/README.md`
  for exactly what's real and what's scaffold, and why).

The first four are then reproducible by calling
`chainwatch.diff.engine.compute_diff()` directly on the two resulting
directories (bypassing the registry-fetch layer entirely, not mocking it);
`ctx`'s and `Lucide Proxy`'s pairs use the same `compute_diff()` call once
their directories are assembled from archives (and, for `Lucide Proxy`, a
synthetic scaffold) rather than a diff/patch step — see each incident's
`SOURCING.md` for the full method and why it was built this way. Feed
lookups (OSV/Rekor/Scorecard) still hit the real APIs in all nine cases;
only the malicious-version tarball fetch is bypassed (and, for the
node-ipc registry pair, nothing is bypassed at all).
