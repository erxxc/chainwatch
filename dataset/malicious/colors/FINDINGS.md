# colors — chainwatch findings

Two pairs, both live pipeline runs (real LLM + real feeds), `claude-sonnet-4-6`:
one registry-fetched benign control (2026-08-07), one a directory-level
reconstruction of the actual sabotage commit (2026-08-08 — see "The
reconstructed pair" below and `SOURCING.md` for exactly how, and why it
never became an installable package). See `evidence/` for the recovered
payload itself.

**Update 2026-08-10:** the reconstructed pair was rerun after two real code
changes landed in response to this exact finding — a sixth risk dimension
(`resource_exhaustion`) and a same-day follow-up aggregator rule (see "The
fix, in two parts" below). **New result: MEDIUM (35.0)**, up from LOW
(7.5). The pre-fix report is preserved at
`pre-dos-fix-report-1.4.0-to-1.4.44-liberty-2-RECONSTRUCTED.json` for
citation.

## Summary

| pair | role | risk | LLM base | feed-adjusted | OSV | Rekor | Scorecard |
|---|---|---|---|---|---|---|---|
| `1.3.3 → 1.4.0` | benign control | LOW | 0.0 | 5.0 | clean | no_data | 2.2/10 suspicious |
| `1.4.0 → 1.4.44-liberty-2` *(reconstructed, post-fix)* | **the actual sabotage commit** | **MEDIUM** | 20.0 | 35.0 | suspicious (2× GHSA) | no_data | 2.2/10 suspicious |

Tarball SHA256 (verified at fetch time — benign-control pair only; the
reconstructed pair has no real tarball, see below):

- `1.3.3`: `ba236fffba0bbee00ba9b3209236e2f0718eaa37d0e8812f6c9f8f4f9551950b`
- `1.4.0`: `b50eb83eda7cc37519809e240338fded8e625169945bbfe6d4156445c6610498`

## The reconstructed pair: found LOW with a diagnosable taxonomy gap, now MEDIUM after two fixes

### What the first run found (2026-08-08)

**This was the corpus's most important negative result.** Unlike node-ipc's
reconstruction (`malicious/node-ipc/FINDINGS.md`), where the composite score
jumped from LOW to HIGH once the *complete* attack was available, colors's
reconstruction was the complete attack from the start — real sabotage
commit, byte-verified against a base tarball that's still live on the
registry — and it **still scored LOW (7.5/100)**.

All five original LLM dimensions scored at or near zero:

| dimension | pre-fix score | reasoning (abridged) |
|---|---|---|
| network_calls | 0.0 | "No network calls... limited to console.log output" |
| obfuscation | 1.0 | "No base64 encoding, eval, or dynamic require patterns" |
| install_hooks | 0.0 | "No changes to package.json, no postinstall/preinstall" |
| env_conditional | 0.0 | "No environment variable checks... present" |
| dependency_changes | 0.0 | "No changes to package.json dependencies" |

Every single dimension was individually correct — the diff genuinely
contained none of those five patterns. **The free-text summary knew better
than the dimensions did:**

> "...the infinite loop... is a denial-of-service / resource exhaustion
> pattern that will hang any process that imports this package... This is
> consistent with the real-world incident where the colors package author
> intentionally sabotaged their own package. The change is disruptive and
> malicious in effect... even without classic supply chain exfiltration
> indicators."

The only reason the composite score was non-zero at all was the unrelated
`scorecard_poor +5` modifier (the project's long-term neglect, not the
diff). **This was a taxonomy gap, not a calibration or fetching gap.**
chainwatch's five risk dimensions — network calls, obfuscation, install
hooks, env conditionals, dependency changes — were shaped around
data-exfiltration and credential-theft attacks (exactly what event-stream,
ua-parser-js, and node-ipc's wiper are). None of them asked "does this code
terminate," "does it consume unbounded resources," or "is it a denial-of-
service payload." A protestware DoS attack was structurally invisible to
that dimension set no matter how completely the diff was presented to the
model. Full pre-fix report:
`pre-dos-fix-report-1.4.0-to-1.4.44-liberty-2-RECONSTRUCTED.json`.

### The fix, in two parts

**Part 1 — a sixth dimension.** `resource_exhaustion` was added to
`models.DIMENSIONS` (`src/chainwatch/models.py`) and to the LLM's system
prompt (`src/chainwatch/analyzer/llm.py`), with explicit scoring guidance:
*"An infinite loop with no break condition that runs unconditionally on
import/require is a 10 even with zero network calls, zero obfuscation, and
zero new dependencies."* Weights were rebalanced to make room — `weight`
history is documented directly on `DIMENSIONS` in `models.py`.

Rerunning the reconstruction against this fix alone:

| dimension | score | confidence |
|---|---|---|
| network_calls | 0.0 | 0.9 |
| obfuscation | 0.0 | 0.9 |
| install_hooks | 0.0 | 0.9 |
| env_conditional | 0.0 | 0.9 |
| dependency_changes | 0.0 | 0.9 |
| **resource_exhaustion** | **10.0** | **1.0** |

`resource_exhaustion` scored a perfect 10.0 at full confidence — the model
correctly recognises and maximally scores the exact pattern its free text
had already been describing qualitatively. **But the composite still landed
at only 25.0, LOW** (`llm_base_score` = 20.0, `+5.0` scorecard_poor). The
sixth dimension was *necessary* but not *sufficient*: at its 20% weight, a
perfect single-dimension score contributes at most `10 × 0.20 × 10 = 20`
points out of 100 — nowhere near the 30-point MEDIUM threshold on its own,
and every other dimension is a legitimate, correct 0.0 because this really
is a single-vector attack. **This was a genuinely new finding, not
anticipated when the dimension was proposed**: "routing it into a score"
(the original recommendation's framing) turned out to be necessary but
incomplete — the weighted-sum aggregation formula itself structurally caps
what one confidently-scored dimension can achieve.

**Part 2 — a definitive-dimension floor.** Added the same day, in
`analyzer/aggregator.py`: if any single LLM dimension scores ≥9.0 at
confidence ≥0.9, the composite score is floored to MEDIUM (≥30) — the
LLM-driven counterpart to the existing OSV `malicious_floor` feed rule (same
shape: `_apply_dimension_floor`, same audit trail via `score_modifiers[]`).
Before shipping this, every report already committed to `dataset/` was
checked for the trigger condition: it fires on three malicious-labelled
reports (all already HIGH — no-op) and node-ipc's diluted registry pair
(`dependency_changes=9.0`, confidence 0.95 — a desirable reclassification,
see below) and **zero benign-labelled reports**, anywhere in this corpus.

### The confirmed result

Rerunning with both fixes live:

**`llm_base_score` = 20.0 → `definitive_dimension_floor +10.0` → 30.0 →
`scorecard_poor +5.0` → risk_score = 35.0, MEDIUM.**

> "This update to the 'colors' package introduces a definitive resource
> exhaustion attack via an unconditional infinite loop... which executes on
> every require() of the package... has no break condition or exit path,
> causing any dependent application to hang indefinitely... the infinite
> loop alone makes this version definitively malicious from a supply chain
> security perspective."

**colors is now correctly flagged** — severity ≠ LOW, for the first time in
this corpus's history. Not a clean HIGH (this remains, correctly, a less
severe finding than node-ipc's destructive wipe or ua-parser-js's
credential theft — a hung process is bad, not catastrophic), but no longer
indistinguishable from routine maintenance the way the pre-fix 7.5 was.

## Per-pair detail

### 1.3.3 → 1.4.0 — benign control

- **What changed.** Adds bright/high-intensity ANSI color codes
  (`brightRed`, `brightGreen`, etc.) and matching bright background colors
  to `lib/styles.js`, updates the random-color map, and fixes a stylize
  fallback for non-ANSI styles. Entirely ordinary feature work.
- **LLM.** All six dimensions scored 0, including `resource_exhaustion`
  (re-verified after the fix — no false positive on this legitimate diff).
  Correctly read as routine.
- **OSV.** Clean for `colors@1.4.0` — correct, since the malicious release
  is `1.4.44-liberty-2`, which is no longer in the registry.
- **Scorecard.** 2.2/10 → `suspicious`, driven by `Maintained=0` and no
  branch protection — the same "abandoned project" signature seen on
  `event-stream` post-incident, here present *before* the incident even
  happened. `colors` was already a thinly-staffed, single-maintainer
  project, which is arguably a precondition for a maintainer being able to
  unilaterally sabotage it in the first place. The `+5` poor-scorecard
  modifier nudges the score up slightly (0.0 → 5.0) but stays LOW either way.
- **Take.** Correct false-positive-baseline behaviour: an ordinary feature
  diff on the eventual sabotage-victim package scores LOW, with the only
  friction being a legitimate long-term-maintenance signal. This holds after
  the DoS-dimension fix too — see "Still no false positives" below.

### 1.4.0 → 1.4.44-liberty-2 *(reconstructed)* — the real attack, LOW pre-fix → MEDIUM post-fix

- **What changed.** Exactly what shipped: a new `lib/custom/american.js`
  (ASCII flag + "LIBERTY" banner) and a ten-line addition to `lib/index.js`
  that unconditionally runs an infinite `for` loop on `require('colors')`.
  See "The reconstructed pair" above for the full before/after breakdown.
- **OSV.** `suspicious` — both real advisories for this incident
  (`GHSA-5rqg-jm4f-cqx7`, `GHSA-gh88-3pxp-6fm8`), correctly resolved against
  the reconstructed version string, before and after the fix. Neither is
  `MAL-*`, so the aggregator's `malicious_floor` rule doesn't fire —
  consistent with every other incident in this corpus (see
  `dataset/findings/README.md` RQ1/RQ4). It's the *new*
  `definitive_dimension_floor` rule that does the work here, not OSV.
- **Scorecard.** Identical to the benign-control pair (2.2/10, suspicious,
  `+5` modifier) both before and after — expected, since Scorecard
  evaluates the repository's overall hygiene, not this specific diff.
- **Take.** Pre-fix, the composite score (7.5) was barely different from
  the benign control's (5.0) — both dominated by the same Scorecard
  modifier, with the actual attack contributing only 2.5 points of LLM base
  score on top. For a CI gate, this diff would have been indistinguishable
  from routine maintenance. Post-fix, the gap is stark: colors sits at 35.0
  MEDIUM against the benign control's unchanged 5.0 LOW — a CI gate at any
  reasonable `--threshold` now separates them cleanly.

## Cross-cutting observations

### 1. Two "complete attack, reconstructed" results in this corpus used to disagree — now three of four agree

node-ipc's reconstruction (`malicious/node-ipc/FINDINGS.md`) went from a
diluted-remnant LOW (29.5) to a complete-attack HIGH (69.0, later 62.5 on
rerun under the weights described below — still comfortably HIGH either
way) — a fetching-completeness story with a happy ending once the full
payload was available.
colors's reconstruction *was* the full payload from the start and stayed
LOW (7.5) regardless — the difference wasn't reconstruction fidelity (both
were verified byte-for-byte against real base tarballs), it was that
node-ipc's payload matched chainwatch's original dimension taxonomy
(network calls, obfuscation, env conditionals) and colors's didn't
(denial-of-service via infinite loop isn't network activity, isn't
obfuscated, isn't env-gated — it's just control flow that never
terminates). **Update 2026-08-10:** with `resource_exhaustion` added and
the definitive-dimension floor in place, colors now also flags correctly
(MEDIUM). Of the four incidents in `dataset/malicious/`, three now reach at
least MEDIUM on reconstruction (node-ipc HIGH, ua-parser-js HIGH, colors
MEDIUM); only the diluted node-ipc *registry* pair remains LOW, and that's
the correct call given what it could see at the time — see recommendation
#3 in `dataset/findings/README.md` for the one remaining wrinkle there.

### 2. This is the "cleanest" attack in the corpus, and also the least severe — that's now visible in the score, not just the free text

The payload here is a denial-of-service (infinite loop), not data theft or
destructive file operations — meaningfully less dangerous than event-stream
(wallet credential theft), ua-parser-js (cryptominer + credential stealer),
or node-ipc (destructive file wipe). Pre-fix, the LLM free-text summary
showed the *model* wasn't fooled — it named the real incident and called
the change "malicious in effect" — but that recognition didn't propagate
into the composite score. Post-fix, the severity ordering now matches
intuition too: colors (MEDIUM, 35.0) sits below node-ipc and ua-parser-js
(both HIGH) but above every benign pair in the corpus, which is the
correct relative ranking for "real but comparatively less severe attack."

### 3. Still no false positives

Adding a dimension whose scoring guide explicitly says a bare loop pattern
"is a 10" carries real false-positive risk — legitimate code loops
constantly. Checked directly: lodash's real `4.17.20→4.17.21` diff (a
genuinely bounded `while (index-- && ...)` loop) scores `resource_exhaustion
= 1.0`, with the model's reasoning explicitly distinguishing "bounded by
string length, exits naturally" from an unbounded pattern. Every
benign-labelled report already committed to this corpus (9 pairs, `dataset/
benign/` + the adjacent pairs across the three unpublished-attack
incidents) was checked against the new `definitive_dimension_floor`
trigger condition before shipping — none hit it. See
`dataset/findings/README.md` recommendation #1 for the full corpus sweep.

## Position in the detection matrix

| package | malicious version available? | did diff-level analysis catch it? |
|---|---|---|
| colors | Yes — reconstructed from verified git history, byte-checked against a live base tarball | **Yes** — MEDIUM (35.0/100), as of the `resource_exhaustion` dimension + `definitive_dimension_floor` fixes. Pre-fix this was a clean miss (LOW, 7.5/100) despite being the complete, real attack: free-text summary correctly identified it, none of the five original scored dimensions did, and the new dimension alone (necessary but not sufficient) only reached 25.0 before the aggregator fix closed the remaining gap. |

Same caveat as event-stream and ua-parser-js: the available registry pair
validates non-false-positive behaviour on the pre-incident state, not
detection. Unlike those two, though, the sabotage commit *is* fully
recoverable and statically analysable outside chainwatch's registry-fetch
pipeline — see `evidence/`.
