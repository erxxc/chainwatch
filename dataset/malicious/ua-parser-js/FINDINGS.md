# ua-parser-js — chainwatch findings

Two version pairs were run on 2026-05-23 with `claude-sonnet-4-6` as the
analyser model. See `SOURCING.md` for why the actual malicious releases
(`0.7.29` / `0.8.0` / `1.0.0`) could not be analysed.

Redaction note: report JSON timestamps are normalized to
`2026-05-23T00:00:00Z` so the corpus records the run date without preserving
minute-level local execution timing.

## Summary

| pair | role | risk | LLM base | feed-adjusted | OSV | Rekor | Scorecard |
|---|---|---|---|---|---|---|---|
| 0.7.28 → 0.7.30 | brackets 0.7.29 | LOW | 3.8 | 0.0 | suspicious (ReDoS) | no_data | 7.4/10 clean |
| 0.7.30 → 0.7.31 | post-incident control | LOW | 15.2 | 10.2 | suspicious (ReDoS) | no_data | 7.4/10 clean |

Tarball SHA256 (verified at fetch time):

- `0.7.28`: `416a7af001e40ea2430136873c638c8afe655a1485b62b3b9e0d7ed49535e46b`
- `0.7.30`: `4d433579092044b1e3c17e01d94dc02f29cd133ab83cc3d5f70f35b4c3359056`
- `0.7.31`: `4d8acdabc90b038490cd85473e5f234096bd3b9a6f3198db6c41788002f06a89`

## Per-pair detail

### 0.7.28 → 0.7.30 — brackets the unpublished `0.7.29`

- **What changed.** Substantial refactor of `src/ua-parser.js` and the
  two minified `dist/` artifacts: vendor name constants extracted
  (`SAMSUNG`, `APPLE`, `HUAWEI`, …), utility-function renames
  (`util.has` → `has`, `mapper.rgx` → `rgxMapper`), nested map flattening,
  and many regex additions/updates for new device fingerprints. No new
  dependencies, no install hooks, no maintainer change visible at the
  diff level. The diff is the *legitimate* maintainer's two-release-worth
  of changes that landed in the post-incident `0.7.30` — i.e. it does
  not contain the attack payload.
- **LLM.** Five dimensions scored: network=0.5, obfuscation=1.0,
  install_hooks=0, env_conditional=0, dependency_changes=0. The two
  small non-zero scores are explainable: the LLM noted the dist files
  are minified (obfuscation=1.0 is a "this is minified, which is normal
  for dist") and that one of the new regex patterns *could* in principle
  match URL-shaped strings (network=0.5). Both rationales are reasonable
  and self-deprecating in the model's own words.
- **LLM was situationally aware.** The summary explicitly notes the
  October 2021 attack and clarifies that this specific diff does not
  contain it: *"ua-parser-js was the subject of a well-known supply
  chain attack in October 2021 (versions 0.7.29, 1.0.0), but this
  specific diff (0.7.28 to 0.7.30) does not show the malicious
  cryptocurrency mining or credential-stealing code associated with
  that incident — though the diff is truncated and only partial
  content is visible."* This is a non-trivial behaviour: the model
  identified the package, recalled the incident, recognized that the
  diff doesn't contain the payload, and flagged its own uncertainty
  due to truncation.
- **Diff truncation.** Two files were truncated by the chunker:
  `dist/ua-parser.min.js` and `src/ua-parser.js` (both from ~31.8KB
  down to a smaller window). The chunker produced 4 chunks total,
  `diff_truncated=True`. The minified file is the most likely place
  for an attacker to hide a payload, so truncation here is a real
  risk for false negatives.
- **OSV.** Flagged `GHSA-fhg7-m89q-25r3` (CVE-2022-25927, ReDoS in
  ua-parser-js `>=0.7.30 <0.7.33` and `>=0.8.0 <1.0.33`). This is a
  *different* vulnerability from the 2021 supply-chain attack —
  a regex denial-of-service published Jan 2023. OSV correctly returns
  it; chainwatch correctly labels the feed `suspicious` (not
  `malicious`) because the advisory ID is `GHSA-*`, not `MAL-*`.
- **Scorecard.** 7.4/10 (Maintained=10, Code-Review=0,
  Branch-Protection=4, Signed-Releases=-1). This is "clean" by the
  current aggregator threshold (>7), which applies a -5 mitigant to
  the composite score.
- **Score progression.** LLM base = 3.8. Feed modifiers:
  GHSA `suspicious` adds 0 (only `malicious` triggers the floor),
  Scorecard >7 applies -5 → 3.8 - 5 = -1.2 → clamped to 0.0. Final:
  **0.0, LOW**.
- **Take.** Useful negative-result run: the diff does not contain the
  payload, the LLM correctly says so while noting its own incomplete
  view, and the composite score lands at the floor. The OSV ReDoS hit
  is a nice side-validation that the OSV path is working — and a small
  reminder that *non-malicious* advisories can colour a report even
  when no supply-chain attack is present.

### 0.7.30 → 0.7.31 — post-incident control

- **What changed.** Minor maintenance: version bump in `package.js`,
  one new regex for an OPPO device model, strict-equality cleanups,
  safer for-loop iteration, and a rewritten test-suite regex
  extraction using `@babel/parser` + `@babel/traverse` (added as
  `devDependencies`, not runtime deps).
- **LLM.** network=0.5, obfuscation=1.0, install_hooks=0.5,
  env_conditional=0.5, **dependency_changes=6.5**. The high
  dependency-changes score is driven by the two new Babel deps. The
  LLM's rationale is balanced: it flags that "@babel/parser and
  @babel/traverse are powerful AST traversal tools that could be used
  to analyze or transform JavaScript code at runtime" while also
  noting in the summary that their use is "transparent and
  appropriate" for the test suite. The dimension scored as if the
  deps were runtime; the summary correctly identified them as
  test-only. This is a soft inconsistency between the per-dimension
  and free-text reasoning.
- **OSV / Rekor / Scorecard.** Same as previous pair — OSV returns
  the same `GHSA-fhg7-m89q-25r3` (the ReDoS range covers `0.7.31` too),
  Rekor has no data for any ua-parser-js version, Scorecard 7.4 clean.
- **Score progression.** LLM base = 15.2. Scorecard >7 → -5 → 10.2.
  Final: **10.2, LOW**.
- **Take.** Cleanest illustration in the corpus so far of how
  *legitimate* dep additions can lift the LLM base score by ≈10 points
  even when those deps are well-known test-only tooling. Without the
  Scorecard mitigant this pair scores 15.2 — still LOW under the
  current bucketing (LOW < 25), but the gap between this benign diff
  and a hypothetical real attack might be smaller than we'd like.

## Cross-cutting observations

### 1. Detection-gap analysis

The 2021-10-22 timeline is the tightest in the corpus and is worth
emphasising:

| event | UTC time | gap from publish |
|---|---|---|
| Malicious 0.7.29 / 0.8.0 / 1.0.0 published | 12:15–12:16 | t = 0 |
| Maintainer regains access | ~16:00 | +3h 45m |
| Fix 0.7.30 / 0.8.1 / 1.0.1 published | 16:16–16:26 | +4h 0m |
| GHSA-pjwm-rvh2-c87w published to OSV | 20:38 | +8h 23m |
| `ossf/malicious-packages` entry | never published | — |

For a tool consuming OSV in real time, the detection gap on this
incident is **8h 23m** — the window in which the malicious release was
live on the registry but no OSV advisory existed. A diff-level LLM
scanner that polls fresh releases could in principle close that
window to "single-digit minutes after publish" — that's the upper
bound on what chainwatch could contribute on an incident shaped like
this one. For comparison, the `event-stream` detection gap was **72
days** (publish 2018-09-09, public disclosure 2018-11-20).

### 2. `malicious` vs `suspicious` OSV statuses change the score path

Both ua-parser-js fix versions have an OSV advisory (`GHSA-fhg7-m89q-25r3`,
a ReDoS bug published Jan 2023). chainwatch correctly categorises this
as `suspicious` rather than `malicious` because the ID is `GHSA-*` and
not `MAL-*`. The aggregator's modifier table only floors the score on
`malicious`, so this advisory contributes 0 to the composite. That is
likely the right behaviour — a ReDoS bug is not a supply-chain attack —
but it should be documented in the paper: **"chainwatch's OSV layer
distinguishes confirmed malware (`MAL-*`) from generic vulnerabilities
(`GHSA-*`/`CVE-*`) and only the former floors the composite score."**

### 3. The Scorecard mitigant nukes low-but-non-zero LLM signal

Both pairs were rescued from a non-zero LLM base score by the
`scorecard_score > 7 → -5` mitigant. The 0.7.28→0.7.30 pair would have
landed at 3.8 (still LOW); the 0.7.30→0.7.31 pair would have landed at
15.2 (still LOW). Under the current bucketing this doesn't change
severity, but if we tighten the LOW/MEDIUM threshold for the paper,
the mitigant could start flipping pairs from MEDIUM down to LOW. The
aggregator's `_apply_feed_modifiers` notes this as an explicit design
choice ("strong hygiene is a mild mitigant") — worth defending or
revising before publication.

### 4. Diff truncation is a real false-negative risk

Both runs hit truncation on the minified dist file. The LLM noticed
in the first run ("the diff is truncated and only partial content is
visible") but cannot reason about what it didn't see. A malicious
payload hidden inside a minified bundle would be exactly where
truncation strikes. The chunker's truncation strategy currently
favours showing the start of large files; for the paper we should
either:

  - Chunk *all* large files end-to-end across multiple LLM calls, or
  - Stamp the report with an explicit "files truncated, score may
    underestimate" caveat that the paper can cite.

### 5. The LLM did real situational reasoning

The `0.7.28→0.7.30` run included an unsolicited paragraph identifying
the historical incident and explaining why this specific diff is
*not* the attack diff. This is more useful than a rote dimension
score: it shows the model can disambiguate "a famously attacked
package" from "a currently-attacked diff." For the paper, this is a
qualitative behaviour worth showing alongside the quantitative
results.

## Position in the Day-3 detection matrix

| package | malicious version available? | did diff-level analysis catch it? |
|---|---|---|
| event-stream | no (3.3.6 unpublished) | not testable at registry level |
| ua-parser-js | no (0.7.29 / 0.8.0 / 1.0.0 unpublished) | not testable at registry level |

Like the event-stream entry, this row in the final precision/recall
table will need to be excluded or footnoted as "artifact unavailable."
The available pairs validate that chainwatch does not false-positive
on the legitimate post-incident diffs (both LOW, score ≤ 10.2), which
is a non-trivial result given the LLM was situationally aware of the
attack — it could plausibly have over-flagged anything in this
package out of caution and did not.

## Implementation gaps surfaced by this run

- **`llm_base_score` still null in the report.** Same observation as
  the event-stream runs: the aggregator logs `LLM base=3.8` and
  `LLM base=15.2` but the saved JSON does not persist these. The
  composite-score audit trail is incomplete without it.
- **Per-dimension `confidence` still null.** As with event-stream,
  the prompt asks for per-dimension reasoning but not confidence.
- **`from_version_sha256` / `to_version_sha256` are present** — same
  as event-stream, reproducibility on the input artefacts is preserved.
- **Feed-modifier provenance not in the report.** The aggregator
  knows it applied `scorecard:good -5` but the saved JSON shows only
  the final `risk_score`. For the paper we want to be able to
  decompose any score post-hoc; adding a `score_modifiers` array to
  the report would close that.
