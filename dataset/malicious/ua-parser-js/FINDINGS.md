# ua-parser-js — chainwatch findings

Two version pairs were run on 2026-05-23 with `claude-sonnet-4-6` as the
analyser model. See `SOURCING.md` for why the actual malicious releases
(`0.7.29` / `0.8.0` / `1.0.0`) could not be analysed *at the registry level*.

**Update 2026-08-07:** the malicious `preinstall.js`/`.sh`/`.bat` scripts have
since been reconstructed from public writeups — see `SOURCING.md`'s
"Recovered evidence" section and `evidence/`.

**Update 2026-08-10:** that recovered payload was run through the real
pipeline — a real, still-published `0.7.28` tarball as the base, with the
recovered `preinstall.js`/`.sh`/`.bat` spliced in exactly as documented and
the `package.json` preinstall hook wired up, diffed as two local
directories. This surfaced a gap not seen in any other reconstruction in
this corpus: `chainwatch.diff.engine.SOURCE_EXTENSIONS` didn't recognise
`.sh`/`.bat`, so two of the three payload files were silently withheld from
the LLM. `claude-sonnet-4-6` again.

**Update 2026-08-10 (later the same day):** that gap has since been fixed
— `SOURCE_EXTENSIONS` now includes `.sh`/`.bat`/`.ps1`/`.cmd`
(`src/chainwatch/diff/engine.py`) — and the reconstruction was rerun
against the real, unmodified fixed code (no monkey-patching this time).
**Result: HIGH (60.0)**, up from the pre-fix MEDIUM (42.5). The pre-fix
report is preserved at
`pre-fix-report-0.7.28-to-0.7.29-RECONSTRUCTED.json` for citation.

**Update 2026-08-10 (a third time, same day):** rerun again after a sixth
risk dimension (`resource_exhaustion`) and a `definitive_dimension_floor`
aggregator rule landed (`malicious/colors/FINDINGS.md`). Unlike
event-stream/node-ipc's reruns (weight cuts outweighing a small or zero new
dimension score), this attack's XMRig cryptominer payload reasonably reads
as resource-abuse too — the LLM scores `resource_exhaustion=10.0` here, not
0. **Current result: HIGH (67.0)**, the highest number this pair has ever
reached. See "The reconstructed pair" below for the full three-act
before/after story.

Redaction note: the two 2026-05-23 report JSON timestamps are normalized to
`2026-05-23T00:00:00Z`. The reconstructed pair's report keeps its real
timestamp, matching the `node-ipc`/`colors`/`flatmap-stream` convention.

## Summary

| pair | role | risk | LLM base | feed-adjusted | OSV | Rekor | Scorecard |
|---|---|---|---|---|---|---|---|
| 0.7.28 → 0.7.30 | brackets 0.7.29 | LOW | 3.8 | 0.0 | suspicious (ReDoS) | no_data | 7.4/10 clean |
| 0.7.30 → 0.7.31 | post-incident control | LOW | 15.2 | 10.2 | suspicious (ReDoS) | no_data | 7.4/10 clean |
| 0.7.28 → 0.7.29 *(reconstructed, post-DoS-fix)* | **the actual attack, as chainwatch sees it today** | **HIGH** | 72.0 | 67.0 | suspicious (`GHSA-pjwm-rvh2-c87w`) | no_data | 7.6/10 clean |

Tarball SHA256 (verified at fetch time — the two registry pairs; the
reconstructed pair's `from` side is the same real, still-published `0.7.28`
tarball, fetched via chainwatch's own npm fetcher, but its hash wasn't
threaded through the report schema — see `SOURCING.md`, matching the
`node-ipc`/`colors`/`flatmap-stream` convention of `null` sha256 fields on
reconstructed pairs):

- `0.7.28`: `416a7af001e40ea2430136873c638c8afe655a1485b62b3b9e0d7ed49535e46b`
- `0.7.30`: `4d433579092044b1e3c17e01d94dc02f29cd133ab83cc3d5f70f35b4c3359056`
- `0.7.31`: `4d8acdabc90b038490cd85473e5f234096bd3b9a6f3198db6c41788002f06a89`

## The reconstructed pair: found MEDIUM with a diagnosable cause, now HIGH after the fix

Real `ua-parser-js@0.7.28` (still published) was fetched via chainwatch's
own npm fetcher and used as both directories — the "from" side untouched,
the "to" side with the recovered `preinstall.js`, `preinstall.sh`, and
`preinstall.bat` (byte-identical to `evidence/`, hashes below) copied to
the package root and `package.json`'s `scripts` gaining
`"preinstall": "start /B node preinstall.js & node preinstall.js"` — exactly
the wiring documented in `evidence/README.md`. Diffed as two local
directories, no registry fetch on the "to" side.

### What the first run found

**`diff_summary.files_added` = `["preinstall.js"]` only.** `preinstall.sh`
and `preinstall.bat` were physically present in the directory chainwatch
diffed — and are exactly where the real attack's payload logic lives, per
`evidence/README.md` — but `chainwatch.diff.engine.SOURCE_EXTENSIONS`
(`src/chainwatch/diff/engine.py`) only recognised
`{.js, .ts, .mjs, .cjs, .jsx, .tsx, .py, .pyi}` at the time. `.sh` and
`.bat` weren't in that set, so `_enumerate_source_files` never returned
them — not truncated, not skipped-as-oversized, **never enumerated at
all**. The LLM was shown only the dispatcher (`preinstall.js`, which merely
`exec`s/`spawn`s the two files by name) and the `package.json` metadata
diff (which did correctly flag `new_install_hooks: ["preinstall"]` — that
part of the schema has no extension filter).

| dimension | pre-fix score | reasoning (abridged) |
|---|---|---|
| network_calls | 6.0 | "The shell scripts are not included in the diff, so network calls within them cannot be ruled out... that evidence is not directly visible here" |
| obfuscation | 1.0 | "No obfuscation patterns... in preinstall.js itself" |
| install_hooks | 9.0 | "A new 'preinstall' hook is added... introducing arbitrary shell execution at install time with no legitimate documented reason" |
| env_conditional | 7.0 | "preinstall.js explicitly checks process.platform to branch..." |
| dependency_changes | 1.0 | "No new package.json dependency additions are visible" |

Pre-fix `llm_base_score` = 47.5, feed-adjusted **42.5, MEDIUM** — flagged
(severity ≠ LOW) but well short of a clean HIGH. The LLM's own free text
was explicit about *why* it was hedging:

> "Although the shell script contents are not included in the diff, this
> exact pattern was confirmed to install a cryptocurrency miner and
> credential-stealing malware."

**It knew what it was missing.** `network_calls` confidence was 0.4 — the
lowest of any dimension in that run — precisely because the model could
see it was being shown an incomplete picture, even though nothing in the
report schema told it so explicitly; it inferred that from the dispatcher
script calling out to files it was never shown. Full pre-fix report:
`pre-fix-report-0.7.28-to-0.7.29-RECONSTRUCTED.json`.

### The natural experiment that isolated the cause

To confirm this as the actual cause (not just a plausible story) before
changing any real code, the same two directories were re-diffed with
`engine.SOURCE_EXTENSIONS` monkey-patched in-process to add `.sh`/`.bat` —
no other change, same real base, same splice, same model, same feed
queries. Saved as `experiment-full-visibility-0.7.28-to-0.7.29.json`
(never a `report-*.json` — it required modifying chainwatch's behaviour,
so it was always a diagnostic artifact, not a corpus ground-truth entry).

| | pre-fix (as chainwatch behaved) | experiment (`.sh`/`.bat` patched in) |
|---|---|---|
| `files_added` | `["preinstall.js"]` | `["preinstall.bat", "preinstall.js", "preinstall.sh"]` |
| `network_calls` | 6.0 | **10.0** |
| `install_hooks` | 9.0 | **10.0** |
| `env_conditional` | 7.0 | **9.0** |
| `llm_base_score` | 47.5 | **62.5** |
| `risk_score` / severity | 42.5 / MEDIUM | **57.5 / HIGH** |

Same attack, same LLM, same feeds, same weighting — the *only* variable
changed was whether the diff engine's file-type allowlist included the two
extensions the real payload happened to be written in. That one change
flipped the severity bucket. The full-visibility summary left no ambiguity:

> "This update to ua-parser-js 0.7.29 is a confirmed supply chain attack.
> Three malicious preinstall scripts are added that download and execute a
> cryptocurrency miner... a geo-exclusion check that skips infection for IP
> addresses resolving to Russia, Ukraine, Belarus, and Kazakhstan. This is a
> definitive, unambiguous malicious compromise of the package."

This was a fourth, structurally distinct category of gap in this corpus —
not a fetching-completeness problem (node-ipc), not a missing risk
dimension (colors), not a feed-timing problem (flatmap-stream), but the
diff engine's own source-file allowlist. Unlike colors's taxonomy gap, this
one didn't need a new dimension or a prompt change — `SOURCE_EXTENSIONS`
was a single frozenset literal, which made it the cheapest fix identified
anywhere in this write-up.

### The fix, and the confirming rerun

`SOURCE_EXTENSIONS` was widened to
`{.js, .ts, .mjs, .cjs, .jsx, .tsx, .py, .pyi, .sh, .bat, .ps1, .cmd}` —
`.ps1`/`.cmd` added alongside `.sh`/`.bat` since they're the same class of
install-time script and were already flagged as "plausible next
candidates" in `dataset/findings/README.md`. A regression test
(`tests/unit/test_diff_engine.py::test_install_scripts_are_enumerated`)
was added, modeled directly on this incident.

The reconstruction was then rerun **against the real fixed code**, not a
monkey-patch — same two directories, same splice, freshly diffed and
re-sent to the LLM:

| dimension | post-fix score | confidence |
|---|---|---|
| network_calls | **10.0** | 1.0 |
| obfuscation | 2.0 | 0.9 |
| install_hooks | **10.0** | 1.0 |
| env_conditional | **9.0** | 1.0 |
| dependency_changes | 1.0 | 0.6 |

`llm_base_score` = 65.0, feed-adjusted **60.0, HIGH**. Close to but not
identical to the experiment's 57.5 (LLM outputs aren't bit-for-bit
reproducible — `obfuscation` came back 2.0 here vs. 1.0 in the experiment,
`dependency_changes` confidence 0.6 vs. 0.8), which is itself a useful
confirmation: two independent runs of the same fixed behaviour against the
same real attack both land solidly in HIGH territory, not just once. The
free-text is unambiguous:

> "This update to ua-parser-js 0.7.29 is a confirmed supply chain attack...
> They download and run a cryptominer binary (jsextension / jsextension.exe)
> connecting to pool.minexmr.com:443, and on Windows also register a DLL
> (create.dll fetched from citationsherbe.at) via regsvr32. A geolocation
> check deliberately skips execution in RU/UA/BY/KZ regions, a hallmark of
> targeted threat actors. This is definitively malicious..."

**Net effect:** a real, historical attack that chainwatch under-scored for
a diagnosable, single-line reason now scores correctly, verified against
the actual attack rather than just argued for. See
`dataset/findings/README.md` recommendation #2 (now implemented) for the
corpus-wide framing.

### A third run, after the resource_exhaustion fix

Later the same day, `resource_exhaustion` (a sixth dimension) and
`definitive_dimension_floor` (an aggregator rule) landed, both built for
the `colors` incident (`malicious/colors/FINDINGS.md`) — not this one. This
pair was rerun anyway, for corpus consistency, against the real fixed code:

| dimension | score | confidence |
|---|---|---|
| network_calls | **10.0** | 1.0 |
| obfuscation | 2.0 | 0.9 |
| install_hooks | **10.0** | 1.0 |
| env_conditional | 8.0 | 1.0 |
| dependency_changes | 1.0 | 0.8 |
| resource_exhaustion | **10.0** | 1.0 |

`resource_exhaustion` scores a full 10.0 here too — not because this attack
is DoS-shaped in the colors sense, but because the model reasonably reads
the XMRig cryptominer as its own kind of resource abuse (an unthrottled
background process consuming CPU indefinitely, `--cpu-max-threads-hint=50`
notwithstanding). `llm_base_score` = 72.0 — *higher* than the
SOURCE_EXTENSIONS-only rerun's 65.0, despite `network_calls`/`obfuscation`
losing weight (25%→20% each) to make room for the new dimension — the new
dimension's contribution outweighs that loss for this specific attack.
Feed-adjusted (Scorecard `-5.0`, unchanged): **67.0, HIGH.** This is now
the highest score this pair has ever reached, across all three runs
(42.5 → 60.0 → 67.0), and the canonical `report-0.7.28-to-0.7.29-RECONSTRUCTED.json`.

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

### 0.7.28 → 0.7.29 *(reconstructed)* — the real attack, MEDIUM pre-fix → HIGH post-fix

- **What changed.** Exactly what shipped: a new `preinstall.js` dispatcher,
  `preinstall.sh`/`preinstall.bat` payload scripts (miner download,
  geo-gate, credential-stealer DLL), and a `package.json` `preinstall`
  hook wiring it all together. See "The reconstructed pair" above for the
  full before/after dimension breakdown, the extension-filter finding, and
  the fix.
- **OSV.** `suspicious` — `GHSA-pjwm-rvh2-c87w`, correctly resolved against
  `ua-parser-js@0.7.29`. Never reached `MAL-*` (see
  `dataset/findings/README.md`), so no feed-floor bonus applies here,
  before or after the fix.
- **Scorecard.** `clean`, 7.6/10 — genuinely reflects the real, actively
  maintained `faisalman/ua-parser-js` repository (unlike flatmap-stream's
  reconstruction, where the registry pointed at npm's placeholder repo
  instead). This applies the `-5.0` mitigant both before and after the fix
  — pre-fix it pushed the composite (42.5) *below* the LLM base score
  (47.5); post-fix the LLM base score is high enough (65.0) that the same
  `-5.0` still leaves a comfortable HIGH (60.0).
- **Take.** Pre-fix: correctly flagged (MEDIUM ≠ LOW), but the weakest "hit"
  in the corpus, for a reason that had nothing to do with the LLM's
  judgement or the feeds — the diff engine's own file-extension allowlist
  withheld the two files that actually contain the attack logic. Post-fix:
  a clean HIGH, on the identical real attack, confirmed by an independent
  (non-monkey-patched) rerun.

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

**Update 2026-08-10:** the reconstructed pair surfaced a *sibling* gap,
worth distinguishing from this one. Truncation is "the diff engine saw the
file but only showed part of it to the LLM." The extension-filter gap (see
"The reconstructed pair" above) was "the diff engine never saw the file at
all" — `preinstall.sh`/`.bat` weren't truncated, they were never enumerated,
because `.sh`/`.bat` weren't in `SOURCE_EXTENSIONS`. Both are false-negative
risks in the same family (the LLM analyses less than the full attack
surface), but they had different fixes: truncation needs better chunking
(still open); the extension filter needed a wider allowlist (**fixed
2026-08-10** — see "The fix, and the confirming rerun" above). Neither is
what colors's gap is (a taxonomy problem — the LLM sees everything and
still has no dimension for it).

### 5. The LLM did real situational reasoning

The `0.7.28→0.7.30` run included an unsolicited paragraph identifying
the historical incident and explaining why this specific diff is
*not* the attack diff. This is more useful than a rote dimension
score: it shows the model can disambiguate "a famously attacked
package" from "a currently-attacked diff." For the paper, this is a
qualitative behaviour worth showing alongside the quantitative
results.

## Position in the detection matrix

| package | malicious version available? | did diff-level analysis catch it? |
|---|---|---|
| ua-parser-js | Yes — reconstructed from a real, still-published `0.7.28` base plus the recovered `preinstall.js`/`.sh`/`.bat` scripts, wired up exactly as documented | **Yes** — HIGH (67.0/100), as of the `SOURCE_EXTENSIONS` fix and the `resource_exhaustion`/`definitive_dimension_floor` fixes. Originally a partial catch (MEDIUM, 42.5/100): correctly flagged (severity ≠ LOW) but held back from HIGH by the diff engine's own `.sh`/`.bat` extension-filter gap, not by the LLM's judgement or feed timing. Three runs, three numbers: 42.5 → 60.0 → 67.0. See "The reconstructed pair" above for the full before/after. |

The two registry-fetched pairs above remain negative results only: they
validate that chainwatch does not false-positive on the legitimate
post-incident diffs (both LOW, score ≤ 10.2), which is a non-trivial result
given the LLM was situationally aware of the attack — it could plausibly
have over-flagged anything in this package out of caution and did not. The
reconstructed pair is what actually answers the detection question for this
incident — see `dataset/findings/README.md` for how it folds into the
corpus-wide precision/recall numbers.

## Implementation gaps surfaced by this run

- **`llm_base_score` was `null` in both original 2026-05-23 reports.** The
  aggregator logged `LLM base=3.8` and `LLM base=15.2` but the saved JSON
  didn't persist these. **Since fixed** (schema `0.2.0`) — the reconstructed
  pair's report carries it (`65.0`) directly.
- **Per-dimension `confidence` was `null` in both original reports.**
  **Since fixed** — the reconstructed pair's report has `confidence`
  populated on every dimension (0.6–1.0).
- **`from_version_sha256` / `to_version_sha256` are present for the two
  registry-fetched pairs**, preserving reproducibility on the input
  artefacts. Both are `null` for the reconstructed pair — the "from" side
  really is the same real `0.7.28` tarball (hash above), but its digest
  wasn't threaded through `aggregator.build_report`, matching the
  established convention for reconstructed pairs elsewhere in this corpus.
- **Feed-modifier provenance was missing from the original reports.**
  **Since fixed** (`score_modifiers[]`, schema `0.2.0`) — the reconstructed
  pair's report shows `scorecard:scorecard_good -5.0` explicitly.
- **`SOURCE_EXTENSIONS` didn't include `.sh`/`.bat`.** Found by this run,
  isolated by a controlled experiment, and **fixed same-day** —
  `src/chainwatch/diff/engine.py` now also recognises `.ps1`/`.cmd`. See
  "The fix, and the confirming rerun" above and
  `tests/unit/test_diff_engine.py::test_install_scripts_are_enumerated`.
