# coa / rc — chainwatch findings

**Not a canonical corpus entry — read `SOURCING.md` first.** All six
reports here (`inconclusive-report-coa-2.0.2-to-2.0.3-PARTIAL.json`,
`inconclusive-report-rc-1.2.8-to-1.2.9-PARTIAL.json`, their
`-SILENT-STUB` counterparts, added 2026-08-11 as a deliberate follow-up,
and their `-STRIPPED` counterparts, added 2026-09-09 — see the last
section) are excluded from every corpus-wide precision/recall statistic in
`dataset/findings/README.md` by filename convention. This document exists
because the *attempt* produced a genuinely useful, unexpected finding —
not the one it was built to test — and a follow-up experiment then
confirmed and quantified it directly.

## What this was supposed to test, and what happened instead

`coa`/`rc` was picked to stress-test `_apply_dimension_floor` on a third
trigger dimension (`install_hooks`), on the hypothesis that a
single-vector, obfuscated postinstall-downloader attack would land
`install_hooks` near-maximally without other dimensions doing much work —
similar in spirit to how `colors`'s `resource_exhaustion=10.0` carried
that pair almost alone. The real payload code was never recoverable (see
`SOURCING.md`/`evidence/README.md`), so both directories use explicitly-
labeled placeholder files in place of `compile.js`/`compile.bat`/`sdd.dll`
— their content states plainly, in a header comment, that they are not
real attacker code, and summarises only the independently-verified facts
(exact preinstall hook, exact file names, exact download domain, malware
family, exact IOCs).

**My own prediction going in, stated to the user before running this, was
that the resulting scores would come out artificially *low*** — the
reasoning being that an LLM reading placeholder comments instead of real
obfuscated code would have nothing substantive to score. **That prediction
was wrong, and the actual mechanism is more interesting than either the
"low score" or "high score" outcome on its own.**

## The actual result

| pair | risk | severity | llm_base_score | scorecard modifier | floor modifier |
|---|---|---|---|---|---|
| `coa 2.0.2 → 2.0.3` | 56.0 | **HIGH** | 51.0 | +5.0 (`scorecard_poor`) | none |
| `rc 1.2.8 → 1.2.9` | 60.0 | **HIGH** | 55.0 | +5.0 (`scorecard_poor`) | none |

Both pairs scored HIGH — comfortably above even the corpus's real,
byte-verified HIGH results in some cases. The reason isn't that chainwatch
"saw through" the placeholders to some real signal. It's visible directly
in the LLM's own reasoning text, per-dimension:

| dimension | coa score/conf | rc score/conf | reasoning (verbatim excerpt) |
|---|---|---|---|
| network_calls | 8.0 / 0.4 | 9.0 / 0.4 | *"The placeholder comments in compile.bat describe the real payload as having made network calls via curl/wget/certutil to download sdd.dll..."* |
| obfuscation | 7.0 / 0.4 | 8.0 / 0.4 | *"The placeholder comments in compile.bat and compile.js explicitly state the real payload was obfuscated..."* |
| install_hooks | 10.0 / **0.9** | 10.0 / **0.9** | *"A new 'preinstall' hook is explicitly flagged as added in the metadata. The compile.js header comment confirms..."* |
| env_conditional | 2.0 / 0.2 | 2.0 / 0.2 | *"No evidence of environment-variable or CI-detection logic is visible in the diff. The placeholder comments do not mention such logic."* |
| dependency_changes | 1.0 / 0.3 | 1.0 / 0.5 | *"No dependency changes are mentioned in the diff metadata."* |
| resource_exhaustion | 1.0 / 0.2 | 1.0 / 0.2 | *"No evidence of resource exhaustion patterns in the visible diff. The payload description focuses on credential theft (DanaBot), not denial of service."* |

The model's own words are explicit about its source: **it is reading the
placeholder comments as a description of the attack and scoring the
description, not analysing real code.** Every reasoning string for a
dimension it can't directly verify says so outright ("the placeholder
comments describe...", "explicitly state...", "the placeholder comments do
not mention..."). This is not a hidden or inferred mechanism — the model
told us exactly what it was doing.

## The follow-up: isolating narration as the variable (2026-08-11)

The result above is suggestive but not, on its own, controlled — the
narrated placeholders and a hypothetical silent version were never
actually compared. This follow-up closes that gap: same real `from`
tarball, same real `preinstall` hook, same three real filenames present —
but `compile.js`/`compile.bat`/`sdd.dll` are now genuinely **empty (0
bytes)**, with no comments, no description, nothing. See
`evidence/README.md`'s "silent-stub control" section for the exact files.

| pair | condition | risk | severity | llm_base_score |
|---|---|---|---|---|
| `coa 2.0.2 → 2.0.3` | narrated placeholder | 56.0 | HIGH | 51.0 |
| `coa 2.0.2 → 2.0.3` | **silent stub** | **36.0** | **MEDIUM** | 31.0 |
| `rc 1.2.8 → 1.2.9` | narrated placeholder | 60.0 | HIGH | 55.0 |
| `rc 1.2.8 → 1.2.9` | **silent stub** | **31.5** | **MEDIUM** | 26.5 |

**The gap is large and it flips the severity bucket both times** — 20.0
points for `coa` (HIGH → MEDIUM), 28.5 points for `rc` (HIGH → MEDIUM).
That's direct, controlled evidence, not just a plausible inference: the
narration in the placeholder comments was doing real, quantifiable work.

It's not the *whole* story, though, and the silent-stub result is
interesting in its own right. The LLM still scored `install_hooks=8.0` at
confidence 0.7 — lower than the narrated run's 10.0/0.9, but still
elevated — and its reasoning explains why without any narration to lean
on: *"The 'coa' package is a simple CLI options parser with no legitimate
need for native compilation or a preinstall script... the actual content
of compile.js and compile.bat is not visible in the diff (shown as 0
lines), preventing full analysis... all other dimensions are scored
conservatively due to truncated content."* That's a genuinely sound piece
of reasoning: a new preinstall hook pointing at unexplained, empty files
on a package with no apparent reason to need either is itself a real
structural red flag, and the model correctly (a) flagged it, (b) said
plainly that it couldn't fully analyse what it couldn't see, and (c) kept
the resulting severity at MEDIUM rather than jumping to HIGH the way the
narrated run did. Zero narration didn't produce zero suspicion — it
produced *calibrated* suspicion, capped well below what naming the actual
attack (DanaBot, the download chain, the obfuscation technique) produced.

## Why this is a real, if narrow, finding

**A diff whose only "evidence" of maliciousness is descriptive prose — even
prose that plainly labels itself a placeholder, written by us, not an
attacker — drives a substantial, now-quantified score increase (20–28.5
points, enough to flip HIGH vs. MEDIUM both times), on top of whatever
structural signal is present regardless.** This wasn't a
training-data-recognition question we set out to test (we still can't
cleanly separate "the model recognises this famous, well-documented 2021
incident by name" from "the model is taking our placeholder comments'
claims at face value" — both are plausible and both would produce the same
observed behaviour; the silent-stub control removes the comments but
doesn't remove the model's general knowledge that `coa`/`rc` were
compromised in 2021, so even this experiment can't fully isolate that
question). But the mechanism that's directly demonstrated, in the model's
own reasoning text and now in a controlled score comparison, doesn't
require assuming training-data recall at all: **narrative description
embedded in a diff substitutes for the code it describes, and the effect
is large enough to measure.**

This matters for the corpus's broader validity in a way distinct from the
"overfitting" caveat already documented in `dataset/findings/README.md`.
That caveat is about two scoring *rules* being tuned on this corpus's own
failures. This finding is about the *evaluation method* itself: every
reconstruction in this corpus, including the byte-verified ones, involves
human-written `SOURCING.md`/`evidence/README.md` prose sitting next to
(not inside) the diffed code — but if a diff's *own comments* narrating an
attack are sufficient to drive a high score on their own, it raises a real
question about how much of chainwatch's LLM-layer signal on any famous,
well-documented incident is code analysis versus incident recognition
dressed as code analysis. Nothing in this corpus can currently distinguish
the two for the six *canonical* incidents, because none of them were
constructed as a controlled test of this specific question — this is the
first time it's been isolated, and only because a real sourcing failure
forced the placeholder-comment condition into existence.

One genuinely reassuring detail, worth stating plainly rather than buried:
**the model didn't treat every dimension the same way.** It reserved its
one high-confidence score (`install_hooks`, 0.9) for the single fact it
could verify directly from the diff's own structure (a real `preinstall`
key was genuinely added — that part isn't fabricated, it's the one real
signal in the whole reconstruction) and kept every inferred dimension at
low confidence (0.2–0.5). That's a calibration behavior worth crediting:
the model isn't uniformly overconfident, it's discriminating between "I
can see this" and "I'm told this," even though both pathways ultimately
pushed the composite score to the same place.

## What this does confirm, consistent with `ctx`

`install_hooks=10.0` at confidence 0.9 (narrated condition) technically
meets `_apply_dimension_floor`'s trigger threshold on both pairs — and,
exactly as with `ctx`'s `0.1.2-1` pair, **the floor rule never fires**,
because `llm_base_score` already clears 30 (51.0 and 55.0) before the
floor rule is even consulted. This is now the *second* out-of-corpus-styled
test where a confidently-scored dimension reaches the floor's trigger
condition without ever needing the floor — both times because realistic
multi-signal attacks (even a placeholder-narrated one) tend to push several
correlated dimensions up together, not just one. The silent-stub condition
doesn't even reach the trigger in the first place (`install_hooks=8.0`,
confidence 0.7 — below both the ≥9.0 score and ≥0.9 confidence bars), so
across all six out-of-corpus runs attempted so far (`ctx`'s two pairs;
`coa`/`rc`'s narrated and silent conditions, two packages each),
`_apply_dimension_floor` has fired exactly zero times outside the two
cases it was built from (`colors`, node-ipc's diluted registry pair) — see
recommendation #7 in `dataset/findings/README.md`, still open.

## Position in the detection matrix

Deliberately **not** included in `dataset/findings/README.md`'s corpus
overview table or confusion matrix, for any of the four runs. If the
narrated pairs alone were counted, they'd read as two more correct HIGH
classifications; if only the silent-stub pairs were counted, two correct
MEDIUMs — either framing would overstate what happened, since the honest
finding is the *gap between them*, not either result in isolation. The
honest summary: an attempted sixth-incident reconstruction that hit a
real, well-documented sourcing wall, produced a methodologically invalid
result for its original purpose (testing `_apply_dimension_floor`), and
a deliberate follow-up then turned that invalidity into a controlled,
quantified finding about the evaluation method itself — narration inside a
diff measurably inflates the score, by 20–28.5 points in this case, on top
of a real, defensible, lower-confidence structural signal that persists
even with zero narration. See `dataset/findings/README.md`'s overfitting
caveat for where this fits alongside the corpus's other open validity
questions.

## Third condition (2026-09-09): the same narrated files, comments stripped by the tool

The two conditions above bracket the effect but differ in more than one
way: the silent-stub trees hold genuinely empty files (the diff shows
`+0 lines`), while the narrated trees hold 14- and 9-line files whose every
line is a comment. `chainwatch diff --strip-comments` (added 2026-09-09;
`chainwatch.diff.preprocess`) removes whole-line comments from the diff
before the LLM sees it, which makes a third condition possible with no
hand-built files at all: the *narrated* trees exactly as committed in
`evidence/`, run through the real pipeline with the flag on. The LLM then
sees the real preinstall hook, the two new filenames, headers reading
`+14 lines` / `+9 lines`, and `(no diff content)` where the prose was — plus
one preamble line stating that 23 comment lines were removed. Same real
`from` tarballs, live feeds, one LLM call per pair (`claude-sonnet-4-6`).

| pair | condition | risk | severity | llm_base_score | install_hooks | network_calls | obfuscation |
|---|---|---|---|---|---|---|---|
| `coa 2.0.2 → 2.0.3` | narrated placeholder | 56.0 | HIGH | 51.0 | 10.0 / 0.9 | 8.0 / 0.4 | 7.0 / 0.4 |
| `coa 2.0.2 → 2.0.3` | **narrated, `--strip-comments`** | **43.5** | **MEDIUM** | **38.5** | 8.0 / 0.7 | 5.0 / 0.3 | 4.0 / 0.2 |
| `coa 2.0.2 → 2.0.3` | silent stub | 36.0 | MEDIUM | 31.0 | 8.0 / 0.7 | 3.0 / 0.2 | 3.0 / 0.2 |
| `rc 1.2.8 → 1.2.9` | narrated placeholder | 60.0 | HIGH | 55.0 | 10.0 / 0.9 | 9.0 / 0.4 | 8.0 / 0.4 |
| `rc 1.2.8 → 1.2.9` | **narrated, `--strip-comments`** | **46.5** | **MEDIUM** | **41.5** | 8.0 / 0.8 | 5.0 / 0.3 | 4.0 / 0.2 |
| `rc 1.2.8 → 1.2.9` | silent stub | 31.5 | MEDIUM | 26.5 | 8.0 / 0.7 | 2.0 / 0.2 | 2.0 / 0.2 |

Reports: `inconclusive-report-coa-2.0.2-to-2.0.3-STRIPPED.json` and
`inconclusive-report-rc-1.2.8-to-1.2.9-STRIPPED.json` — still excluded
from every corpus count by filename, like the four before them.

What it shows:

- **The flag reproduces the bucket flip.** Removing the prose alone takes
  both pairs from HIGH to MEDIUM — 12.5 points on `coa`, 13.5 on `rc` —
  with `install_hooks` dropping from 10.0/0.9 to 8.0 and every inferred
  dimension losing both score and confidence. Same direction as the
  hand-built silent-stub comparison, now obtainable on any pair with one
  flag instead of a rebuilt directory.
- **It also separates two things the silent-stub condition conflated.**
  The stripped scores sit 7.5 (`coa`) and 15.0 (`rc`) points *above* the
  silent stubs. The model's reasoning explains the gap in its own words:
  it reads "14 lines added, content not shown" as suspicious opacity —
  *"This opacity itself is a concern"*, *"The absence of visible content
  is itself suspicious"* — and scores `network_calls`/`obfuscation` at
  5.0/4.0 on that basis, where genuinely empty files drew 2.0–3.0. So of
  the 20–28.5 point narrated-vs-silent gap measured on 2026-08-11, the
  prose accounts for 12.5–13.5 points and the model's reaction to hidden
  content for the remaining 7.5–15.0. The second path is worth naming on
  its own: it is leakage from *our* tooling's notice text (`(no diff
  content)`, the line counts), not from anything an attacker wrote.
- **The structural signal survives unchanged.** `install_hooks` lands at
  8.0 in both non-narrated conditions with the same reasoning — a
  preinstall hook plus compile scripts on a package with no build step —
  consistent with the 2026-08-11 conclusion that zero narration produces
  calibrated, not zero, suspicion.
- **Still not evidence about `_apply_dimension_floor`.** No dimension
  reaches the 9.0/0.9 trigger in the stripped condition, and both base
  scores already clear 30, so the rule stays unexercised; the count of
  out-of-corpus runs where it has fired remains zero.

Caveats: every condition is a single run, and none has been repeated to
measure run-to-run variance, so differences of a few points between
conditions should not be over-read. And, as before, none of this
separates "the model believes the prose" from "the model recognises a
famous 2021 incident" — stripping removes the prose but not the package
names.
