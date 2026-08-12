# coa / rc — chainwatch findings

**Not a canonical corpus entry — read `SOURCING.md` first.** Both reports
here (`inconclusive-report-coa-2.0.2-to-2.0.3-PARTIAL.json`,
`inconclusive-report-rc-1.2.8-to-1.2.9-PARTIAL.json`) are excluded from
every corpus-wide precision/recall statistic in `dataset/findings/README.md`
by filename convention. This document exists because the *attempt*
produced a genuinely useful, unexpected finding — not the one it was
built to test.

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

## Why this is a real, if narrow, finding

**A diff whose only "evidence" of maliciousness is descriptive prose — even
prose that plainly labels itself a placeholder, written by us, not an
attacker — is enough to drive a HIGH severity score, with no real payload
present at all.** This wasn't a training-data-recognition question we set
out to test (we can't cleanly separate "the model recognises this famous,
well-documented 2021 incident by name" from "the model is taking our
placeholder comments' claims at face value" — both are plausible and both
would produce the same observed behaviour; this experiment doesn't
distinguish them). But the mechanism that's directly demonstrated, in the
model's own reasoning text, doesn't require assuming training-data recall
at all: **narrative description embedded in a diff substitutes for the
code it describes.**

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

`install_hooks=10.0` at confidence 0.9 technically meets
`_apply_dimension_floor`'s trigger threshold on both pairs — and, exactly
as with `ctx`'s `0.1.2-1` pair, **the floor rule never fires**, because
`llm_base_score` already clears 30 (51.0 and 55.0) before the floor rule
is even consulted. This is now the *second* out-of-corpus-styled test
where a confidently-scored dimension reaches the floor's trigger condition
without ever needing the floor — both times because realistic multi-signal
attacks (even a placeholder-narrated one) tend to push several correlated
dimensions up together, not just one. `_apply_dimension_floor` remains
validated only against the two cases it was built from
(`colors`, node-ipc's diluted registry pair) — see recommendation #7 in
`dataset/findings/README.md`, still open.

## Position in the detection matrix

Deliberately **not** included in `dataset/findings/README.md`'s corpus
overview table or confusion matrix. If it were counted, it would read as
two more correct HIGH classifications — but that would overstate what
happened. The honest summary: an attempted sixth-incident reconstruction
that hit a real, well-documented sourcing wall, produced a methodologically
invalid result for its original purpose, and surfaced a more interesting
finding about the evaluation method itself along the way. See
`dataset/findings/README.md`'s overfitting caveat for where this fits
alongside the corpus's other open validity questions.
