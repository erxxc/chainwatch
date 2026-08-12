# node-ipc — chainwatch findings

Two pairs, both live pipeline runs (real LLM + real feeds), `claude-sonnet-4-6`:
one registry-fetched (2026-08-07), one a directory-level reconstruction of
the actual wiper payload (also 2026-08-07 — see "Reconstructed pair" below
and `SOURCING.md` for exactly how, and why it never became an installable
package). See `evidence/` for the recovered payload itself.

**Update 2026-08-10:** both pairs were rerun against the fully fixed code —
`resource_exhaustion` (a sixth risk dimension) and a same-day
`definitive_dimension_floor` aggregator rule, both described in
`malicious/colors/FINDINGS.md`. The `10.1.0 → 11.0.0` registry pair got a
real, fresh `chainwatch diff npm node-ipc 10.1.0 11.0.0` run (no
reconstruction needed, both versions are still live); the
`10.1.0 → 10.1.1` reconstructed pair got the same evidence-splice rerun
against the real fixed code (no monkey-patching). **New results: `11.0.0`
MEDIUM (30.0)**, up from LOW (29.5); **`10.1.1` stays HIGH but moves to
62.5**, down from 69.0 — the weight cuts to `network_calls`/`obfuscation`
(25%→20% each, to make room for the new dimension) outweigh a modest new
`resource_exhaustion=4.0` contribution (the model reasonably reads the
recursive file-wipe as having some resource-abuse character, though it
isn't this attack's primary shape). The pre-fix `11.0.0` report is
preserved at `pre-dos-fix-report-10.1.0-to-11.0.0.json`; `10.1.1`'s
severity bucket never changed (HIGH before and after), so no separate
archive was made for it — see `dataset/findings/README.md` "Reproducing
this analysis" for the full inventory of what was and wasn't rerun.

## Summary

| pair | role | risk | LLM base | feed-adjusted | OSV | Rekor | Scorecard |
|---|---|---|---|---|---|---|---|
| `10.1.0 → 11.0.0` *(rerun post-fix)* | contains the compromised `peacenotwar` dependency (registry-fetched) | **MEDIUM** | 19.5 | 30.0 | suspicious (GHSA-3mpp-xfvh-qh37) | no_data | 4.0/10 clean |
| `10.1.0 → 10.1.1` *(reconstructed, rerun post-fix)* | **the actual destructive wiper** | **HIGH** | **62.5** | 62.5 | suspicious (GHSA-97m3-w2cp-4xx6) | no_data | 4.0/10 clean |

Tarball SHA256 (verified at fetch time — `11.0.0` pair only; the
reconstructed pair has no real tarball, see below). Unchanged by the
rerun — same real tarballs, same registry, only the scoring logic changed:

- `10.1.0`: `3ae711f24ce5e31b696e4228452258954b1cbc0983fdb345b0755cd9e9366a2b`
- `11.0.0`: `24388fb7f28c167afd426b17667a2563ec6f094a7e83f3aef84d48a73b11a37b`

## The reconstructed pair: 62.5/HIGH (post-fix), confirming the diagnosis below

Section "2" below predicted, before this was first run, that reconstructing
the actual wiper "would very plausibly score much higher... this pair
likely *understates* what the full incident would score." That prediction
was confirmed with a real run, not a guess, and holds after the 2026-08-10
rerun too:

| dimension | `11.0.0` (peacenotwar remnant, post-fix) | `10.1.1` (full wiper, reconstructed, post-fix) |
|---|---|---|
| network_calls | 1.0 | **10.0** (corpus max) |
| obfuscation | 2.0 | **10.0** (corpus max) |
| env_conditional | 3.0 | 7.0 |
| install_hooks | 0.0 | 2.0 |
| dependency_changes | **9.0** | 1.0 |
| resource_exhaustion | 0.0 | 4.0 |
| **llm_base_score** | 19.5 | **62.5** |

The two payload tiers are structurally different attacks on the same
dimensions the LLM is asked to score, and the LLM told them apart correctly
without being pointed at the difference: `11.0.0` is a *dependency* whose
own code writes a file — no network call, no encoding, so
`dependency_changes` carries the signal. `10.1.1` is inline code that
*makes an obfuscated geo-IP HTTP call and gates a filesystem wipe on the
response* — `network_calls` and `obfuscation` both hit the ceiling instead.
The free-text summary for the reconstructed pair, original run: *"This is a
confirmed, unambiguous malicious payload with a severity score of 10."*
Post-fix rerun: *"This is a confirmed malicious supply chain attack...
[ssl-geospec.js] is a deliberately obfuscated wiper payload."* Same
verdict, independently reached twice — and the composite score agrees
(HIGH) both times.

**This is the corpus's clearest evidence that the `11.0.0` near-miss (below)
is a diluted-artifact problem, not a detection-capability problem.** Given
the complete attack, chainwatch's LLM layer rates it correctly and the
aggregator's bucketing agrees. See `SOURCING.md` for exactly how the
reconstruction was built (the real `10.1.0` tarball plus the exact verified
git diff, applied as two local directories — never packaged, never served).

## The headline result: 29.5 was 0.5 points from MEDIUM — now it's there

**This was the most significant single finding in the whole dataset, and
it's the case that most directly motivated the 2026-08-10 aggregator fix.**
`10.1.0 → 11.0.0` is a real, currently-available-on-the-registry diff that
adds the actual compromised `peacenotwar` dependency from this incident —
not a reconstruction, not an adjacent benign pair. chainwatch's LLM layer
correctly identified it, by name, with high stated confidence, in both the
pre-fix and post-fix runs:

> "This diff represents the well-documented node-ipc supply chain attack
> from 2022 (versions 10.1.1/11.0.0), where maintainer RIAEvangelist
> introduced the 'peacenotwar' dependency... constitutes a clear and
> confirmed supply chain compromise with high confidence."

And yet the pre-fix composite score was **29.5 — LOW** (severity buckets:
LOW 0–29, MEDIUM 30–54, per `models.py`). The free-text summary said "clear
and confirmed compromise, high confidence"; the bucketed severity said
"LOW." Those two statements were in real tension, and a reader looking only
at `severity` (the field most likely to drive a threshold-based CI gate,
e.g. `chainwatch diff ... --threshold`) would have seen this pass as
low-risk.

**This was never a case chainwatch missed** — the dimension scores and the
free-text summary both showed the model correctly reasoning about a genuine
compromise. It was a case where the *aggregation and bucketing* undersold
what the model itself found. Contributing factors, pre-fix:

- `dependency_changes` scored 9.0/10 (correctly, and the highest single
  dimension score anywhere in this dataset outside the benign corpus) but
  was weighted only 15%, capping its ceiling contribution at 1.5/10 of the
  final 0–100 base score.
- `env_conditional` scored 4.0/10 for the existence-check-before-write
  persistence pattern — reasonable, but modest.
- OSV correctly returned `GHSA-3mpp-xfvh-qh37` ("node-ipc behavior change,"
  the actual advisory for this exact version range, `>=11.0.0 <12.0.0`) —
  but it's a GHSA, not a `MAL-*` ID, so the aggregator's `malicious_floor`
  rule (which would force the score to ≥55) never fires, before or after
  the fix. The advisory itself is rated "low severity" upstream too (no
  CWE/CVE assigned), which is arguably *correct* for the desktop-notice-only
  behavior actually present in `11.0.0` — the advisory undersold the
  incident the same way chainwatch's severity bucket did, for the same
  underlying reason: what's in `11.0.0` really is milder than what shipped
  in `10.1.1`/`10.1.2`.
- Scorecard 4.0/10 → neither the `>7` mitigant nor the `<4` amplifier
  fires (right at the boundary), contributing 0, before or after the fix.

**Rerun 2026-08-10 against the real fixed code** — same real tarballs, a
fresh LLM call, the new weight matrix, the new `definitive_dimension_floor`
rule:

| dimension | score | confidence | weight (post-fix) |
|---|---|---|---|
| dependency_changes | 9.0 | 1.00 | 10% |
| env_conditional | 3.0 | 0.8 | 15% |
| obfuscation | 2.0 | 0.8 | 20% |
| network_calls | 1.0 | 0.8 | 20% |
| resource_exhaustion | 0.0 | 0.9 | 20% |
| install_hooks | 0.0 | 0.9 | 15% |

`llm_base_score` = 19.5 — *lower* than the pre-fix 29.5, because
`dependency_changes`'s weight actually dropped (15%→10%) to make room for
`resource_exhaustion`, which scores 0 here (correctly — this attack isn't
DoS-shaped). But `dependency_changes` at 9.0/10, confidence 1.00, trips the
new `definitive_dimension_floor` rule: `+10.5 → 30.0`. Scorecard stays a
no-op (4.0, right at the boundary). **Final: 30.0, MEDIUM.**

> "`dependency_changes` scored 9.0/10 at confidence 1.00 — raised score to
> floor 30"

**Worth stating plainly:** this is the one entry in the corpus where a
*lower* per-dimension weight and a *higher* final severity happened at the
same time. The weight cut would, on its own, have made this pair's
LOW-vs-MEDIUM problem strictly worse (13.5-point contribution → 9.0-point
contribution); it's specifically the new floor rule — designed for colors,
not for this pair — that fixes it. Recommendation #3 in
`dataset/findings/README.md` proposed revisiting `dependency_changes`'s
weight "or a special-case modifier" for exactly this diluted-pair problem;
the modifier path is what ended up shipping, as a side effect of a fix
built for a completely different incident.

## Why the `11.0.0` pair originally ran without the wiper (now resolved above)

`10.1.1`/`10.1.2`/`10.1.3` — the versions with the actual file-wiping
payload — are unpublished and not registry-fetchable (see `SOURCING.md`).
`11.0.0` was, at the time, the closest available version that still carried
the `peacenotwar` dependency (minus the destructive, geo-gated wiper — see
`evidence/README.md` for exactly what was removed between `10.1.2` and
`11.0.0`, which we did not independently diff). The prediction made here —
that a reconstructed wiper pair would score meaningfully higher — is now
confirmed with a real run; see the reconstructed-pair section above.

## Cross-cutting observations

### 1. First registry-diffable real attack in this dataset

event-stream and ua-parser-js both require secondary-source reconstruction
because their malicious releases are structurally gone from npm. node-ipc's
`peacenotwar` tier is not — it's sitting on the registry as `11.0.0` today,
making this the first pair in the corpus where "did chainwatch's registry
pipeline actually see the attack" has a real, non-hypothetical answer: yes,
and it correctly explained what it saw. Pre-2026-08-10 it scored LOW despite
that; post-fix it scores MEDIUM — see "The headline result" above.

### 2. `dependency_changes`'s 15% weight was a real bottleneck here — since resolved

This was the clearest example in the corpus of the weight matrix capping a
correctly-identified signal. Per `RiskDimension.weighted_contribution`
(`score × weight × 10`), the full pre-fix breakdown of the 29.5 base score:

| dimension | score | weight (pre-fix) | contribution |
|---|---|---|---|
| dependency_changes | 9.0 | 0.15 | **13.5** |
| env_conditional | 4.0 | 0.15 | 6.0 |
| network_calls | 2.0 | 0.25 | 5.0 |
| obfuscation | 2.0 | 0.25 | 5.0 |
| install_hooks | 0.0 | 0.20 | 0.0 |
| **total** | | | **29.5** |

`dependency_changes` — the model's highest score anywhere in the corpus
outside the benign baseline, and the dimension that directly names the
compromised `peacenotwar` package — was also the single largest contributor
at 13.5 points, but its 15% weight capped what a 9/10 finding could do to
the composite. Even a maxed-out 10/10 on this one dimension alone (15.0
points) wouldn't have reached MEDIUM without help from the others.

**Resolved 2026-08-10, but not the way this section originally
proposed.** The write-up's recommendation #3
(`dataset/findings/README.md`) floated two options: revisit the weight, or
add a "known-compromised transitive dependency" special case. What actually
shipped was neither, directly — `dependency_changes`'s weight was cut
further (15%→10%, to make room for the new `resource_exhaustion`
dimension), which alone would have made this pair's problem *worse*
(13.5-point contribution → 9.0). What fixes it instead is the new
`definitive_dimension_floor` rule, built for a different incident (colors)
entirely: any dimension scoring ≥9.0 at confidence ≥0.9 floors the
composite to MEDIUM, and `dependency_changes=9.0, confidence=1.00` clears
that bar on its own. Same practical outcome recommendation #3 asked for
(this pair now reads correctly), reached by a more general mechanism than
either option it originally proposed.
