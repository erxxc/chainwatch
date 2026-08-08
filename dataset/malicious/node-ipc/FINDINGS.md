# node-ipc — chainwatch findings

One version pair run on 2026-08-07 with `claude-sonnet-4-6`, live pipeline
(real LLM + real feeds). See `SOURCING.md` for the incident background and
`evidence/` for the recovered destructive-wiper payload (not present in the
pair below — see why that matters).

## Summary

| pair | role | risk | LLM base | feed-adjusted | OSV | Rekor | Scorecard |
|---|---|---|---|---|---|---|---|
| `10.1.0 → 11.0.0` | **contains the compromised `peacenotwar` dependency** | LOW | 29.5 | 29.5 | suspicious (GHSA-3mpp-xfvh-qh37) | no_data | 4.0/10 clean |

Tarball SHA256 (verified at fetch time):

- `10.1.0`: `3ae711f24ce5e31b696e4228452258954b1cbc0983fdb345b0755cd9e9366a2b`
- `11.0.0`: `24388fb7f28c167afd426b17667a2563ec6f094a7e83f3aef84d48a73b11a37b`

## The headline result: 29.5 is 0.5 points from MEDIUM

**This is the most significant single finding in the whole dataset.**
`10.1.0 → 11.0.0` is a real, currently-available-on-the-registry diff that
adds the actual compromised `peacenotwar` dependency from this incident —
not a reconstruction, not an adjacent benign pair. chainwatch's LLM layer
correctly identified it, by name, with high stated confidence:

> "This diff represents the well-documented node-ipc supply chain attack
> from 2022 (versions 10.1.1/11.0.0), where maintainer RIAEvangelist
> introduced the 'peacenotwar' dependency... constitutes a clear and
> confirmed supply chain compromise with high confidence."

And yet the composite score is **29.5 — LOW** (severity buckets: LOW 0–29,
MEDIUM 30–54, per `models.py`). The free-text summary says "clear and
confirmed compromise, high confidence"; the bucketed severity says "LOW."
Those two statements are in real tension, and a reader looking only at
`severity` (the field most likely to drive a threshold-based CI gate, e.g.
`chainwatch diff ... --threshold`) would see this pass as low-risk.

**This is not a case chainwatch missed** — the dimension scores and the
free-text summary both show the model correctly reasoning about a genuine
compromise. It's a case where the *aggregation and bucketing* undersell
what the model itself found. Contributing factors:

- `dependency_changes` scored 9.0/10 (correctly, and the highest single
  dimension score anywhere in this dataset outside the benign corpus) but
  is weighted only 15%, capping its ceiling contribution at 1.5/10 of the
  final 0–100 base score.
- `env_conditional` scored 4.0/10 for the existence-check-before-write
  persistence pattern — reasonable, but modest.
- OSV correctly returned `GHSA-3mpp-xfvh-qh37` ("node-ipc behavior change,"
  the actual advisory for this exact version range, `>=11.0.0 <12.0.0`) —
  but it's a GHSA, not a `MAL-*` ID, so the aggregator's `malicious_floor`
  rule (which would force the score to ≥55) never fires. The advisory
  itself is rated "low severity" upstream too (no CWE/CVE assigned), which
  is arguably *correct* for the desktop-notice-only behavior actually
  present in `11.0.0` — the advisory undersells the incident the same way
  chainwatch's severity bucket does, for the same underlying reason: what's
  in `11.0.0` really is milder than what shipped in `10.1.1`/`10.1.2`.
- Scorecard 4.0/10 → neither the `>7` mitigant nor the `<4` amplifier
  fires (right at the boundary), contributing 0.

**Worth stating plainly for the paper:** the free-text `llm_summary` field
contains a more accurate risk assessment than the bucketed `severity` field
does, for this diff. A precision/recall table built purely from
`severity` buckets would score this as a false negative on a genuinely
correctly-reasoned detection.

## Why this pair, not the destructive-wiper versions

`10.1.1`/`10.1.2`/`10.1.3` — the versions with the actual file-wiping
payload — are unpublished and not registry-fetchable (see `SOURCING.md`).
`11.0.0` is the closest available version that still carries the
`peacenotwar` dependency (minus the destructive, geo-gated wiper — see
`evidence/README.md` for exactly what was removed between `10.1.2` and
`11.0.0`, which we did not independently diff). If the destructive versions
were reconstructed and run through the pipeline, the `network_calls` and
`env_conditional` dimensions would very plausibly score much higher than
they do here, given the geo-IP HTTP call and the country-based branch —
this pair likely *understates* what the full incident would score.

## Cross-cutting observations

### 1. First registry-diffable real attack in this dataset

event-stream and ua-parser-js both require secondary-source reconstruction
because their malicious releases are structurally gone from npm. node-ipc's
`peacenotwar` tier is not — it's sitting on the registry as `11.0.0` today,
making this the first pair in the corpus where "did chainwatch's registry
pipeline actually see the attack" has a real, non-hypothetical answer: yes,
and it correctly explained what it saw, but scored it LOW.

### 2. `dependency_changes`'s 15% weight is a real bottleneck here

This is the clearest example yet in the corpus of the weight matrix capping
a correctly-identified signal. Per `RiskDimension.weighted_contribution`
(`score × weight × 10`), the full breakdown of the 29.5 base score:

| dimension | score | weight | contribution |
|---|---|---|---|
| dependency_changes | 9.0 | 0.15 | **13.5** |
| env_conditional | 4.0 | 0.15 | 6.0 |
| network_calls | 2.0 | 0.25 | 5.0 |
| obfuscation | 2.0 | 0.25 | 5.0 |
| install_hooks | 0.0 | 0.20 | 0.0 |
| **total** | | | **29.5** |

`dependency_changes` — the model's highest score anywhere in the corpus
outside the benign baseline, and the dimension that directly names the
compromised `peacenotwar` package — is also the single largest contributor
at 13.5 points, but its 15% weight caps what a 9/10 finding can do to the
composite. Even a maxed-out 10/10 on this one dimension alone (15.0
points) wouldn't reach MEDIUM without help from the others. Worth
revisiting the weight matrix, or adding a "known-compromised transitive
dependency" special case, before publication.
