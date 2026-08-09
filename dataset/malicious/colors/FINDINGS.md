# colors — chainwatch findings

Two pairs, both live pipeline runs (real LLM + real feeds), `claude-sonnet-4-6`:
one registry-fetched benign control (2026-08-07), one a directory-level
reconstruction of the actual sabotage commit (2026-08-08 — see "The
reconstructed pair" below and `SOURCING.md` for exactly how, and why it
never became an installable package). See `evidence/` for the recovered
payload itself.

## Summary

| pair | role | risk | LLM base | feed-adjusted | OSV | Rekor | Scorecard |
|---|---|---|---|---|---|---|---|
| `1.3.3 → 1.4.0` | benign control | LOW | 0.0 | 5.0 | clean | no_data | 2.2/10 suspicious |
| `1.4.0 → 1.4.44-liberty-2` *(reconstructed)* | **the actual sabotage commit** | **LOW** | 2.5 | 7.5 | suspicious (2× GHSA) | no_data | 2.2/10 suspicious |

Tarball SHA256 (verified at fetch time — benign-control pair only; the
reconstructed pair has no real tarball, see below):

- `1.3.3`: `ba236fffba0bbee00ba9b3209236e2f0718eaa37d0e8812f6c9f8f4f9551950b`
- `1.4.0`: `b50eb83eda7cc37519809e240338fded8e625169945bbfe6d4156445c6610498`

## The reconstructed pair: LOW, and this time it's not a fetching problem

**This is the corpus's most important negative result.** Unlike node-ipc's
reconstruction (`malicious/node-ipc/FINDINGS.md`), where the composite score
jumped from LOW to HIGH once the *complete* attack was available, colors's
reconstruction is the complete attack from the start — real sabotage
commit, byte-verified against a base tarball that's still live on the
registry — and it **still scores LOW (7.5/100)**.

All five LLM dimensions scored at or near zero:

| dimension | score | reasoning (abridged) |
|---|---|---|
| network_calls | 0.0 | "No network calls... limited to console.log output" |
| obfuscation | 1.0 | "No base64 encoding, eval, or dynamic require patterns" |
| install_hooks | 0.0 | "No changes to package.json, no postinstall/preinstall" |
| env_conditional | 0.0 | "No environment variable checks... present" |
| dependency_changes | 0.0 | "No changes to package.json dependencies" |

Every single dimension is individually correct — the diff genuinely
contains none of those five patterns. **The free-text summary knows better
than the dimensions do:**

> "...the infinite loop... is a denial-of-service / resource exhaustion
> pattern that will hang any process that imports this package... This is
> consistent with the real-world incident where the colors package author
> intentionally sabotaged their own package. The change is disruptive and
> malicious in effect... even without classic supply chain exfiltration
> indicators."

The only reason the composite score is non-zero at all is the unrelated
`scorecard_poor +5` modifier (the project's long-term neglect, not the
diff). **This is a taxonomy gap, not a calibration or fetching gap.**
chainwatch's five risk dimensions — network calls, obfuscation, install
hooks, env conditionals, dependency changes — were shaped around
data-exfiltration and credential-theft attacks (exactly what event-stream,
ua-parser-js, and node-ipc's wiper are). None of them ask "does this code
terminate," "does it consume unbounded resources," or "is it a denial-of-
service payload." A protestware DoS attack is structurally invisible to
this dimension set no matter how completely the diff is presented to the
model — which the node-ipc comparison below makes concrete.

## Per-pair detail

### 1.3.3 → 1.4.0 — benign control

- **What changed.** Adds bright/high-intensity ANSI color codes
  (`brightRed`, `brightGreen`, etc.) and matching bright background colors
  to `lib/styles.js`, updates the random-color map, and fixes a stylize
  fallback for non-ANSI styles. Entirely ordinary feature work.
- **LLM.** All five dimensions scored 0. Correctly read as routine.
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
  friction being a legitimate long-term-maintenance signal.

### 1.4.0 → 1.4.44-liberty-2 *(reconstructed)* — the real attack, scored LOW

- **What changed.** Exactly what shipped: a new `lib/custom/american.js`
  (ASCII flag + "LIBERTY" banner) and a ten-line addition to `lib/index.js`
  that unconditionally runs an infinite `for` loop on `require('colors')`.
  See "The reconstructed pair" above for the full dimension breakdown and
  the free-text summary, which correctly identifies the incident by name.
- **OSV.** `suspicious` — both real advisories for this incident
  (`GHSA-5rqg-jm4f-cqx7`, `GHSA-gh88-3pxp-6fm8`), correctly resolved against
  the reconstructed version string. Neither is `MAL-*`, so the aggregator's
  `malicious_floor` rule doesn't fire — consistent with every other incident
  in this corpus (see `dataset/findings/README.md` RQ1/RQ4).
- **Scorecard.** Identical to the benign-control pair (2.2/10, suspicious,
  `+5` modifier) — expected, since Scorecard evaluates the repository's
  overall hygiene, not this specific diff.
- **Take.** The composite score (7.5) is barely different from the benign
  control's (5.0) — both are dominated by the same Scorecard modifier, and
  the actual attack contributes only 2.5 points of LLM base score on top.
  For a CI gate, this diff would be indistinguishable from routine
  maintenance. That's the finding.

## Cross-cutting observations

### 1. Two "complete attack, reconstructed" results in this corpus disagree — and that's informative

node-ipc's reconstruction (`malicious/node-ipc/FINDINGS.md`) went from a
diluted-remnant LOW (29.5) to a complete-attack HIGH (69.0) — a fetching-
completeness story with a happy ending once the full payload was available.
colors's reconstruction *is* the full payload from the start and stays LOW
(7.5). The difference isn't reconstruction fidelity (both were verified
byte-for-byte against real base tarballs) — it's that node-ipc's payload
matches chainwatch's dimension taxonomy (network calls, obfuscation, env
conditionals) and colors's doesn't (denial-of-service via infinite loop
isn't network activity, isn't obfuscated, isn't env-gated — it's just
control flow that never terminates). Two reconstructions, two different
kinds of miss: one about *what got fetched*, one about *what the tool knows
to look for*.

### 2. This is the "cleanest" attack in the corpus, and also the least severe — but not undetected-in-principle

The payload here is a denial-of-service (infinite loop), not data theft or
destructive file operations — meaningfully less dangerous than event-stream
(wallet credential theft), ua-parser-js (cryptominer + credential stealer),
or node-ipc (destructive file wipe). Lower severity in impact, but the LLM
free-text summary shows the *model* isn't fooled — it names the real
incident and calls the change "malicious in effect." The gap is entirely in
how that recognition does (or doesn't) propagate into the five numeric
dimensions the composite score is built from.

## Position in the detection matrix

| package | malicious version available? | did diff-level analysis catch it? |
|---|---|---|
| colors | Yes — reconstructed from verified git history, byte-checked against a live base tarball | **No** — LOW (7.5/100) despite being the complete, real attack. Free-text summary correctly identifies it; none of the five scored dimensions do. A taxonomy gap (no DoS/resource-exhaustion dimension), not a fetching or calibration gap — contrast with `node-ipc`, where reconstruction *did* flip the result to HIGH. |

Same caveat as event-stream and ua-parser-js: the available registry pair
validates non-false-positive behaviour on the pre-incident state, not
detection. Unlike those two, though, the sabotage commit *is* fully
recoverable and statically analysable outside chainwatch's registry-fetch
pipeline — see `evidence/`.
