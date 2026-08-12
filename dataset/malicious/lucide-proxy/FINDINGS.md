# Lucide Proxy — chainwatch findings

Two pairs, both directory-level reconstructions (real LLM + real feeds),
`claude-sonnet-4-6`, run 2026-08-11 as recommendation #7's answer to
`ctx`'s open question: a real, independently-sourced attack shaped to
actually exercise `resource_exhaustion`. See `SOURCING.md` for the
incident and why it was picked; `evidence/README.md` for exactly what's
real (both payload files, byte-verified) versus synthetic (the
`package.json` scaffold — no real tarball exists on either side for this
incident).

**Read this whole document before citing the headline number.** Both
pairs land at 55.0/100, HIGH — but that number is misleading on its own.
It's entirely a floor imposed by OSV's `malicious_floor` feed rule, not by
`resource_exhaustion` or `_apply_dimension_floor`. The real result is one
level down, in the dimension table.

## Summary

| pair | risk | severity | llm_base_score | resource_exhaustion | floor modifier |
|---|---|---|---|---|---|
| `cdn.js` only | 55.0 | HIGH | 44.5 | **8.0 / conf 0.95** | `osv/malicious_floor` +10.5 |
| `cdn.js` + `sw.js` | 55.0 | HIGH | 37.0 | **6.0 / conf 0.9** | `osv/malicious_floor` +18.0 |

Both pairs hit the exact same final score (55.0) because
`_apply_feed_modifiers`' `malicious_floor` rule floors to a flat 55
whenever OSV reports `MAL-*`, regardless of the LLM base score underneath
— `44.5 + 10.5 = 55.0` and `37.0 + 18.0 = 55.0` are two different-sized
jumps landing on the same number by construction, not a coincidence to
read anything into.

## What this incident actually answers

**`resource_exhaustion` generalises to a genuinely different DoS shape.**
Every prior test of this dimension in this corpus (`colors`'s original
incident, the corpus-wide false-positive sweep on `lodash`, `ctx`'s
correct 0.0) involved either a *synchronous, blocking* infinite loop or no
DoS pattern at all. `cdn.js` is neither: an `async`, *non-blocking*
`setInterval` that fires forever with no exit condition. The model scored
it 8.0/10 (cdn.js-only pair) and 6.0/10 (cdn.js+sw.js pair), both at high
confidence (0.95, 0.9), with reasoning that names the exact right pattern:

> *"cdn.js wraps the fetch call in `setInterval(..., 2000)`, which fires
> every 2 seconds indefinitely with no termination condition, no stop
> mechanism, and no rate limit..."*

That's not the model pattern-matching "this looks like `colors`" — the
mechanisms are structurally different (async interval vs. sync loop,
network-bound vs. CPU-bound) and the reasoning is specific to what's
actually in this diff. This is the first time in the corpus's history that
`resource_exhaustion` has been validated against a DoS shape it wasn't
designed around, and it worked.

## What this incident does *not* answer

**`_apply_dimension_floor` still hasn't fired on anything outside the two
cases that motivated it.** The floor rule triggers on any dimension
scoring ≥9.0 at confidence ≥0.9. `resource_exhaustion` reached 8.0/0.95 on
the cleaner pair — real, strong, but short of the threshold by a full
point. Recommendation #7's other open question — does the floor rule
generalise — remains genuinely untested. Across every out-of-corpus run
attempted so far (`ctx`'s two pairs, `coa`/`rc`'s four conditions, and now
these two), the floor rule has fired exactly zero times outside `colors`
and node-ipc's diluted registry pair.

**The composite score doesn't actually depend on either mechanism here.**
OSV's `malicious_floor` feed rule reaches the same 55.0 regardless of what
`resource_exhaustion` or the floor rule do — a real, fast `MAL-*` hit (see
"A fast `MAL-*` hit" below) makes this incident, in the end, a feed-carried
result like `flatmap-stream`, not an LLM-carried or aggregator-carried one.
If OSV had been slower (as it was for `flatmap-stream`, `colors`, and
every other incident in this corpus except this one), the `cdn.js`-only
pair's `llm_base_score` alone (44.5) would still clear MEDIUM comfortably
on `resource_exhaustion`'s contribution — but wouldn't reach HIGH without
the feed's help.

## Per-pair detail

### `cdn.js` only

- **What's diffed.** One new file, `cdn.js` (231 bytes, real, byte-verified
  — see `evidence/README.md`) added to a synthetic minimal `package.json`
  scaffold. 6 total diff lines.
- **LLM dimensions:**

  | dimension | score | confidence | reasoning (abridged) |
  |---|---|---|---|
  | network_calls | 8.5 | 0.95 | "a repeated, unconditional... fetch call to 'https://verify.titaniumnetwork.org/callback/'..." |
  | obfuscation | 3.0 | 0.8 | "The URL path is partially randomised using Math.random()... makes static analysis harder. This is mild..." |
  | install_hooks | 2.0 | 0.6 | "No explicit preinstall/postinstall script changes... would need to be imported or executed somewhere..." |
  | env_conditional | 1.0 | 0.85 | "No environment variable reads or conditional branching..." |
  | dependency_changes | 1.0 | 0.7 | "No new dependencies are visible in the diff. The fetch call uses the built-in Fetch API..." |
  | resource_exhaustion | **8.0** | **0.95** | "wraps the fetch call in `setInterval(..., 2000)`, which fires every 2 seconds indefinitely with no termination condition, no stop mechanism, and no rate limit" |

  `llm_base_score = 44.5`. `+10.5` `osv/malicious_floor` → `risk_score =
  55.0, HIGH`.
- **Free text:** *"This combination of persistent, unbounded network
  beaconing with a randomised URL path and no-referrer/no-cors settings
  strongly suggests tracking, callback verification, or exfiltration
  infrastructure... should be treated as likely malicious and blocked."*
  Notably, the model did **not** name this incident by name (unlike every
  other reconstruction in this corpus, where the free text reliably named
  the real incident) — plausible read: this is a much less
  famous/documented incident than `colors`/`node-ipc`/`ua-parser-js`, so
  there's less to recognise from training data, and the classification
  here is closer to "code analysis alone" than anything else in this
  corpus. Worth reading alongside `coa`/`rc`'s narrative-leakage finding —
  the opposite condition (no fame to lean on) produces a plausible attack
  read purely from the code's own structure.
- **OSV.** `malicious`, `MAL-2026-10305` — a real `MAL-*` hit, fast (see
  `SOURCING.md`).
- **Rekor.** `no_data` — no Sigstore provenance attestation for
  `ilovefemboys@2.0.0` (expected; this was never a signed release in the
  first place).
- **Scorecard.** `no_data` — could not resolve a GitHub repo for
  `ilovefemboys` (correct — there wasn't a real source repo for this
  package to begin with, unlike `ctx`'s case where a real-but-unresolvable
  repo exists).

### `cdn.js` + `sw.js`

- **What's diffed.** Both real recovered files added together — `cdn.js`
  (unchanged) plus `sw.js` (7,574 bytes, the ad-hijacking service worker).
  257 total diff lines.
- **LLM dimensions:**

  | dimension | score | confidence | reasoning (abridged) |
  |---|---|---|---|
  | network_calls | 8.0 | 0.95 | "cdn.js adds a setInterval that fires every 2000ms and calls fetch()... This is a re[peated pattern]" |
  | obfuscation | 2.0 | 0.85 | "No base64, eval, or dynamic require patterns... relatively readable... random path generation... mild[ly obfuscating]" |
  | install_hooks | 1.0 | 0.8 | "No package.json changes... no preinstall/postinstall script additions... added files are JS modules that would n[eed a loader]" |
  | env_conditional | 1.0 | 0.85 | "No environment variable reads or platform/CI branching logic..." |
  | dependency_changes | 2.0 | 0.6 | "sw.js references './runtime/scramjet/scramjet.all.js' via importScripts, implying a runtime dependency on the Scramjet library..." |
  | resource_exhaustion | **6.0** | **0.9** | "cdn.js uses setInterval(..., 2000) with no clear termination condition... unbounded network drain..." |

  `llm_base_score = 37.0`. `+18.0` `osv/malicious_floor` → `risk_score =
  55.0, HIGH`.
- **Take: `resource_exhaustion` scored *lower* with more real evidence
  present, not higher.** 8.0 (cdn.js alone) → 6.0 (cdn.js + sw.js) is a
  genuinely interesting, honest finding, not something to paper over.
  `sw.js` doesn't touch DoS/resource-exhaustion at all — its presence
  shouldn't logically lower that specific dimension's score. The most
  likely explanation, visible in the free text (below), is a framing
  effect: with `sw.js` present, the model reads the combination as "a
  proxy tool with a hijacking/adware layer" — a more *specific*, more
  *legitimate-shaped* narrative (real proxy engine, real service-worker
  patterns) that seems to have modestly diluted how anomalous `cdn.js`'s
  polling loop reads in isolation. This is worth flagging as a real
  calibration question for future work: does adding *more* real malicious
  context sometimes *reduce* an individual dimension's score by making the
  overall diff read as more "explicably complex" rather than more
  suspicious? This corpus can name the pattern; it can't yet explain it.
- **Free text:** *"...cdn.js installs a persistent setInterval beacon...
  constituting an unbounded network drain and potential
  tracking/exfiltration mechanism. sw.js registers a service worker that
  proxies web traffic through the Scramjet obfuscating proxy library and
  injects a JavaScript payload into every HTML response... a pattern
  consistent with adware or traffic-hijacking."* Correctly separates and
  names both real mechanisms distinctly — still doesn't name the incident.
- **OSV / Rekor / Scorecard.** Identical to the pair above (same package,
  same version, same feed queries).

## Cross-cutting observations

### 1. A fast `MAL-*` hit — the opposite of this corpus's other data point

Every malicious-labelled pair in this corpus prior to this one either
never reached `MAL-*` (5 of 6 prior incidents) or took nearly seven years
to get there (`flatmap-stream`). This incident's `MAL-2026-10305` landed
**2 days 17 hours** after the malicious version's npm publish, and days
after public disclosure. The credited sources —
`amazon-inspector` (automated scanning) and `ghsa-malware` — suggest this
reflects a newer, more automated detection pathway than the manual
advisory process that handled `event-stream` in 2018, not that this
incident was somehow more "obviously" malicious than the others. One fast
example and one seven-year-slow example is not enough to characterise a
trend — flagged as a real, dated data point for RQ1/RQ4, not a general
claim.

### 2. The reconstruction is honestly partial, and that's stated everywhere on purpose

This is the first incident in the corpus where **neither side has a real
recovered tarball** — `ctx` had this same "no live tarball" problem but
still had two *independently corroborating* full-tarball archives
(Software Heritage + Wayback). Here, only fragments of the real attack are
recoverable, and the single largest, most sophisticated component (the 5.4
MB obfuscated entry bundle JFrog fully analysed) isn't recoverable at all
— see `evidence/README.md`. What's scored here is real, byte-verified
campaign code, but it's a genuine subset, not the complete attack the way
`node-ipc`'s or `colors`'s reconstructions are. Read the result as "does
`resource_exhaustion` recognise this real pattern" — a question it
answers cleanly — not as "does chainwatch catch the complete Lucide Proxy
attack," a question this reconstruction can't fully answer either way.

## Position in the detection matrix

| package | malicious version available? | did diff-level analysis catch it? |
|---|---|---|
| Lucide Proxy (`ilovefemboys`) | Partially — no live/archived tarball on either side, but real, byte-verified payload fragments recovered independently from the campaign's own external C2 repositories (not from any vendor's writeup) | **Yes, both pairs, but feed-carried (55.0, HIGH via `osv/malicious_floor`), not floor-rule-carried.** The genuinely new result: `resource_exhaustion` scored 8.0/6.0 on a real, structurally different DoS shape (unbounded async polling, not a blocking loop) — the first out-of-corpus validation this dimension has had. `_apply_dimension_floor` still hasn't fired on anything outside the two cases that built it. See `dataset/findings/README.md` recommendation #7 for how this updates (and doesn't fully close) that question. |
