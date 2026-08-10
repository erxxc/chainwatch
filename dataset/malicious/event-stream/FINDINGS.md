# event-stream — chainwatch findings

Two version pairs were run on 2026-05-23 with `claude-sonnet-4-6` as the
analyser model. See `SOURCING.md` for why the actual malicious release
(`3.3.6`) and the payload package (`flatmap-stream`) could not be analysed
*at the registry level*.

**Update 2026-08-07:** the actual `flatmap-stream@0.1.1` file and a full
deobfuscated reconstruction of the payload chain have since been recovered —
see `SOURCING.md`'s "Recovered evidence" section and `evidence/`.

**Update 2026-08-10:** that recovered payload has now been run through the
real pipeline — same directory-level bypass-the-fetch-layer mechanic as the
`node-ipc`/`colors` reconstructions, sourced from CDN archaeology instead of
git. See "The reconstructed pair" below. `claude-sonnet-4-6` again.

Redaction note: the two 2026-05-23 report JSON timestamps are normalized to
`2026-05-23T00:00:00Z`, recording the run date without minute-level local
timing. The reconstructed pair's report keeps its real timestamp, matching
the `node-ipc`/`colors` reconstruction convention.

## Summary

| pair | role | risk | LLM base | feed-adjusted | OSV | Rekor | Scorecard |
|---|---|---|---|---|---|---|---|
| 3.3.4 → 3.3.5 | benign control | LOW | 0.0 | 5.0 | clean | no_data | 2.1/10 suspicious |
| 3.3.5 → 4.0.0 | post-incident cleanup | LOW | 0.0 | 5.0 | clean | no_data | 2.1/10 suspicious |
| flatmap-stream 0.1.0 → 0.1.1 *(reconstructed)* | **the actual bootstrap payload** | **HIGH** | 51.5 | 60.0 | malicious (`MAL-2025-20690`) | no_data | 2.2/10 suspicious |

Tarball SHA256 (verified at fetch time — the two `event-stream` pairs only;
the reconstructed `flatmap-stream` pair has no real tarball, see
`SOURCING.md`):

- `3.3.4`: `cd4198c30c9deb0d3c5044b230116305539a45b46174a5e8030a3f2d50deed80`
- `3.3.5`: `21debd071d386e46a1e83682df60bc98119bf33c2d7051e1a1769bd86f529f84`
- `4.0.0`: `515810c9089ee41448def64724c9349e8156d602683e29ced8676f4a695090c5`

## The reconstructed pair: HIGH, and the one time the feed floor actually fires

`flatmap-stream@0.1.1`'s recovered `index.min.js` (the real bootstrap/
decrypt-loader IIFE, byte-verified — see `evidence/README.md`) plus its
`test/data.js` sidecar (the real hex/AES-256 ciphertext table `payload_a`
requires) were diffed as two local directories against a reconstructed
`0.1.0` baseline. Result:

| dimension | score | reasoning (abridged) |
|---|---|---|
| network_calls | 3.0 | "No direct network calls are visible... the decrypted payload... could contain network calls. The encrypted blobs... are too large to rule out exfiltration logic" |
| obfuscation | 10.0 | "textbook multi-layer obfuscation and dynamic code execution" — hex-decoded string literals, AES-256 decryption keyed on an env var, `module.constructor._compile` |
| install_hooks | 2.0 | "executes at require/import time... rather than at install time. No package.json changes are shown" |
| env_conditional | 9.0 | "process.env['npm_package_description']... used as the AES-256 decryption key... returns early if this env var is absent... a classic targeted supply-chain attack" |
| dependency_changes | 1.0 | "no new external dependencies are added" |

`llm_base_score` = 51.5 — on its own, **MEDIUM**, not HIGH. What pushes the
composite to 60.0/HIGH is two feed modifiers:

- **`osv/malicious_floor +3.5`** — OSV returned `MAL-2025-20690` for
  `flatmap-stream`, the one advisory in this entire corpus that has ever
  carried the `MAL-*` prefix chainwatch's aggregator treats as decisive (see
  `dataset/findings/README.md`). It fired here, live, on a real query.
- **`scorecard/scorecard_poor +5.0`** — Scorecard returned 2.2/10 for
  `github.com/npm/security-holder`. **This is not a meaningful signal for
  the actual 2018 incident** — it's npm's generic placeholder repo that
  every unpublished/security-held package's registry metadata now points
  to, not the (long-gone) original `flatmap-stream` repository. The score
  is real and the modifier fired correctly given the pipeline's inputs, but
  it's measuring the wrong thing. Contrast with `node-ipc`'s reconstruction,
  where the Scorecard signal (4.0/10, `clean`) genuinely reflects
  `RIAEvangelist/node-ipc`.

**This is the corpus's third fully-tested-for-real reconstruction, and it
lands differently from both previous ones.** `node-ipc`'s HIGH (69.0) was
carried entirely by the LLM layer — the feed floor never fired.
`flatmap-stream`'s HIGH (60.0) partially *depends* on the feed floor firing,
and it only does because this specific incident is the one time in the
corpus OSV ever reached `MAL-*` — seven years after disclosure (see
`dataset/findings/README.md`'s corrected timeline). Had this run happened
before 2025-08-14, OSV would have returned `suspicious` (two GHSA IDs, no
`MAL-*`), the floor rule would not have fired, and the composite would have
landed at 51.5 + 5.0 = 56.5 — still HIGH, as it happens, but by a much
thinner margin, and for a materially different reason (LLM signal alone
clearing 55, not the floor rule).

**The LLM correctly named the incident regardless:**

> "This diff is the infamous flatmap-stream/event-stream supply chain
> attack... a definitive, confirmed malicious supply chain attack with
> multi-layer obfuscation, environment-gated activation, and hidden dynamic
> code execution."

## Per-pair detail

### 3.3.4 → 3.3.5 — benign control

- **What changed.** `package.json` version-specifier cleanup (`~` → `^`),
  two new example scripts (`examples/map.js`, `examples/split.js`), and a
  refactor of `examples/pretty.js`. No new dependencies, no install hooks,
  no maintainer change visible at the diff level.
- **LLM.** All five dimensions scored 0. Summary: *"This diff adds two new
  example files... All changes are limited to illustrative example scripts
  using stdin/stdout... The diff appears entirely benign."*
- **OSV.** No advisories for `event-stream@3.3.5`. **Correct** — the malicious
  release is `3.3.6`, which is no longer in the registry.
- **Scorecard.** 2.1/10 (Maintained=0, Branch-Protection=0,
  Signed-Releases=-1). This is fair: `event-stream` has been effectively
  abandoned since the incident. The "suspicious" status here is driven
  entirely by the package being unmaintained, not by anything in the diff.
- **Take.** This is the false-positive baseline: a genuinely benign diff
  scored LOW, with the only friction coming from a Scorecard signal that
  reflects a real long-term maintenance problem rather than a malicious one.

### 3.3.5 → 4.0.0 — post-incident cleanup

- **What changed.** Two new internal helpers added to `index.js`:
  `es.filterSync` and `es.flatmapSync`. Two corresponding test files.
  No `package.json` change visible in the diff (file was filtered out as
  unchanged or the manifest was not re-emitted).
- **LLM.** All five dimensions scored 0. Summary: *"This diff adds two
  utility functions (filterSync and flatmapSync) to index.js along with
  corresponding test files... no suspicious patterns: no network calls,
  no obfuscation, no install hooks, no environment-based conditionals, and
  no new dependencies."*
- **Historical note worth flagging.** The function added is named
  `flatmapSync`. The 2018 attack was delivered through a malicious
  dependency named `flatmap-stream`. The most plausible reading is that
  `4.0.0` inlined the small piece of functionality the attack-vector
  dependency had provided, eliminating the need for the dep — i.e. this
  is the *remediation* diff. chainwatch as currently configured does not
  surface this connection; it sees only "new utility function, no deps."
- **OSV / Scorecard.** Same as the previous pair.

### flatmap-stream 0.1.0 → 0.1.1 *(reconstructed)* — the real attack, scored HIGH

- **What changed.** Exactly what shipped: the bootstrap/decrypt-loader IIFE
  appended to `index.min.js`, plus the new `test/data.js` ciphertext sidecar
  it requires. See "The reconstructed pair" above for the full dimension
  breakdown, the feed detail, and the caveat on what the Scorecard signal is
  actually measuring here.
- **OSV.** `malicious` — `MAL-2025-20690` plus two GHSA IDs, correctly
  resolved against `flatmap-stream@0.1.1`. This is the only feed-floor
  firing anywhere in this corpus (see `dataset/findings/README.md`).
- **Take.** Unlike `colors`'s reconstruction, this one isn't a taxonomy
  miss — `obfuscation` (10.0) and `env_conditional` (9.0) both fired hard,
  and correctly. It's also not a clean "LLM alone gets there" story like
  `node-ipc`'s reconstruction: the LLM base score (51.5) is real signal but
  only reaches MEDIUM on its own. What tips this pair into HIGH is a feed
  rule that fires for this specific incident and no other in the corpus,
  seven years after the fact.

## Cross-cutting observations

### 1. The diff signal that mattered most wasn't in any of these pairs — until it was

The actual attack happened in the gap between `3.3.5` and `3.3.6`, and the
only thing visible in `event-stream` itself at that point would have been:

```diff
+    "flatmap-stream": "^0.1.1",
```

A one-line `package.json` change. chainwatch's `dependency_changes`
dimension would have caught the "new dep" event, but the LLM has no way
to judge whether `flatmap-stream` is itself malicious from that line alone
— *within `event-stream`'s own diff*. The malicious code lived in the
transitive package, and none of the three pairs originally run here ever
put that package's own content in front of the LLM.

**Update 2026-08-10:** the reconstructed `flatmap-stream 0.1.0 → 0.1.1` pair
above closes that specific gap — once `flatmap-stream`'s own diff *is* what
gets analysed, chainwatch catches it decisively (HIGH). So the structural
limitation below is scoped more narrowly than the original write-up
assumed: it's not that chainwatch's LLM/feed layers are blind to this
payload, it's that chainwatch's *registry-walking* fetcher never follows a
freshly-added dependency to fetch and diff it on `event-stream`'s behalf in
the first place. Both framings point at the same fix:

This is the headline structural limitation of any registry-level diff
scanner: **a one-line dependency addition can deliver an arbitrary payload
through a fresh, unfamiliar package**. Catching it requires either
(a) recursively analysing every newly-added transitive dependency, or
(b) treating any new-dep-from-a-new-maintainer as a HIGH-signal event
regardless of the dep's contents.

### 2. Feed latency

- **OSV.** Currently has advisory entries for `event-stream@3.3.6`,
  `flatmap-stream@0.1.1`, and `flatmap-stream@0.1.2`. These were added in
  the days following public disclosure (2018-11-20). At the moment of
  attack (publication on 2018-09-09), OSV had **no signal** — the LLM
  layer is the only one that could have raised an alert.
- **Rekor.** No attestations for any `event-stream` version. The package
  predates Sigstore adoption; this is a `no_data` for the whole package,
  not just specific versions.
- **Scorecard.** The current 2.1/10 score reflects the post-2018 abandoned
  state. We do not have a Scorecard score from September 2018; if we did,
  it would likely have shown a maintained-but-thinly-staffed project with
  no branch protection — i.e. exactly the profile that the attack
  exploited (a single maintainer with publish rights, no review process).

### 3. chainwatch implementation gaps surfaced by this run

- The structured report schema includes a top-level `llm_summary` field
  populated by the model, but the per-`RiskDimension` `rationale` and
  `confidence` fields are `null` in both `2026-05-23` runs. The prompt at
  that time asked for an overall summary but not per-dimension
  justifications. **Since fixed** — the reconstructed pair's report has
  `confidence` populated on every dimension, per-dimension reasoning, and a
  persisted `llm_base_score` (see next bullet), confirming the self-
  containment work landed for real, not just in newer corpus entries.
- `from_version_sha256` / `to_version_sha256` are recorded for the two
  registry-fetched pairs, which gives us reproducibility on the input
  artefacts. Both are `null` for the reconstructed pair — expected, there's
  no real tarball behind it (see `SOURCING.md`).
- `llm_base_score` was `null` in both original reports despite the log line
  `LLM base=0.0` — the aggregator computed the value but didn't persist it.
  **Since fixed** (schema `0.2.0`); the reconstructed pair's report carries
  it (`51.5`) directly.

## Position in the detection matrix

| package | malicious version available? | did diff-level analysis catch it? |
|---|---|---|
| event-stream | **no** (3.3.6 unpublished — even just its one-line `package.json` dependency addition was never archived anywhere checked) | not testable at registry level; see `flatmap-stream` below for the payload itself |
| flatmap-stream | Yes — reconstructed from CDN-archaeology evidence (Wayback-cached `0.1.1`, paper-corpus `0.1.0`/`test-data.js`), byte-verified against the hashes in `evidence/README.md` | **Yes** — HIGH (60.0/100). `obfuscation` and `env_conditional` both scored correctly high; the composite additionally benefits from OSV's `MAL-2025-20690` floor rule firing, the only time it does anywhere in this corpus (see `dataset/findings/README.md`) |

The two registry-fetched `event-stream` pairs above remain negative results
only: they validate that chainwatch doesn't false-positive on benign diffs
of a high-profile victim package, which is useful but doesn't speak to
detection on their own. `flatmap-stream`'s reconstructed pair is what
actually answers the detection question for this incident — see "The
reconstructed pair" above and `dataset/findings/README.md` for how it folds
into the corpus-wide precision/recall numbers.
