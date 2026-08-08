# event-stream — chainwatch findings

Two version pairs were run on 2026-05-23 with `claude-sonnet-4-6` as the
analyser model. See `SOURCING.md` for why the actual malicious release
(`3.3.6`) and the payload package (`flatmap-stream`) could not be analysed.

**Update 2026-08-07:** the actual `flatmap-stream@0.1.1` file and a full
deobfuscated reconstruction of the payload chain have since been recovered —
see `SOURCING.md`'s "Recovered evidence" section and `evidence/`. This is
real payload code for citation/static reference, not a registry tarball, so
it hasn't been run through chainwatch's pipeline and the pairs below are
still the only pipeline-run results in this corpus.

Redaction note: report JSON timestamps are normalized to
`2026-05-23T00:00:00Z` so the corpus records the run date without preserving
minute-level local execution timing.

## Summary

| pair | role | risk | LLM base | feed-adjusted | OSV | Rekor | Scorecard |
|---|---|---|---|---|---|---|---|
| 3.3.4 → 3.3.5 | benign control | LOW | 0.0 | 5.0 | clean | no_data | 2.1/10 suspicious |
| 3.3.5 → 4.0.0 | post-incident cleanup | LOW | 0.0 | 5.0 | clean | no_data | 2.1/10 suspicious |

Tarball SHA256 (verified at fetch time):

- `3.3.4`: `cd4198c30c9deb0d3c5044b230116305539a45b46174a5e8030a3f2d50deed80`
- `3.3.5`: `21debd071d386e46a1e83682df60bc98119bf33c2d7051e1a1769bd86f529f84`
- `4.0.0`: `515810c9089ee41448def64724c9349e8156d602683e29ced8676f4a695090c5`

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

## Cross-cutting observations

### 1. The diff signal that mattered most isn't in any of these pairs

The actual attack happened in the gap between `3.3.5` and `3.3.6`, and the
only thing visible in `event-stream` itself at that point would have been:

```diff
+    "flatmap-stream": "^0.1.1",
```

A one-line `package.json` change. chainwatch's `dependency_changes`
dimension would have caught the "new dep" event, but the LLM has no way
to judge whether `flatmap-stream` is itself malicious from that line alone.
The malicious code lived in the transitive package.

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
  `confidence` fields are `null` in both runs. The current prompt asks
  for an overall summary but does not require per-dimension justifications.
  Adding those would make the output more useful for the paper.
- `from_version_sha256` / `to_version_sha256` are recorded, which gives
  us reproducibility on the input artefacts.
- `llm_base_score` is `null` in both reports despite the log line
  `LLM base=0.0`. The aggregator computes the value but does not persist
  it in the saved JSON — worth fixing so the report is self-contained.

## Position in the Day-3 detection matrix

| package | malicious version available? | did diff-level analysis catch it? |
|---|---|---|
| event-stream | **no** (3.3.6 unpublished) | not testable at registry level |

Even the *successful* runs above are negative results: they validate that
chainwatch doesn't false-positive on benign diffs of a high-profile victim
package, which is useful but doesn't speak to detection. The
event-stream entry in the final precision/recall table will need to be
either excluded or footnoted as "artifact unavailable."
