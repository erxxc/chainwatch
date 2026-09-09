# benign — chainwatch findings

Four pairs run on 2026-08-07 with `claude-sonnet-4-6`, live pipeline (real
LLM + real feed lookups, no `--no-feeds`). See `SOURCING.md` for why each
pair was chosen.

## Summary

| pair | pattern under test | risk | LLM base | feed-adjusted | OSV | Rekor | Scorecard |
|---|---|---|---|---|---|---|---|
| `husky@5.0.9 → 5.1.0` | new install hook | LOW | 3.0 | 3.0 | clean | no_data | 4.7/10 clean |
| `lodash@4.17.20 → 4.17.21` | minified dist | LOW | 4.0 | 0.0 | suspicious (3× GHSA) | no_data | clean → −5 |
| `esbuild@0.27.4 → 0.27.5` | network + env conditional | LOW | 0.0 | 0.0 | suspicious (GHSA) | **clean** | clean |
| `requests@2.31.0 → 2.32.0` | large diff, dep churn | LOW | 7.5 | 2.5 | suspicious (2× GHSA, 2× PYSEC) | no_data | clean → −5 |

**Zero false positives at the severity level** — all four land LOW. That's
the headline result: none of the four "looks risky on paper" patterns pushed
a genuinely benign diff out of LOW.

## Per-pair detail

### husky@5.0.9 → 5.1.0 — new install hook, LLM caught what the structural diff missed

- **What changed.** A new `lib/commands/init.js` implementing `husky init`:
  reads the *consuming* project's `package.json` and sets
  `pkg.scripts.postinstall = 'husky install'` on it, then runs `install()`
  and creates a default `.husky/pre-commit` hook running `npm test`.
- **Structural diff_summary says nothing happened.** `new_install_hooks: []`
  — because the metadata extractor only diffs *husky's own*
  `package.json.scripts`, which didn't change. The hook being added lives in
  a string literal inside `init.js`, written into someone else's manifest at
  runtime, not into husky's own manifest at diff time.
- **The LLM caught it anyway.** `install_hooks` scored 1.5/10 — non-zero,
  correctly identified via source-level reasoning ("The new `init.js`
  programmatically sets `pkg.scripts.postinstall`..."), and correctly judged
  low-severity because the mechanism is transparent, documented, and
  user-initiated (the warning about `pinst` for published packages is
  itself evidence of legitimate intent). **This is the dataset's best
  evidence that the LLM layer adds signal beyond the structural
  `new_install_hooks` field** — the semantic layer sees a pattern the
  syntactic layer is structurally blind to (a hook being programmatically
  *written*, not *declared*).
- **Feeds.** OSV clean, Scorecard 4.7/10 clean (no mitigant applied — score
  wasn't above the >7 threshold), Rekor no_data (husky predates/doesn't use
  npm provenance).
- **Take.** Correctly LOW (3.0), for the right reasons, via a path the
  structural diff summary alone wouldn't have supported.

### lodash@4.17.20 → 4.17.21 — turned out to be a real CVE fix, not just a bump

- **What changed.** Two new internal helpers, `_baseTrim.js` and
  `_trimmedEndIndex.js`, replacing regex-based string trimming with
  character-code iteration. The LLM correctly identified this unprompted as
  a **ReDoS fix**, not a routine refactor.
- **LLM.** `obfuscation=1.0` (dist minification, expected/discounted) and
  `dependency_changes=1.0` (new internal helper modules, not external deps)
  — both low and well-reasoned. Base score 4.0.
- **OSV returned `suspicious`** with three GHSA IDs
  (`GHSA-f23m-r3pf-42rh`, `GHSA-r5fr-rjxr-66jc`, `GHSA-xxjr-mmjv-4gpg`) —
  these are *older*, unrelated lodash prototype-pollution advisories whose
  affected-version ranges still cover `4.17.21`, not anything introduced by
  this diff. Correctly `suspicious`, not `malicious` (no `MAL-*` ID), so it
  contributes 0 to the floor.
- **Scorecard clean (>7) applied the −5 mitigant** → 4.0 − 5 → clamped to
  **0.0, LOW**.
- **Take.** A stronger test than intended — this is a genuinely security-
  relevant diff (fixing a real vulnerability) that still correctly reads as
  low-risk rather than high-risk, which is the right outcome: patching a bug
  is not the same shape of event as introducing one.

#### lodash, reruns 2026-09-09 — baseline reproduced, `--strip-comments` and `--split-large-files` deltas measured

Three further live runs of the same pair (`claude-sonnet-4-6`, live
feeds), kept as `experiment-rerun-4.17.20-to-4.17.21.json`,
`experiment-strip-comments-4.17.20-to-4.17.21.json`, and
`experiment-split-large-files-4.17.20-to-4.17.21.json` — not `report-*`,
so excluded from every corpus count; the 2026-08-07 report above remains
the canonical one.

| condition | LLM base | feed-adjusted | obfuscation | dependency_changes | resource_exhaustion |
|---|---|---|---|---|---|
| baseline rerun | 4.0 | 0.0 | 1.0 / 0.7 | 1.0 / 1.0 | 0.5 / 0.85 |
| `--strip-comments` (47 comment lines removed) | 3.0 | 0.0 | 0.5 / 0.5 | 1.0 / 0.9 | 0.5 / 0.85 |
| `--split-large-files` (`lodash.min.js` seen whole, 6 chunks) | 3.5 | 0.0 | 1.0 / 0.7 | 0.5 / 0.85 | 0.5 / 0.8 |

The rerun landed on the same 4.0 base as the 2026-08-07 report, through
the same two non-zero original dimensions at the same scores and
confidences, plus a 0.5 on `resource_exhaustion` under the current
six-dimension weights — a useful run-to-run stability point for this
pair. Stripping the JSDoc and line comments that lodash's new helper
modules carry moved the base by one point, on `obfuscation` alone. That is
the benign-side counterpart to the 12.5–13.5 point drop the same flag
produces on the `coa`/`rc` narrated placeholders
(`malicious/coa-rc/FINDINGS.md`, third condition). The rerun also carries
the corpus's first `timings` block: 18.8 s end to end, 17.8 s of it LLM
time for three chunks.

`--split-large-files` sent `lodash.min.js` whole instead of head-first —
six chunks, nothing truncated — and changed nothing material: base 3.5
(`dependency_changes` 1.0 → 0.5), still 0.0 / LOW, with the model's
reasoning on the full bundle saying the minification is expected for that
file and no further obfuscation is layered on. On this pair the truncated
tail hid nothing, which is the expected result for a benign bundle and
says nothing about a malicious one. Cost of finding that out: 42.1 s of
LLM time against 17.8 s for the three-chunk run, since six chunks at
concurrency 4 means two waves.

### esbuild@0.27.4 → 0.27.5 — first live validation of the Rekor identity feature

- **What changed.** 18 lines, all version-string literal bumps in
  `lib/main.js` (binary version checks, worker thread data, pnpapi cache
  paths, the exported version constant). No logic change.
- **LLM.** All five dimensions 0. Base score 0.0 — correctly recognised as a
  pure version-string bump despite `lib/main.js` containing exactly the kind
  of platform-detection and native-binary-fetch logic that would deserve
  scrutiny in a *first-seen* diff.
- **Rekor: real signing identity, real comparison, real match.** This is
  the first pair in the dataset where npm provenance attestations exist on
  both sides. Recovered identity:
  `https://github.com/evanw/esbuild/.github/workflows/publish.yml@refs/heads/main`,
  identical on `0.27.4` and `0.27.5` → `signing_identity_changed: false`,
  status `clean`, with a real `search.sigstore.dev` URL
  (`?logIndex=1210320642`). This is the feature built earlier this session
  working end-to-end against a real, currently-maintained package outside
  the unit-test mocks — the maintainer-hijack signal it's designed to catch
  correctly stays silent on a same-maintainer release.
- **OSV suspicious** — an unrelated GHSA advisory in esbuild's history;
  doesn't affect the score (not `malicious`).
- **Take.** Correctly 0.0/LOW on every axis, and the Rekor feed did
  meaningful, verifiable work for the first time in this corpus rather than
  reporting `no_data`.

### requests@2.31.0 → 2.32.0 — large legitimate refactor, chunking under real load

- **What changed.** A full layout migration (`requests/` → `src/requests/`),
  touching every source file: 19 files added, 18 removed, 5 modified,
  ~5,900 total changed lines. Two files (`models.py`, `utils.py`) hit the
  per-file diff-size cap and were truncated. The chunker split the diff into
  **10 chunks** sent to the LLM — the largest chunk count anywhere in this
  dataset.
- **LLM base score 7.5** — the highest LLM base score in the benign corpus,
  driven by `env_conditional=1.5` and `network_calls=1.0`/`obfuscation=0.5`
  spread across the ten chunks (aggregated via max-per-dimension across
  chunks, per `analyzer/llm.py`'s aggregation strategy — a single elevated
  reading in one chunk sets the dimension for the whole diff). The summary
  correctly identifies the change as "a standard Python packaging refactor,"
  not a security event.
- **OSV suspicious** — four advisories (2 GHSA, 2 PYSEC), all pre-existing
  `requests` CVEs whose ranges include `2.32.0`; not introduced by this diff.
- **Scorecard clean (>7) → −5 mitigant** → 7.5 − 5 = **2.5, LOW**.
- **Take.** The highest-volume, highest-chunk-count diff in either corpus
  (malicious or benign) still lands LOW — a reasonable signal that chunking
  + max-aggregation doesn't runaway-inflate scores on large legitimate
  diffs. Worth flagging for the paper: this is also the pair most likely to
  suffer from truncation-driven blind spots (two files truncated), so a
  LOW score here is reassuring but not a strong guarantee — see the
  ua-parser-js corpus's truncation observations for the same caveat.

## Cross-cutting observations

### 1. Zero severity-level false positives, on patterns chosen to be hard

All four pairs were deliberately selected to hit a dimension chainwatch
watches for. None crossed LOW. That's a genuine, if small-sample, positive
result for the paper's false-positive-rate claim (Research Context item 3
in the top-level README).

### 2. The Scorecard mitigant did real work here too

Three of four pairs (`lodash`, `requests`, and `esbuild` — though esbuild's
base was already 0) had their score reduced by the `scorecard_good −5`
modifier. Combined with the ua-parser-js corpus's identical observation,
this mitigant is now pulling real weight across both the malicious-adjacent
and benign corpora — worth the "defend or revise before publication" note
already on record in `ua-parser-js/FINDINGS.md` carries over here.

### 3. The Rekor feature's first real signal

Every prior report in this dataset (event-stream, ua-parser-js, and the
other three benign pairs) shows Rekor as `no_data` — either the package
predates npm provenance or one side of the diff lacks an attestation.
`esbuild` is the first pair with attestations on both sides, and the
feature behaved exactly as designed: same identity, same release pipeline,
correctly silent. This corpus still has no example of the identity-*changed*
path actually firing (`suspicious`) — that would need a real hijack-adjacent
pair, which by definition isn't in the benign baseline.

### 4. Structural fields and LLM reasoning can diverge — see husky

`diff_summary.new_install_hooks` is a purely syntactic signal (did *this*
package's manifest gain a hook). The LLM's `install_hooks` dimension is
semantic and caught husky's runtime-written hook that the syntactic field
missed entirely. Neither layer alone would have been sufficient; the
combination is what surfaced the real (benign) pattern correctly.
