# colors — chainwatch findings

One version pair run on 2026-08-07 with `claude-sonnet-4-6`, live pipeline
(real LLM + real feeds). See `SOURCING.md` for why the actual sabotage
commit could not be run through the pipeline (never published to npm as a
diffable pair — see below) and `evidence/` for the recovered payload.

## Summary

| pair | role | risk | LLM base | feed-adjusted | OSV | Rekor | Scorecard |
|---|---|---|---|---|---|---|---|
| `1.3.3 → 1.4.0` | benign control | LOW | 0.0 | 5.0 | clean | no_data | 2.2/10 suspicious |

Tarball SHA256 (verified at fetch time):

- `1.3.3`: `ba236fffba0bbee00ba9b3209236e2f0718eaa37d0e8812f6c9f8f4f9551950b`
- `1.4.0`: `b50eb83eda7cc37519809e240338fded8e625169945bbfe6d4156445c6610498`

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

## Cross-cutting observations

### 1. There is no registry-level "attack diff" to run for this incident, structurally

Unlike node-ipc (where the registry-available `10.1.0 → 11.0.0` pair
*does* contain real attack-adjacent code — see `node-ipc/FINDINGS.md`),
`colors`'s fix was never republished to npm. `1.4.0` has been `latest`
since 2019 and there is no later "clean" version to diff against — the
project is effectively frozen. Any registry-level scan of `colors` today
sees only the pre-incident state; the only way to see the sabotage at all
is the git-level recovery in `evidence/`.

### 2. This is the "cleanest" attack in the corpus, and also the least severe

The payload here is a denial-of-service (infinite loop), not data theft or
destructive file operations — the correct read is that it's meaningfully
less dangerous than event-stream (wallet credential theft), ua-parser-js
(cryptominer + credential stealer), or node-ipc (destructive file wipe).
It's included in this dataset for incident diversity (protestware as a
distinct threat category from account-compromise attacks) rather than
because it's a peer in severity.

## Position in the Day-3 detection matrix

| package | malicious version available? | did diff-level analysis catch it? |
|---|---|---|
| colors | no via registry (git-recoverable, see `evidence/`) | not testable at registry level |

Same caveat as event-stream and ua-parser-js: the available registry pair
validates non-false-positive behaviour on the pre-incident state, not
detection. Unlike those two, though, the sabotage commit *is* fully
recoverable and statically analysable outside chainwatch's registry-fetch
pipeline — see `evidence/`.
