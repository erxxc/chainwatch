# colors — corpus sourcing notes

## Attack summary

On 8 January 2022, `colors`' sole maintainer (Marak Squires) intentionally
sabotaged his own package — no account compromise, no third-party attacker.
In protest of large companies profiting from unpaid open-source labor, he
committed a change adding an unconditional infinite loop (`for (let i = 666;
i < Infinity; i++) console.log(...)`) that runs at `require('colors')` time,
plus an ASCII-art "LIBERTY" banner. Any process depending on `colors` —
directly or transitively — would hang and spin CPU indefinitely on startup.
He made the same change to his other popular package, `faker`, the same day.

Attack timeline:

- `colors@1.4.0` published 2019-09-22 — last known-clean release, and
  npm's `dist-tags.latest` **still points here** — the sabotage was never
  re-published after being reverted upstream.
- `colors@1.4.44-liberty` / `colors@1.4.44-liberty-2` published
  2022-01-08 04:19–04:22 UTC by Marak — added the infinite loop + banner.
  `-liberty-2` is the version that actually reached npm.
- `colors@1.4.1` / `colors@1.4.2` also published around the same window
  per the registry's `time` metadata (exact relationship to the
  `-liberty` commits not established — see `evidence/README.md`).
- Community reverts the sabotage same day: [PR #286](https://github.com/Marak/colors.js/pull/286),
  bumping to `1.5.0` in git — **never published to npm**.
- npm unpublishes `1.4.1`, `1.4.2`, `1.4.44-liberty`, `1.4.44-liberty-2`.
  `1.4.0` remains `latest` to this day.
- The community subsequently forked to `@colors/colors` as the maintained
  successor; the original `colors` package is effectively frozen at `1.4.0`.

## Availability of the attack artifacts

Unlike event-stream and ua-parser-js, this was a **legitimate-maintainer
commit to a public repository**, not an account hijack — nothing needed
hiding from git at commit time, so the payload is recoverable directly from
GitHub's commit history rather than needing CDN archaeology or third-party
reconstruction. See `evidence/README.md` for the full recovery: exact
sabotage commit (`074a0f8ed0c3...`, author Marak Squires, timestamped), the
complete `lib/index.js` and `lib/custom/american.js` as published, and the
community revert PR. This is stronger provenance than either other
incident in this dataset.

The npm tarballs for `1.4.1`/`1.4.2`/`1.4.44-liberty(-2)` themselves remain
unrecoverable — confirmed via direct checks: `ossf/malicious-packages` and
the Datadog malicious-software-packages-dataset (both empty for `colors`),
and unpkg/jsDelivr via the Wayback Machine (no captures for any of the four
tainted version strings).

## What we ran instead

`1.4.0` is still `latest`, so there is no "post-incident fix" pair to run
the way event-stream (`3.3.5→4.0.0`) and ua-parser-js (`0.7.30→0.7.31`) do —
there was never a republished fix. Instead we ran the last two *pre*-incident
releases as a benign control:

| pair | role | report |
|---|---|---|
| `1.3.3 → 1.4.0` | benign control (last two clean releases, pre-incident) | `report-1.3.3-to-1.4.0.json` |

Findings in `FINDINGS.md`.

## Reconstructed pair — the actual sabotage, run for real (2026-08-08)

Same method as `node-ipc`'s reconstruction (see `malicious/node-ipc/SOURCING.md`
for the full rationale): applied the exact verified sabotage commit
(`evidence/commit-074a0f8ed0c3.diff`) to the real, still-published `1.4.0`
tarball, then ran chainwatch's diff engine, LLM analysis, and feed lookups
directly against the two resulting local directories — never packaged into
an installable tarball, never served through a registry. Verified before
running: real `colors@1.4.0`'s actual `lib/index.js` is byte-identical to
the "before" state implied by the evidence files, so this reconstruction
carries the same fidelity guarantee node-ipc's did — apply the same diff to
the same real base and you get the same result.

| pair | role | report |
|---|---|---|
| `1.4.0 → 1.4.44-liberty-2` *(reconstructed)* | **the actual sabotage commit** | `report-1.4.0-to-1.4.44-liberty-2-RECONSTRUCTED.json` |

**First result (pre-fix): 7.5/100, LOW** — and unlike node-ipc's
reconstruction, this *wasn't* a fetching-completeness story. This was the
complete, real, unedited attack, and it still scored LOW. See `FINDINGS.md`
for why: none of chainwatch's five risk dimensions were shaped to detect
"this code hangs the process forever" — the taxonomy (network calls,
obfuscation, install hooks, env conditionals, dependency changes) was built
around data-exfiltration- and credential-theft-shaped attacks, and a
denial-of-service payload didn't match any of them, even when the LLM's own
free-text summary correctly identified it as "malicious in effect." That
pre-fix report is preserved at
`pre-dos-fix-report-1.4.0-to-1.4.44-liberty-2-RECONSTRUCTED.json` for
citation.

## The fix (2026-08-10) and the confirmed result

Two real code changes landed the same day, both directly motivated by this
finding:

1. A sixth risk dimension, `resource_exhaustion`, added to
   `models.DIMENSIONS` and the LLM prompt (`src/chainwatch/analyzer/llm.py`).
   Rerunning with just this fix: `resource_exhaustion` scores a perfect
   10.0 at confidence 1.0 — but the composite only reaches 25.0, still LOW,
   because the weighted-sum formula caps a single dimension's contribution
   at `weight × 100` (20 points at this dimension's 20% weight). Necessary,
   not sufficient.
2. A same-day aggregator rule, `_apply_dimension_floor`
   (`src/chainwatch/analyzer/aggregator.py`): any single dimension scoring
   ≥9.0 at confidence ≥0.9 floors the composite to MEDIUM (≥30), mirroring
   the existing OSV `malicious_floor` feed rule but triggered by the LLM's
   own dimension scores. Checked against the whole corpus before shipping —
   fires on zero benign-labelled reports.

**Current result: 35.0/100, MEDIUM** — this is now the canonical
`report-1.4.0-to-1.4.44-liberty-2-RECONSTRUCTED.json`, i.e. what
`chainwatch diff` would produce today (modulo LLM non-determinism) if
`1.4.44-liberty-2` were still fetchable. Full before/after breakdown,
including why the dimension alone wasn't enough, in `FINDINGS.md`.
