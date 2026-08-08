# node-ipc — corpus sourcing notes

## Attack summary

Starting 7 March 2022, node-ipc's sole maintainer (RIAEvangelist / Brandon
Nozaki Miller) added protest code targeting Russian and Belarusian users in
response to the invasion of Ukraine — no account compromise, a legitimate
maintainer sabotaging his own package, same structural pattern as `colors`.
Two payload tiers were shipped under the same incident:

- A **destructive wiper** (`node-ipc@10.1.1`/`10.1.2`/`10.1.3`): geolocates
  the installing machine via a public IP-geolocation API, and if the
  country resolves to Russia or Belarus, recursively overwrites every file
  reachable from `./`, `../`, `../../`, and `/` with a heart emoji. See
  `evidence/` for the full recovered payload.
- A **non-destructive protest notice**, later folded in as a new
  `peacenotwar` dependency (`node-ipc@9.2.2` and `11.0.0`+): writes a
  `WITH-LOVE-FROM-AMERICA.txt` file to the user's Desktop/OneDrive on
  module load, unconditionally, regardless of geolocation. No wiping.

Attack timeline:

- `node-ipc@10.1.0` published pre-incident — last known-clean release on
  the 10.x line.
- `node-ipc@10.1.1` published 2022-03-07T11:03 UTC — commit `847047cf7f81...`
  ("added ssl check"), adds `dao/ssl-geospec.js`, the destructive wiper.
- `node-ipc@10.1.2` published same day (~21:34 UTC) — dependency bump only
  (`ansi-regex`), wiper code untouched.
- `node-ipc@10.1.3` published shortly after (exact commit not identified).
- npm unpublishes `10.1.1` / `10.1.2` / `10.1.3` within ~24 hours per public
  reporting.
- `node-ipc@11.0.0` published — **the wiper is gone, but the `peacenotwar`
  dependency (protest-notice-only) is still present and still on the
  registry today.** This is the version `latest`-adjacent scans would
  actually see.
- `node-ipc@9.2.2` backports the same `peacenotwar` notice-only behaviour
  to the 9.x line.

## Availability of the attack artifacts

Same legitimate-maintainer-commit pattern as `colors` — the destructive
payload is recoverable from git, not CDN archaeology, though the *upstream*
`RIAEvangelist/node-ipc` repository's own history around this period is no
longer reachable via the GitHub API (consistent with a rewritten/force-pushed
history after the incident). A full mirror predating any cleanup survives at
`samuelmattjohnston/node-ipc`. Full recovery, exact commit SHA, and
deobfuscated payload walkthrough in `evidence/README.md`.

Checked directly and confirmed empty for the destructive-wiper versions
(`10.1.1`/`10.1.2`/`10.1.3`): `ossf/malicious-packages`, the Datadog
malicious-software-packages-dataset, and unpkg/jsDelivr via the Wayback
Machine.

**Critically, this incident differs from event-stream and ua-parser-js: the
`peacenotwar`-dependency tier was never unpublished and is directly
diffable at the registry level today** — see below.

## What we ran — this is a real, registry-diffable attack-adjacent pair

Unlike the other two incidents in this corpus, `node-ipc@11.0.0` is
currently `available` on the npm registry and **does contain the
compromised `peacenotwar` dependency** (confirmed by the diff — see
`FINDINGS.md`). `10.1.0 → 11.0.0` is therefore not a benign control; it's
the closest thing in this dataset to a directly analysable attack diff.

| pair | role | report |
|---|---|---|
| `10.1.0 → 11.0.0` | brackets the incident — pre-incident clean → post-incident, still-compromised `peacenotwar` dependency present | `report-10.1.0-to-11.0.0.json` |

Findings — including a genuinely significant near-miss on the severity
threshold — are in `FINDINGS.md`.

## Reconstructed pair — the full destructive wiper, run for real (2026-08-07)

`10.1.1` itself (the actual wiper) is unpublished and not registry-fetchable
(see above). Its full file tree is fully recoverable, though: apply the
exact verified commit diff (`evidence/commit-847047cf7f81-relevant.diff`) to
the real, still-published `10.1.0` tarball, and the result is a byte-for-byte
match for what `10.1.1` actually shipped — anyone can verify this by
re-running the same diff against the same tarball.

We did this and ran chainwatch's actual diff engine, LLM analysis, and feed
lookups (OSV, Rekor, Scorecard — all by name/version, no tarball needed)
directly against the reconstructed local directory pair, **never packaging
it as an installable tarball or serving it through a registry** — the diff
engine takes two directory paths, so the fetcher/registry layer was
bypassed entirely rather than mocked. This keeps a real, currently-functional
destructive payload (unlike event-stream/ua-parser-js's dead-C2 payloads,
this one's only dependency — a live geolocation API — plausibly still works)
from ever existing as something `npm install`-able.

| pair | role | report |
|---|---|---|
| `10.1.0 → 10.1.1` (reconstructed) | **the actual wiper, not a remnant** | `report-10.1.0-to-10.1.1-RECONSTRUCTED.json` |

**Result: 69.0/100, HIGH** — `network_calls` and `obfuscation` both scored
10/10 (the corpus maximum on any dimension, by a wide margin), versus
`11.0.0`'s 29.5/LOW. See `FINDINGS.md` for the full breakdown; this is the
corpus's clearest evidence that the earlier near-miss was specifically an
artifact of only having the diluted, wiper-removed `11.0.0` release
available at the registry level — not a fundamental detection gap.

The `report-*-RECONSTRUCTED.json` filename is deliberately distinct from the
registry-fetched reports elsewhere in this corpus: `from_version_sha256`/
`to_version_sha256` are `null` (there is no real tarball to hash), and the
diff/analysis ran against local directories, not downloaded archives. Treat
it as a validated reconstruction, not a registry-reproducible artifact —
reproduce it via the diff file above, not via `chainwatch diff`.
