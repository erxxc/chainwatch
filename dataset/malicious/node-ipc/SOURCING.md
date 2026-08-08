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
