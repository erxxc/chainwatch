# ua-parser-js — corpus sourcing notes

## Attack summary

On 22 October 2021, the npm account of `ua-parser-js`'s sole maintainer
(Faisal Salman) was hijacked. The attacker published three malicious
releases — `0.7.29`, `0.8.0`, and `1.0.0` — within roughly 90 seconds of
each other, covering the three actively-supported major lines of the
package. Each release shipped a `preinstall` hook that downloaded and
executed a Linux/Windows-targeted cryptocurrency miner plus a credential
stealer (`jsextension` / `sdd.dll`).

The maintainer regained access and published patched releases (`0.7.30`,
`0.8.1`, `1.0.1`) approximately four hours later, all on the same day.
npm subsequently unpublished the three malicious versions.

`ua-parser-js` is one of the most-downloaded npm packages (≈8M weekly
downloads at the time of attack), making this one of the highest-impact
maintainer-account-compromise incidents on record.

Attack timeline (all 2021-10-22 UTC unless noted):

- `0.7.28` published 2021-04-10 by Faisal Salman — last known-clean release
  on the 0.7 line.
- `0.7.29` / `0.8.0` / `1.0.0` published 12:15–12:16 UTC by the attacker —
  contained `preinstall` script fetching and executing `jsextension` payload.
- Public disclosure: GitHub issue #536 opened ~14:00 UTC; npm security team
  alerted shortly after.
- `0.7.30` / `0.8.1` / `1.0.1` published 16:16–16:26 UTC by the legitimate
  maintainer after account recovery — clean code, no install hooks.
- `0.7.31` / `1.0.2` published 2021-10-27 — follow-up maintenance releases.
- GHSA-pjwm-rvh2-c87w / CVE-2021-4229 published 2021-10-22 20:38 UTC.

## Availability of the attack artifacts

| version | role | npm registry | OSV advisory | ossf/malicious-packages |
|---|---|---|---|---|
| `0.7.28` | pre-incident clean | available | — | — |
| `0.7.29` | **malicious** | **unpublished** | GHSA-pjwm-rvh2-c87w | not present |
| `0.7.30` | post-incident fix | available | — | — |
| `0.7.31` | follow-up clean | available | — | — |
| `0.8.0`  | **malicious** | **unpublished** | GHSA-pjwm-rvh2-c87w | not present |
| `0.8.1`  | post-incident fix | available | — | — |
| `1.0.0`  | **malicious** | **unpublished** | GHSA-pjwm-rvh2-c87w | not present |
| `1.0.1`  | post-incident fix | available | — | — |

The malicious artifacts are **not recoverable from the standard public
sources we checked**. OSV has the advisory metadata for the affected
version range but does not preserve the package contents. The
`ossf/malicious-packages` corpus has no entry for `ua-parser-js` — the
incident predates that project's coverage.

Also checked directly (2026-08-07), also empty: the Datadog
malicious-software-packages-dataset (404 on all three versions via direct
API lookup) and unpkg/jsDelivr via the Wayback Machine — see "Recovered
evidence" below for what the CDN crawl logs actually show.

## Research finding

This is the same structural problem we documented for `event-stream`:
the canonical malicious release of a high-profile compromise cannot be
retrospectively diffed at the registry level because npm's unpublish
policy removes the only authoritative copy.

The `ua-parser-js` case is in some ways a *cleaner* example than
`event-stream` for the "detection gap" framing:

- **The payload was in the package itself**, not in a transitive
  dependency. The malicious code lived in a new `preinstall` hook and
  three accompanying scripts shipped directly inside the tarball. A
  diff-level scanner that had the 0.7.28 → 0.7.29 tarballs would have
  seen the attack — there is no "transitive blind spot" excuse here.
- **The fix versions were published the same day**, only four hours
  after the malicious ones. This is the tightest realistic "detect
  before the official fix" window we have in the corpus: any tool that
  can score a fresh release in the low single-digit minutes can
  meaningfully beat the official remediation here.
- **OSV ingested the advisory the same day** (GHSA published
  2021-10-22 20:38 UTC, ~8 hours after the malicious publish). For
  this incident, OSV is *fast*. The detection gap chainwatch needs to
  close is therefore not against OSV at all — it's the
  "hours-after-publish, before-any-advisory-exists" window between
  12:15 and 20:38 UTC on 2021-10-22.

## What we ran instead

We ran the two adjacent pairs around the incident that *are* available:

| pair | role | report |
|---|---|---|
| `0.7.28 → 0.7.30` | brackets the unpublished `0.7.29` (pre → fix) | `report-0.7.28-to-0.7.30.json` |
| `0.7.30 → 0.7.31` | post-incident clean control (fix → next clean) | `report-0.7.30-to-0.7.31.json` |

Tarball SHA256 (verified at fetch time):

- `0.7.28`: `416a7af001e40ea2430136873c638c8afe655a1485b62b3b9e0d7ed49535e46b`
- `0.7.30`: `4d433579092044b1e3c17e01d94dc02f29cd133ab83cc3d5f70f35b4c3359056`
- `0.7.31`: `4d8acdabc90b038490cd85473e5f234096bd3b9a6f3198db6c41788002f06a89`

Findings from these runs are in `FINDINGS.md`.

## Recovered evidence (2026-08-07)

Checked directly and confirmed empty for all three malicious versions:
`ossf/malicious-packages` (metadata only, by design), the Datadog
malicious-software-packages-dataset (404 via direct API lookup), and
unpkg/jsDelivr via the Wayback Machine — the CDX logs show other researchers'
own fetch attempts for `preinstall.bat`/`preinstall.sh` 404ing in real time
on 2021-10-24, confirming no CDN edge ever cached them inside the ~4-hour
window before takedown. Unlike event-stream, there is no primary-source file
recoverable here at all.

`evidence/` now holds `preinstall.js`, `preinstall.sh`, and `preinstall.bat`
transcribed verbatim from [Socket.dev's writeup](https://socket.dev/blog/inside-node-modules)
— the only source found quoting the complete scripts rather than excerpts —
cross-corroborated against Mandiant, Cybereason, and other independent
vendor writeups (same C2 IP, same payload domain, same XMRig flags, same
geo-gate logic across all of them). This confirms the prediction below: the
readable, unobfuscated nature of this payload made it fully reconstructable
from public secondary sources. See `evidence/README.md` for full provenance.

Still missing: `jsextension`/`jsextension.exe` (the dropped XMRig binary
itself) and `sdd.dll` (the credential-stealer DLL) — the *scripts* that
fetch them were recovered, not the binaries. Contacting npm Inc. directly for
the original tarballs was out of scope for this pass, per project direction.

<details>
<summary>Original future-work note (superseded by the above)</summary>

If the project requires the actual attack diff, possible paths:

- Contact npm Inc. directly — same caveat as event-stream; npm retains
  internal copies of unpublished packages for legal/audit purposes.
- Reconstruct the `preinstall` script from the public Snyk / npm /
  Sonatype writeups, which all quote substantial portions of the
  payload verbatim. Unlike `event-stream` (where the obfuscated payload
  was minified+base64), the `ua-parser-js` `preinstall` script was a
  short, readable shell-and-Node.js fetch-and-exec routine and is
  largely reconstructable from secondary sources.
- The Datadog `malicious-software-packages-dataset` may contain
  `jsextension` itself (the dropped payload) even if the parent tarball
  is missing — worth checking if payload-side analysis becomes a goal.

</details>

## Reconstructed pair — the actual attack, run for real (2026-08-10)

Unlike `event-stream`/`flatmap-stream` (no live base tarball anywhere),
`ua-parser-js@0.7.28` **is** still published — so this reconstruction is
closer in shape to `node-ipc`/`colors` than to `flatmap-stream`: a real,
still-published base tarball, fetched via chainwatch's own npm fetcher
(same code path the registry pipeline uses), with the recovered attack
files spliced onto a copy of it. Specifically: `preinstall.js`,
`preinstall.sh`, and `preinstall.bat` (byte-identical to `evidence/` —
hashes in `evidence/README.md`) were copied to the package root, and
`package.json`'s `scripts` gained `"preinstall": "start /B node
preinstall.js & node preinstall.js"` — the exact wiring documented above
and in `evidence/README.md`. The two resulting directories were diffed,
analysed, and feed-queried directly — never packaged into an installable
tarball, never served through a registry.

| pair | role | report |
|---|---|---|
| `0.7.28 → 0.7.29` *(reconstructed)* | **the actual attack, as chainwatch's diff engine sees it today** | `report-0.7.28-to-0.7.29-RECONSTRUCTED.json` |

**Result: 42.5/100, MEDIUM** — flagged, but the weakest hit in the corpus,
for a specific and fixable reason: chainwatch's `SOURCE_EXTENSIONS`
allowlist (`src/chainwatch/diff/engine.py`) doesn't include `.sh`/`.bat`,
so `preinstall.sh`/`preinstall.bat` — where the actual miner-download and
credential-stealer logic lives — were never enumerated by the diff engine
at all, despite being physically present in the directory it diffed. Only
the dispatcher (`preinstall.js`) and the `package.json` metadata diff
reached the LLM. A controlled experiment (`SOURCE_EXTENSIONS` patched
in-process to add `.sh`/`.bat`, otherwise identical run) reaches **57.5,
HIGH** on the same attack — saved as
`experiment-full-visibility-0.7.28-to-0.7.29.json` (not a `report-*.json`;
it required modifying chainwatch's actual behaviour, so it's a comparison
artifact, not a corpus ground-truth entry). Full breakdown in
`FINDINGS.md`.
