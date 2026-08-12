# Lucide Proxy — corpus sourcing notes

## Why this incident

Recommendation #7 in `dataset/findings/README.md` needed a real,
independently-sourced attack that actually exercises `resource_exhaustion`
or `_apply_dimension_floor` — `ctx` (this corpus's previous addition)
turned out not to touch either mechanism, and the next three candidates
investigated (`coa`/`rc`, a Shai-Hulud-adjacent campaign, `torchtriton`)
all hit real sourcing walls of their own (see `dataset/malicious/coa-rc/`
for the first of those). Lucide Proxy was chosen specifically because its
documented DoS mechanism — an unthrottled, persistent flood with "no rate
limit" (JFrog's own words) — is a genuinely different shape from `colors`'s
synchronous infinite loop, the only shape this corpus had tested before.

## Attack summary

Starting 2026-05-27, an npm account (`terminal3airport`, later
`eerikakirk`) published 148 packages disguised as student web-proxy tools
("Riverbend Tutoring," "Northstar Tutoring," and similar branding) — not
hijacks of previously-legitimate packages, but malicious from first
publish. The packages abused the npm registry as free static-asset
hosting for a real web proxy application (built on the legitimate
open-source Scramjet/Ultraviolet proxy engines), then added two
undisclosed capabilities on top:

- **A popunder/traffic-hijacking adware layer**: a service worker
  (`sw.js`, recovered — see `evidence/`) intercepts link clicks, form
  submissions, and `window.open` calls and relays them through
  `postMessage` to force popunder ad traffic.
- **A browser-recruited DDoS botnet**: visiting the proxy web app silently
  enlisted the visitor's browser into flooding a target Wisp proxy server
  with WebSocket `CONNECT`/`CLOSE` frames — up to 1,024 concurrent sockets
  per browser, no rate limiting, capable of ~10,240 socket
  operations/second from a single visitor. The DDoS capability ran for
  roughly two weeks in May 2026 before the campaign reverted to
  adware-only monetization.

**A structural detail with no precedent elsewhere in this corpus**: the
DDoS/beaconing logic was not baked into the npm tarball at publish time.
It was loaded at runtime from an external, attacker-controlled GitHub
repository referenced with no Subresource Integrity hash — meaning the
"mutable `main` branch" could change what every visitor's browser executed
at any time, independent of any npm version bump. The traditional
"malicious version published → advisory" timeline this corpus's other
incidents use (see `dataset/findings/README.md` RQ2) doesn't map onto this
incident the same way; see "Timeline" below for how this write-up handles
that.

Disclosed publicly by JFrog Security Research on 2026-07-13. npm removed
the packages; `ilovefemboys` and `miguelphonk` were replaced with the
standard `0.0.1-security` holding placeholder, `charlie-kirk` was fully
unpublished.

## Availability of the attack artifacts

**No live tarball, no archived tarball, on either side, for any of the 148
packages** — see `evidence/README.md` for the full recoverability
investigation (registry 404s, empty Wayback CDX for every tarball URL
checked, no CDN cache since these weren't `require()`-imported libraries).

What *is* recoverable: the campaign's own external C2 repositories, via
the Wayback Machine, independent of any vendor's writeup (JFrog's own
article — like every secondary source checked for `coa`/`rc` — describes
the mechanism but does not quote code). Full detail in `evidence/README.md`.

## What we ran

No benign "control" pair is possible here, the same as `ctx` — these
packages have no legitimate predecessor version. Both pairs below use an
explicitly-synthetic `package.json` scaffold (real package name and
version strings, not a real recovered tarball) with real, hash-verified
recovered files layered on top:

| pair | "to" contents | report |
|---|---|---|
| `ilovefemboys 1.1.3 → 2.0.0`, cdn.js only | isolates the DoS-relevant file | `report-lucide-proxy-cdn-only-RECONSTRUCTED.json` |
| `ilovefemboys 1.1.3 → 2.0.0`, cdn.js + sw.js | fuller reconstruction, both real recovered files | `report-lucide-proxy-cdn-and-sw-RECONSTRUCTED.json` |

**Results: both 55.0/100, HIGH.** Read that number carefully before citing
it, though — it's not evidence of what it looks like at first glance. Both
final scores are floored by OSV's `malicious_floor` feed rule
(`MAL-2026-10305`, a real, fast hit — published days after disclosure, not
years, unlike this corpus's `flatmap-stream` precedent), not by the LLM
layer or `_apply_dimension_floor`. The LLM's own `resource_exhaustion`
scores — 8.0/10 (cdn.js-only) and 6.0/10 (cdn.js+sw.js), both well above
0 and both citing the exact right reasoning (an unbounded `setInterval`
with "no termination condition") — are the actual answer to what this
incident set out to test, and they're a real, positive, independently-sourced
result: `resource_exhaustion` generalises to a genuinely different DoS
shape than the one it was built from. What it does *not* do is settle
`_apply_dimension_floor`: 8.0 falls short of that rule's ≥9.0 trigger, so
the floor rule still hasn't fired on anything outside the two cases that
motivated it. See `FINDINGS.md` for the complete picture, including why
this result is genuinely mixed rather than a clean resolution of
recommendation #7.

## Timeline (does not fit this corpus's usual RQ2 format — read before citing)

- `ilovefemboys@1.1.3` published to npm: **2026-05-07T09:24:57Z**
- `ilovefemboys@2.0.0` published to npm: **2026-07-10T13:02:23Z**
- `cdn.js` confirmed live at the campaign's C2 repository: **2026-05-18**
  (Wayback capture date — the closest thing to a "malicious capability
  confirmed active" timestamp this incident has, given the mutable-remote-script
  structure means neither npm publish date above necessarily corresponds
  to when the DDoS logic was actually being served)
- JFrog public disclosure: **2026-07-13**
- `MAL-2026-10305` (OSV, `ilovefemboys`) published: **2026-07-13T06:27:39Z**
- `MAL-2026-10335` (OSV, `miguelphonk`) published: **2026-07-13T06:27:40Z**

Gap from `2.0.0`'s npm publish to the `MAL-*` advisory: **~2 days 17
hours** — genuinely fast, and worth contrasting directly with
`flatmap-stream`'s ~7-year gap to its own `MAL-*` reclassification (see
`dataset/findings/README.md` RQ1/RQ4). The likely explanation isn't that
this incident was less severe — it's that the `MAL-*` sources here
(`amazon-inspector`, automated scanning; `ghsa-malware`) reflect a newer,
more automated detection pathway than the purely-manual advisory process
that handled `event-stream`/`flatmap-stream` in 2018. Worth flagging as a
real, dated data point rather than a general claim about `MAL-*` speed
improving — this corpus has exactly one fast example and one slow one.
