# Recovered payload evidence — Lucide Proxy (npm, 2026)

**Static analysis reference only. Do not execute any file in this
directory.** `cdn.js` still points at a live-looking domain
(`verify.titaniumnetwork.org`) as of this writing — treat it as inert
text, not runnable code, same posture chainwatch itself takes toward
untrusted package code.

## Why these files, and not the actual npm tarball

`SOURCING.md` explains the incident. Unlike every other reconstruction in
this corpus, **the actual npm tarballs are not recoverable by any method
checked**: `charlie-kirk` was fully unpublished (both versions gone,
metadata stub only); `ilovefemboys` and `miguelphonk` were replaced with
npm's standard `0.0.1-security` holding placeholder, and their real
version-specific tarball URLs 404 directly. The Wayback Machine has zero
captures of any of these packages' registry tarball URLs, and — because
these were static web-app packages, not importable libraries — there's no
unpkg/jsDelivr CDN cache either (the mechanism that recovered
`flatmap-stream` and `ctx` doesn't apply to a package nobody `require()`d).

What **is** independently recoverable: the campaign's own external,
attacker-controlled infrastructure. JFrog's technical writeup (the primary
public source on this campaign) describes the mechanism but — like every
other secondary source checked for this corpus — does not quote source
code verbatim, only screenshots and paraphrase. The files below were not
transcribed from any vendor's article; they were recovered independently,
directly from the campaign's own GitHub-hosted C2 repositories, via the
Wayback Machine.

## Files

| File | What it is | SHA256 |
|---|---|---|
| `cdn.js` | The DDoS/resource-exhaustion-relevant beacon. An unconditional `setInterval(…, 2000)` that fires forever, with no exit condition, sending a `fetch()` with a randomised path to an external domain on every tick. | `28dedd9a920a206435416fcfadce16f2cf62bcec98bbfc30c5c4407138c80ac1` |
| `sw.js` | A service worker: proxies traffic through the (legitimate, open-source) Scramjet proxy engine, then injects a script into every HTML response that intercepts `window.open`, link clicks, and form submissions and relays them via `postMessage` — a popunder/traffic-hijacking mechanism. Unrelated to `resource_exhaustion` specifically; included for a fuller second reconstruction pair. Quoted in part (not verbatim, not hash-verified against this exact copy) by a SafeDep writeup on an earlier wave of the same campaign. | `2d2be24559ea3a1c9823acdbbde1342c30762538b764d0f409dd5d1a9f8bfe63` |

## Provenance

**`cdn.js`**: recovered from
`https://web.archive.org/web/20260518174009/https://raw.githubusercontent.com/canyoupleasesaysomething/cdn/refs/heads/main/cdn.js`
— a raw-content capture (not an HTML wrapper), fetched directly, hash
computed locally. The surrounding repository (`canyoupleasesaysomething/cdn`)
was extensively crawled by Wayback on 2026-05-18 (commit pages, blob pages,
a `websocket.txt` blob at a separate commit) — consistent with this being
the actual, real GitHub account JFrog's writeup names as the source of the
"mutable remote script... with no Subresource Integrity validation" the
campaign's web apps loaded at runtime. The GitHub account itself
(`canyoupleasesaysomething`) still resolves (HTTP 200) but now shows zero
public repositories — consistent with takedown/removal after disclosure.

**`sw.js`**: recovered from
`https://web.archive.org/web/20260426172256/https://raw.githubusercontent.com/lucideproxy/svg/refs/heads/main/sw.js`
— same mechanism, a different repository under a differently-named account
(`lucideproxy/svg`) referenced by an unrelated writeup (SafeDep) covering
an earlier wave of the same campaign under the `terminal3airport` npm
account. `github.com/lucideproxy` also still resolves (HTTP 200).

**Why two different GitHub accounts hosted real, recoverable code while the
JFrog-analysed 5.4 MB obfuscated entry bundle (`assets/73sxysj46r.js`,
the file actually carrying the full flood-generator logic JFrog describes
— 500ms intervals, up to 1,024 concurrent WebSocket sockets, Wisp v2
protocol framing) was not found anywhere:** that giant bundle appears to
have been published *inside* the npm tarballs themselves (per JFrog, as
`assets/73sxysj46r.js`), not loaded from an external, Wayback-crawlable
URL — so its unrecoverability follows the same pattern as `coa`/`rc`
(short-lived or never-crawled tarball). `cdn.js`/`sw.js`, by contrast,
were loaded at runtime from external repos with predictable, guessable-once-named
URLs, and GitHub raw-content URLs are exactly the kind of thing Wayback's
crawlers (and, per JFrog's own report, JFrog themselves) do catch. **This
means what's reconstructed here is real, verified, unambiguously part of
the actual campaign infrastructure — but it is not the single largest or
most sophisticated component of the attack.** `cdn.js`'s simple periodic
beacon is milder than the flood engine JFrog fully documented; see
`FINDINGS.md` for what that means for interpreting the result.

## Corroborating sources (not used for code, cross-checked against the above)

- [JFrog Security Research — "Lucide Proxy: Turning Student Web Proxies into DDoS Bots"](https://research.jfrog.com/post/lucide-proxy-npm-malware-campaign/) — the primary technical writeup; describes the full campaign, the flood mechanism, and file inventory, but does not quote source.
- [SafeDep — "Malicious npm terminal3airport proxy adware spam"](https://safedep.io/malicious-npm-terminal3airport-proxy-adware-spam) — covers an earlier, adware-focused wave of the same campaign under a different npm publisher account; quotes `sw.js` in part and an `auto-publish.sh` automation script.
- OSV `MAL-2026-10305` (`ilovefemboys`) and `MAL-2026-10335` (`miguelphonk`), queried live for this write-up — both real `MAL-*` classifications, sourced from `amazon-inspector` and `ghsa-malware` automated scanning, published 2026-07-13, days after the campaign's public disclosure (not years, unlike this corpus's `flatmap-stream` precedent — see `SOURCING.md`).

## Reconstruction run (2026-08-11)

Same "diff two local directories, bypass the registry fetch entirely"
mechanic used elsewhere in this corpus, but with an honest structural
difference from every prior incident: **there is no real tarball on
either side.** The "from" directory is an explicitly-synthetic minimal
`package.json` — the real package name and a real, registry-verified
version string, but not real tarball content (there's no legitimate
predecessor version to recover; these packages were malicious from
inception, not hijacked). The "to" directory is that same synthetic
scaffold plus the real, hash-verified files above.

| pair | "to" contents | report |
|---|---|---|
| `cdn.js` only | isolates the `resource_exhaustion`-relevant file, keeping the test clean of `sw.js`'s unrelated attack surface | `../report-lucide-proxy-cdn-only-RECONSTRUCTED.json` |
| `cdn.js` + `sw.js` | both real recovered files together, a fuller (if still partial) reconstruction | `../report-lucide-proxy-cdn-and-sw-RECONSTRUCTED.json` |

Labelled `ilovefemboys 1.1.3 → 2.0.0` (both real, registry-verified
version strings for this package) — but see `SOURCING.md` for why the
exact version-to-payload mapping is representative, not verified the way
e.g. `ctx`'s reconstruction is: nothing here confirms `ilovefemboys@2.0.0`
specifically, as opposed to any other of the campaign's 148 packages,
loaded exactly this `cdn.js` URL at exactly that version. What's verified
is that this file is real campaign infrastructure, recovered independently,
not narrated or fabricated. Full results and dimension breakdown in
`../FINDINGS.md`.
