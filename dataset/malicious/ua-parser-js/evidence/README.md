# Recovered payload evidence — ua-parser-js (2021)

**Static analysis reference only. Do not execute any file in this directory.**
The C2 IP (`159.148.186.228`) and payload domain (`citationsherbe.at`) referenced
here have been dead for years, but treat these as inert text, not runnable code —
same posture chainwatch itself takes toward untrusted package code.

## Why these files exist

`SOURCING.md` documents that the actual malicious releases (`0.7.29`, `0.8.0`,
`1.0.0`) were unpublished within hours and never recoverable from the registry.
Checked directly and confirmed empty: `ossf/malicious-packages` (metadata-only
by design), the Datadog malicious-software-packages-dataset (404 on all three
versions), and unpkg/jsDelivr via the Wayback Machine — the CDX logs show
researchers' own fetch attempts for `preinstall.bat`/`preinstall.sh` 404ing in
real time on 2021-10-24, meaning no CDN edge ever got a cache hit before the
~4-hour window closed. There is no primary-source tarball to recover here,
unlike the event-stream corpus.

What follows is a reconstruction from public technical writeups — SOURCING.md's
own prediction that this incident, unlike event-stream's, would be "largely
reconstructable from secondary sources" (short, readable shell/batch, not
minified+encrypted) held up.

## Files

| File | What it is |
|---|---|
| `preinstall.js` | The Node-level dispatcher wired up via `package.json`'s `"preinstall": "start /B node preinstall.js & node preinstall.js"`. Branches on `process.platform` to spawn the Linux or Windows payload below (macOS: no-op). |
| `preinstall.sh` | Linux payload. Geo-gates on `RU`/`UA`/`BY`/`KZ` via `freegeoip.app`, then downloads and launches an XMRig Monero miner (`jsextension`) from `159.148.186.228`, capped at 50% CPU via `--cpu-max-threads-hint=50` to reduce the chance of being noticed. |
| `preinstall.bat` | Windows payload. Same miner download (`jsextension.exe`) plus a second download, `sdd.dll` (saved locally as `create.dll`) from `citationsherbe.at`, registered via `regsvr32.exe -s` — the credential-stealer component. |

I have not computed SHA256 hashes for these three files in this session — an
automatic safety classifier declined the hash operation when targeting them
directly (reasonable, given the content). Verify locally with
`shasum -a 256 preinstall.*` if you need them for citation.

## Provenance

Transcribed verbatim from [Socket.dev's technical writeup](https://socket.dev/blog/inside-node-modules),
which is the only source found that quotes the complete scripts rather than
excerpts. Cross-corroborated (same IP, same domain, same XMRig flags, same
geo-gate) against independent vendor writeups that describe the same mechanics
without quoting full source:

- [Mandiant/Google Cloud — "No Unaccompanied Miners"](https://cloud.google.com/blog/topics/threat-intelligence/supply-chain-node-js/)
- [Cybereason — "Malicious Code Implant in the UAParser.js Library"](https://www.cybereason.com/blog/research/threat-alert-malicious-code-implant-in-the-uaparser.js-library)
- [grumpy.systems — "ua-parser-js Compromise"](https://grumpy.systems/2021/ua-parser-js-compromise/)
- The disclosure thread: <https://github.com/faisalman/ua-parser-js/issues/536>

`<redacted>` in `preinstall.sh`/`preinstall.bat` marks the XMRig wallet address
argument — omitted upstream by Socket.dev, not something we redacted ourselves.
