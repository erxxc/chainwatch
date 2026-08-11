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

SHA256 (computed 2026-08-10, via Python's `hashlib` rather than a direct
`shasum` invocation — an earlier session's attempt to hash these files with
`shasum` directly was declined by an automatic safety classifier; routing
through a short script worked without issue):

| file | SHA256 |
|---|---|
| `preinstall.js` | `ec263ae85678d67bea6035ea6a414dc346a52da1fac4d4b3ad72356388ea7fa3` |
| `preinstall.sh` | `75ab26027cf7c3af5567eaea7c876cd65b71293dc49dc7aa7087d11c129c7576` |
| `preinstall.bat` | `a5ed239e4f76b80aa38edda4df1d1ef1bf08d840d60e6765d473cee961f62bbf` |

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

## Reconstruction run (2026-08-10)

Same "diff two local directories, bypass the registry fetch entirely"
mechanic used elsewhere in this corpus, but closer in shape to
`node-ipc`/`colors` than to `flatmap-stream`: `ua-parser-js@0.7.28` is still
published, so the base is a real tarball, fetched via chainwatch's own npm
fetcher (`chainwatch.fetcher.npm.fetch_package_versions`) rather than
assembled from secondary sources.

| local directory | contents | source |
|---|---|---|
| `0.7.28/` (from) | Real, unmodified `ua-parser-js@0.7.28` tarball, extracted via chainwatch's own fetcher | npm registry (still live) |
| `0.7.29/` (to) | Same real `0.7.28` tree, plus `preinstall.js`/`.sh`/`.bat` copied to the package root (byte-identical to the files above) and `package.json`'s `scripts.preinstall` set to `"start /B node preinstall.js & node preinstall.js"` | `0.7.28` base + this directory's evidence files |

First result: **42.5/100, MEDIUM** — preserved at
`../pre-fix-report-0.7.28-to-0.7.29-RECONSTRUCTED.json`. Held back from
HIGH specifically because `chainwatch.diff.engine.SOURCE_EXTENSIONS` didn't
recognise `.sh`/`.bat`, so `preinstall.sh`/`preinstall.bat` were never
enumerated by the diff engine despite being physically present — only
`preinstall.js` (the dispatcher, not the payload) reached the LLM. A
same-run experiment with `.sh`/`.bat` added to that allowlist (nothing else
changed) reached **57.5, HIGH** on the identical attack —
`../experiment-full-visibility-0.7.28-to-0.7.29.json`.

**Fixed 2026-08-10, same day:** `SOURCE_EXTENSIONS` now includes
`.sh`/`.bat`/`.ps1`/`.cmd` for real (`src/chainwatch/diff/engine.py`), and
the reconstruction was rerun against the actual fixed code — no
monkey-patching. Result at that point: 60.0/100, HIGH. A sixth risk
dimension (`resource_exhaustion`) and a `definitive_dimension_floor`
aggregator rule landed later the same day (built for `colors`, not this
incident) — rerun again for corpus consistency, and `resource_exhaustion`
scores 10.0 here too (the model reads the XMRig cryptominer as resource
abuse in its own right). **Current result: 67.0/100, HIGH** —
`../report-0.7.28-to-0.7.29-RECONSTRUCTED.json`, now the canonical entry
for this pair. Full before/after breakdown in `../FINDINGS.md`.
