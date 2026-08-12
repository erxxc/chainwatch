# Recovered payload evidence — event-stream / flatmap-stream (2018)

**Static analysis reference only. Do not execute any file in this directory.**
These are historical malware samples/reconstructions from a 2018 npm supply-chain
attack. The C2 infrastructure they reference has been dead for years, but the
files are kept as inert text for provenance and static (AST-level) analysis —
the same posture chainwatch itself takes toward untrusted package code
(see `src/chainwatch/diff/engine.py` — manifests are parsed via AST, never executed).

## Why these files exist

`SOURCING.md` documents that the actual malicious releases
(`event-stream@3.3.6`, `flatmap-stream@0.1.2`) were unpublished from npm and
are not recoverable from the registry, `ossf/malicious-packages`, or the
Datadog malicious-software-packages-dataset (all checked directly — none
carry these artifacts). CDN archaeology (unpkg/jsDelivr via the Wayback
Machine) also came up empty for `3.3.6` and `0.1.2` — no crawler ever
successfully fetched them before npm pulled the versions.

One exception: `flatmap-stream@0.1.1` *was* cached by unpkg before takedown,
and Wayback still has it. Everything else here is a faithful deobfuscation
from `es-incident/attack-data`, the companion artifact repository for
["A Systematic Analysis of the Event-Stream Incident"](https://es-incident.github.io)
(an academic paper analysing this exact attack) — independently cross-validated
below.

## Files

| File | What it is | SHA256 |
|---|---|---|
| `flatmap-stream-0.1.0-index.min.js` | Last clean release before the takeover — no malicious code. Included for diffing against 0.1.1. | `54ac6eb72bc3126811b68b20e4627e94805034503b540ecfdca60a88f0d017a7` |
| `flatmap-stream-0.1.1-index.min.js` | **Actual minified file as served by unpkg**, recovered from the Wayback Machine (see Provenance below). Contains the full bootstrap/decrypt-loader IIFE appended after the legitimate flat-map-stream code. | `3c7079f735f0fc01192c8e65e46b580f52ae7bfe34b11424a1dee5e5b9d2d466` |
| `payload_a_bootstrap_deobfuscated.js` | Pretty-printed form of the loader IIFE in `0.1.1`: `require('./test/data')`, reads `process.env.npm_package_description` as an AES-256 key, decrypts, `eval`s the result via a fresh `module.constructor`. | `8cad08e264806e08f237877762f977ec2bdfd8e38b0e0ee14c7119536c32d647` |
| `payload_b_reedsolomon_injector_deobfuscated.js` | Second-stage payload. Only runs when `process.argv[2]` matches `build:*-release` (i.e. inside a release build). Decrypts a second AES-256 blob using the same `npm_package_description` key and splices it into `node_modules/@zxing/library/.../ReedSolomonDecoder.js` — a dependency of the Copay Bitcoin wallet's build — then restores the original file on process exit to hide the tampering. | `30d319666e33ed08446abc25e9baede5c3a1e4f69511feb7aa4c3514a947b7fa` |
| `payload_c_credential_harvester_deobfuscated.js` | Third-stage payload spliced in by payload B. RSA-encrypts (hardcoded public key) and exfiltrates wallet data in 200-byte chunks via HTTP POST to two hosts, hex-encoded in the source: `636f7061796170692e686f7374` = `copayapi.host`, `3131312e39302e3135312e313334` = `111.90.151.134`. | `db2757a86d530275c17db9114fb96bc30db30f5526474a6d775572ebee32747a` |
| `test-data.js` | The actual `./test/data` module `payload_a` requires: two long AES-256 ciphertext blobs (payloads B and C, still encrypted) plus the hex-encoded string table (`env`, `npm_package_description`, `aes256`, `createDecipher`, `_compile`, `hex`, `utf8`) that `payload_a` decodes at runtime. | `13b1e28069806c6aff1dcd27199b6c757cb94ebdd2ec0a9df1f7301ca496346b` |

The ciphertext blobs in `test-data.js` are **not decrypted** here — the key is
`process.env.npm_package_description`, which only resolves correctly inside a
Copay release build (`"description": "A Secure Bitcoin Wallet"`), which is the
entire point of the targeting mechanism. The plaintext of payload B/C above
comes from `es-incident/attack-data`'s own deobfuscation, not from us
decrypting `test-data.js` ourselves.

## Provenance

- **`flatmap-stream-0.1.1-index.min.js`** (unpkg cache, via Wayback Machine):
  `https://web.archive.org/web/20181128045746/https://unpkg.com/flatmap-stream@0.1.1/index.min.js`
  (capture timestamp 2018-11-28 04:57:46 UTC — 11 weeks after publish, still
  live in the CDN edge cache at crawl time). Independently fetched and
  confirmed byte-identical (code body) to the copy in `es-incident/attack-data`.
- **All other files**: `es-incident/attack-data` (commit as of 2022-03-09),
  companion repo to <https://es-incident.github.io/paper.html>.
- Corroborating secondary sources for the attack mechanism (not quoted
  directly, used to sanity-check the above): the disclosure thread at
  <https://github.com/dominictarr/event-stream/issues/116>, and
  [Snyk's post-mortem](https://snyk.io/blog/a-post-mortem-of-the-malicious-event-stream-backdoor/).

## Correction to `SOURCING.md`

The original sourcing notes characterised `flatmap-stream@0.1.1` as a
"benign-looking placeholder." That's wrong — the recovered file shows `0.1.1`
already carries the full bootstrap/decrypt-loader mechanism (`payload_a`
above). What was likely true is that *running* it does nothing observable
without `test/data`'s specific ciphertext and the Copay-specific env var, so
it *looks* inert under casual inspection — but the code itself is the load-bearing
first stage of the attack, not a placeholder. `SOURCING.md` has been updated.

## Reconstruction run (2026-08-10)

Same "diff two local directories, bypass the registry fetch entirely"
mechanic used for `node-ipc`/`colors` (see their `evidence/README.md`), but
sourced differently — there is no live base tarball for `flatmap-stream`
anywhere (npm serves only a security-holding placeholder for every version
string, confirmed via a direct registry check the day of this run), so the
"before" side comes from the same CDN-archaeology/paper-corpus evidence
already committed here, not a real npm download:

| local directory | contents | source |
|---|---|---|
| `0.1.0/index.min.js` | `flatmap-stream-0.1.0-index.min.js` verbatim | `es-incident/attack-data` (no live CDN capture of `0.1.0` exists — see table above) |
| `0.1.1/index.min.js` | `flatmap-stream-0.1.1-index.min.js` verbatim | Wayback-recovered unpkg cache, cross-validated against the paper corpus |
| `0.1.1/test/data.js` | `test-data.js` verbatim | `es-incident/attack-data`; module path resolved from the hex-decoded `require(e("2e2f746573742f64617461"))` → `./test/data` in `payload_a` |

Before running, every file placed in either directory was re-hashed and
checked against the SHA256 values already published in the table above —
byte-identical, same fidelity guarantee as the git-commit-based
reconstructions.

No `package.json` was recoverable for either version from any source
checked (unlike `node-ipc`/`colors`, where a real base tarball supplied
one) — see "Still missing" in `SOURCING.md`. It was not fabricated; the
diff engine handles its absence gracefully (metadata-diff fields all read
empty/false, correctly, since there's nothing to compare), and the omission
is disclosed here rather than papered over with an invented manifest.

Result: **60.0/100, HIGH** — `dataset/malicious/event-stream/report-flatmap-stream-0.1.0-to-0.1.1-RECONSTRUCTED.json`.
Full breakdown in `../FINDINGS.md`.
