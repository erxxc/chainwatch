# event-stream — corpus sourcing notes

## Attack summary

In November 2018, a new maintainer (`right9ctrl`) was given publish access to
`event-stream` by the original author (Dominic Tarr). The new maintainer published
`event-stream@3.3.6` with an added dependency on `flatmap-stream@0.1.1` — a package
under their own control. Several days later they published `flatmap-stream@0.1.2`,
which contained obfuscated code that targeted users of the `copay` Bitcoin wallet
and exfiltrated wallet credentials.

Attack timeline:

- `event-stream@3.3.5` published 2018-08-09 by Dominic Tarr — last known-clean release.
- `event-stream@3.3.6` published 2018-09-09 by right9ctrl — added `flatmap-stream` dep.
- `flatmap-stream@0.1.1` published 2018-09-09 by right9ctrl — carries the
  bootstrap/decrypt-loader stage (see `evidence/`); **not** a benign
  placeholder, see the correction note below.
- `flatmap-stream@0.1.2` published 2018-09-09 by right9ctrl — activated/supplied
  the payload the `0.1.1` loader decrypts and runs.
- Incident disclosed publicly 2018-11-20 (npm advisory, GitHub issue #116).
- npm unpublished `event-stream@3.3.6` and both `flatmap-stream` versions shortly after.

## Availability of the attack artifacts

| version | npm registry | unpkg/jsDelivr (via Wayback) | ossf/malicious-packages | Datadog dataset |
|---|---|---|---|---|
| `event-stream@3.3.4` | available | n/a | — | — |
| `event-stream@3.3.5` | available | n/a | — | — |
| `event-stream@3.3.6` | **unpublished** | no capture exists at any CDN | metadata only, confirmed via direct API check | 404, confirmed via direct API check |
| `event-stream@4.0.0` | available (post-incident) | n/a | — | — |
| `flatmap-stream@0.1.1` | **unpublished** | **recovered** — cached by unpkg before takedown, still in Wayback | metadata only, confirmed via direct API check | 404, confirmed via direct API check |
| `flatmap-stream@0.1.2` | **unpublished** | no capture exists at any CDN | metadata only, confirmed via direct API check | 404, confirmed via direct API check |

`event-stream@3.3.6` and `flatmap-stream@0.1.2` are **not recoverable as
tarballs** from any source checked. `flatmap-stream@0.1.1` *is* recoverable —
see `evidence/` for the actual file plus a deobfuscated reconstruction of the
full payload chain (sourced from `es-incident/attack-data`, a paper's
companion artifact repo, cross-validated against the recovered `0.1.1`).
`ossf/malicious-packages` was re-checked directly (not just inferred from its
advisory JSON, which was the earlier basis for this table) and confirmed to
store OSV metadata only, no package contents, by design.

## Research finding

The canonical 2018 `event-stream` supply-chain attack — one of the most-cited
incidents in the literature — cannot be reproduced today from public registry
data. The combination of npm's unpublish policy and the absence of any
mandatory registry archival means a tool like chainwatch cannot retrospectively
diff the attack release at the registry level. This is itself a relevant
observation for the paper:

- **Detection windows shrink as registries evict evidence.** Even when an
  advisory exists (OSV `MAL-*` records both packages), the *content* needed to
  validate a detector against the original payload is gone.
- **Archival is a precondition for reproducible supply-chain security research.**
  Datasets like `ossf/malicious-packages` and `DataDog/malicious-software-packages-dataset`
  focus on newer incidents detected by their own tooling; they don't backfill
  historical attacks whose tarballs were never preserved.
- **Diff-level scanners are structurally blind to transitive-dep attacks.**
  Even if `event-stream@3.3.6` were recoverable, the only diff signal in
  `event-stream` itself is "new dependency added." The actual payload lives in
  the unrelated `flatmap-stream` package. A registry-walking scanner must
  follow dep edges and analyse every new transitive package, not just the
  direct target.

## What we ran instead

To still produce useful corpus output for `event-stream`, we ran the two
adjacent benign pairs that *are* available:

| pair | role | report |
|---|---|---|
| `3.3.4 → 3.3.5` | benign control (version-specifier cleanup, deps unchanged) | `report-3.3.4-to-3.3.5.json` |
| `3.3.5 → 4.0.0` | post-incident "cleanup" diff (skips the unpublished 3.3.6) | `report-3.3.5-to-4.0.0.json` |

Findings from these runs are in `FINDINGS.md`.

## Recovered evidence (2026-08-07)

`evidence/` now holds the actual `flatmap-stream@0.1.1` file (recovered from
a Wayback Machine capture of unpkg's CDN cache, predating npm's takedown) plus
a full deobfuscated reconstruction of the three-stage payload chain — bootstrap
decrypt-loader, the Copay build-time ReedSolomonDecoder.js injector, and the
RSA-encrypting credential harvester that exfiltrates to `copayapi.host` /
`111.90.151.134` — sourced from `es-incident/attack-data`, the companion
repository to a published paper analysing this exact incident. The `0.1.1`
recovery and the paper's copy were independently cross-validated
byte-for-byte. See `evidence/README.md` for full provenance and per-file hashes.

This corrects the `flatmap-stream@0.1.1` "benign-looking placeholder"
characterisation above — it isn't benign, it's the bootstrap stage.

This is real payload code, not a full registry tarball — the composed
`event-stream@3.3.6` / `flatmap-stream@0.1.2` packages (with valid
`package.json`, complete `test/data` ciphertext resolved, etc.) are still not
reconstructable, and `test-data.js`'s two AES-256 blobs remain encrypted
(the key only resolves inside a Copay release build). Sufficient for citing
and statically describing the attack; not sufficient to run through
chainwatch's registry-fetch pipeline.

## Still missing / future work

- `event-stream@3.3.6` itself — even just the one-line `package.json` diff
  adding the `flatmap-stream` dependency — was never captured by unpkg,
  jsDelivr, or Wayback's tarball crawl (confirmed via direct CDX lookups).
- `flatmap-stream@0.1.2`'s own file diff versus `0.1.1` (unpkg never
  successfully served any file from `0.1.2`, per the archived crawl attempts).
- The two AES-256 ciphertext blobs in `test-data.js` decrypted to plaintext.
- Contacting npm Inc. directly (out of scope for this pass — the standard
  public-source options above were exhausted first, per project direction).
