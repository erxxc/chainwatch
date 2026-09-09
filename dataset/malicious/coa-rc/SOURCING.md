# coa / rc — corpus sourcing notes

**This is not a canonical corpus entry.** Every other incident in
`dataset/malicious/` has a byte-verified recovered payload behind it. This
one doesn't — the actual attacker code was never recoverable — and this
document exists to record that honestly rather than paper over it. See
`FINDINGS.md` for the full result and exactly what it does and doesn't
demonstrate; see `evidence/README.md` for the complete sourcing trail.

## Why this incident, and why it ended up here

Recommendation #7 in `dataset/findings/README.md` called for ground-truth
positives that would actually stress-test `resource_exhaustion` and
`_apply_dimension_floor` — the two mechanisms `ctx` (this corpus's
previous addition) turned out not to exercise. `coa`/`rc` was picked as a
candidate for the floor rule specifically: a single-vector,
platform-gated, obfuscated postinstall-downloader attack, structurally
similar in shape to `ua-parser-js`'s but from a different incident and
year, that seemed likely to land `install_hooks` at or near the floor
rule's ≥9.0/confidence≥0.9 trigger without other dimensions carrying the
score on their own.

What actually happened: the incident is exceptionally well documented
*behaviorally* (10+ independent sources agree on every mechanical detail)
but the real payload source was never publicly recovered by anyone,
anywhere, in any form more concrete than prose description. Every other
reconstruction in this corpus started from real recovered code and *then*
diffed it; this one had no code to start from. Rather than fabricate
plausible-looking malicious JavaScript and present it as a reconstruction
— which would break the norm every other `SOURCING.md`/`evidence/README.md`
in this corpus holds to — the two directories here use explicitly-labeled
placeholder files instead. See `evidence/README.md` for the full
recoverability investigation.

## Attack summary

On 2021-11-04, npm accounts for `coa` (a command-line option parser, ~9M
weekly downloads, unmaintained since 2018) and `rc` (a config loader,
~14M weekly downloads) were compromised — the same week as, and by
apparently related infrastructure to, the `ua-parser-js` hijack
(`dataset/malicious/ua-parser-js/`) already in this corpus. Malicious
versions added a `preinstall` hook (`"start /B node compile.js & node
compile.js"`) that spawned an obfuscated batch script, which downloaded
and installed the DanaBot password-stealing trojan via `regsvr32`/
`rundll32`. Both packages' malicious versions were live for only ~72
minutes before npm pulled them — `coa`'s advisory (`GHSA-73qr-pfmq-6rp8`)
and `rc`'s (`GHSA-g2q5-5433-rhrf`) were both published the same day, within
minutes of each other.

## What we ran

Both pairs use a real, live "from" side — `coa@2.0.2` and `rc@1.2.8` (the
last legitimate releases, both still `latest` on npm today, fetched via
chainwatch's own npm fetcher) — with the placeholder files from
`evidence/` spliced onto a copy of that same real tree, plus the real,
verified `preinstall` hook line.

| pair | role | report |
|---|---|---|
| `coa 2.0.2 → 2.0.3` | placeholder reconstruction, install hook + verified metadata only | `inconclusive-report-coa-2.0.2-to-2.0.3-PARTIAL.json` |
| `rc 1.2.8 → 1.2.9` | placeholder reconstruction, install hook + verified metadata only | `inconclusive-report-rc-1.2.8-to-1.2.9-PARTIAL.json` |
| `coa 2.0.2 → 2.0.3` *(follow-up)* | same, but with genuinely empty (0-byte) stub files instead of narrated placeholders — a controlled comparison, added 2026-08-11 | `inconclusive-report-coa-2.0.2-to-2.0.3-SILENT-STUB.json` |
| `rc 1.2.8 → 1.2.9` *(follow-up)* | same | `inconclusive-report-rc-1.2.8-to-1.2.9-SILENT-STUB.json` |
| `coa 2.0.2 → 2.0.3` *(third condition)* | the narrated placeholder tree exactly as above, run with `--strip-comments` so the LLM sees the structure but none of the prose — added 2026-09-09 | `inconclusive-report-coa-2.0.2-to-2.0.3-STRIPPED.json` |
| `rc 1.2.8 → 1.2.9` *(third condition)* | same | `inconclusive-report-rc-1.2.8-to-1.2.9-STRIPPED.json` |
| `coa 2.0.2 → 2.0.3` *(third condition, repeat)* | the same run again, to put one number on run-to-run variance — added 2026-09-09 | `inconclusive-report-coa-2.0.2-to-2.0.3-STRIPPED-run2.json` |

**All seven filenames are deliberately prefixed `inconclusive-` and don't
match `report-*.json`** — the naming convention this corpus already uses to
exclude pre-fix/experimental snapshots from every corpus-wide count and
table (see `dataset/findings/README.md`'s "Reproducing this analysis").
None of these seven reports are part of this corpus's precision/recall
statistics, none are listed in the corpus overview table, and none should
be cited as evidence chainwatch would catch a real attack shaped like this
one. See `FINDINGS.md` for why, and for what the comparison between the
narrated and silent-stub conditions actually shows instead.
