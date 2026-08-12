# Placeholder evidence — coa / rc (npm, 2021) — NOT a recovered payload

**This directory does not contain recovered malicious code.** Every other
`evidence/` directory in this corpus holds the actual attacker's code,
byte-verified against an independent archive. This one doesn't, and that's
the point — it exists to document a real sourcing failure, not to work
around it.

## Why there's no real payload here

The `compile.js`/`compile.bat` payload from the November 2021 `coa`/`rc`
npm hijack was never recovered. Checked directly:

- **The Wayback Machine's CDX index of `registry.npmjs.org`**: zero
  snapshots exist for any of the six malicious `coa` tarballs (`2.0.3`,
  `2.0.4`, `2.1.1`, `2.1.3`, `3.0.1`, `3.1.3`) or three malicious `rc`
  tarballs (`1.2.9`, `1.3.9`, `2.3.9`). Unlike `ctx` (malicious for ~10
  days before takedown, giving crawlers time to catch it), `coa`/`rc`'s
  malicious versions were live for **roughly 72 minutes** (14:12–15:24
  CET, 2021-11-04) — too narrow a window for any archive to have a chance.
- **unpkg/jsDelivr via the Wayback Machine**: same result, empty.
- **`ossf/malicious-packages`**: checked directly via the GitHub API
  (both the contents listing and a recursive tree fetch) — no `coa` or
  `rc` entry found.
- **The Datadog malicious-software-packages-dataset**: no entry.
- **Ten-plus vendor writeups** (Rapid7, Sonatype, BleepingComputer,
  Heimdal, FOSSA, TheRecord, SecurityAffairs, the GitHub incident thread
  at `veged/coa#99`, the Hacker News discussion thread) all describe the
  attack's *mechanism* in detail and agree with each other, but **none of
  them quote the actual `compile.js`/`compile.bat` source.** One
  BleepingComputer article mentions a deobfuscated screenshot shared by a
  researcher (`_TheEmperors_`) — the image itself was never transcribed to
  text anywhere findable.

## What IS independently verified

Quoted directly from `veged/coa#99` and corroborated by every vendor
writeup checked:

| Fact | Source |
|---|---|
| Exact preinstall hook: `"preinstall": "start /B node compile.js & node compile.js"` | `veged/coa#99`, quoted verbatim |
| Files added: `compile.js`, `compile.bat`, `sdd.dll` | Every writeup, consistent IOC list |
| `compile.js` (obfuscated JS) spawns `compile.bat` as a child process | Rapid7, FOSSA, Heimdal |
| `compile.bat` (obfuscated via variable-expansion) tries `curl`, then `wget`, then `certutil` (a Windows LOLBin) to fetch `sdd.dll` | BleepingComputer, Sonatype |
| Download domain: `pastorcryptograph[.]at` | BleepingComputer |
| `sdd.dll` registered via `regsvr32.exe`, executed via `rundll32.exe` | BleepingComputer |
| Payload identified as the DanaBot password-stealing trojan | BleepingComputer, Sonatype, Heimdal (consistent across all three) |
| VirusTotal hash reference for the payload | OSV `GHSA-73qr-pfmq-6rp8`/`GHSA-g2q5-5433-rhrf`: `26451f7f6fe297adf6738295b1dcc70f7678434ef21d8b6aad5ec00beb8a72cf` |
| Exact malicious versions: `coa` 2.0.3/2.0.4/2.1.1/2.1.3/3.0.1/3.1.3, `rc` 1.2.9/1.3.9/2.3.9 | OSV `GHSA-73qr-pfmq-6rp8`/`GHSA-g2q5-5433-rhrf`, live-queried |

Also notable, and worth flagging even though it isn't decisive: the
dropped filename `sdd.dll` is identical to the one used in this corpus's
`ua-parser-js` incident (`malicious/ua-parser-js/evidence/README.md`),
suggesting a shared threat-actor toolkit or infrastructure across both
2021 hijacks — a real, if circumstantial, cross-incident link.

## The files in this directory

`compile.js`, `compile.bat`, and `sdd.dll` below are **placeholders**, not
reconstructions. Each text file's own header comment states this
explicitly and summarises only the independently-verified facts above —
none of it is fabricated attacker logic, and none of it should be read as
"what the code probably looked like." `sdd.dll` is a plain-text stand-in,
not a DLL.

| File | What it is |
|---|---|
| `compile.js` | Placeholder. Header comment explains the sourcing gap and states the two verified facts about this file (obfuscated JS, spawned `compile.bat`). |
| `compile.bat` | Placeholder. Header comment states the verified facts about this file (variable-expansion obfuscation, curl/wget/certutil download chain, `pastorcryptograph[.]at`, regsvr32/rundll32 execution, DanaBot). |
| `sdd.dll` | Placeholder text file, not a binary. |

### The silent-stub control (2026-08-11 follow-up)

`compile-silent.js`, `compile-silent.bat`, `sdd-silent.dll` are the
control condition for the narrative-leakage follow-up described in
`../FINDINGS.md` — genuinely empty (0 bytes), no comments, no
description of any kind. The only thing distinguishing that "to" tree
from the real, live `from` tree is three new empty files with these exact
real filenames and the real preinstall hook line — no narration at all.
Committed here (even though they carry no information themselves) so the
experiment is fully reproducible from this directory alone.

## What running this through chainwatch actually tests — and doesn't

See `../FINDINGS.md` for the full result — now two results, narrated vs.
silent — and why both are excluded from this corpus's precision/recall
statistics. In short: the four resulting reports
(`inconclusive-report-coa-2.0.2-to-2.0.3-PARTIAL.json`,
`inconclusive-report-rc-1.2.8-to-1.2.9-PARTIAL.json`, and their
`-SILENT-STUB` counterparts — note none of these filenames match
`report-*.json`, so they're excluded from every corpus-wide glob) score
**HIGH with narration present (56.0, 60.0), MEDIUM with it stripped out
(36.0, 31.5)**. That gap — 20 to 28.5 points, enough to flip the severity
bucket both times — is direct, controlled evidence that a diff whose only
"evidence" of maliciousness is descriptive prose (even clearly-labeled
placeholder prose) drives real, quantifiable score inflation on its own,
independent of any actual payload. It's not the whole story, though: even
with zero narration, the silent-stub pairs still land at MEDIUM, not LOW —
a new preinstall hook pointing at unexplained files the package has no
apparent reason to need is itself a real, defensible structural signal,
and the LLM's own reasoning in the silent runs says so explicitly while
appropriately lowering confidence across the board. See `../FINDINGS.md`
and `dataset/findings/README.md` recommendation #8 for the full
before/after and what it does and doesn't establish.
