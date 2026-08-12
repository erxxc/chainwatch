# ctx — corpus sourcing notes

## Why this incident, and why now

Every other incident in this corpus was reconstructed to close a gap
`chainwatch` itself surfaced — the fixes that resulted
(`resource_exhaustion`, `_apply_dimension_floor`, `SOURCE_EXTENSIONS`) were
all designed by observing failures on `node-ipc`/`colors`/`event-stream`/
`ua-parser-js` and validated only against that same four-incident corpus
(see `dataset/findings/README.md`'s "overfitting caveat"). `ctx` is
different on purpose: it's the corpus's first incident chosen and
reconstructed *after* every one of those fixes already existed, specifically
to test whether they generalise to an attack none of them were shaped by —
recommendation #7 in that write-up. It's also the corpus's first PyPI
malicious example (the other four are all npm), and the first single-vector
attack in the corpus that is neither an install hook nor a `require`/`import`-time
network payload embedded in a larger legitimate file — it's a full package
takeover where the *entire* published file is small enough to read in one
sitting.

## Attack summary

On 2022-05-14, an unknown party registered the expired email domain
(`figlief.com`) tied to the PyPI account of `ctx`'s sole maintainer, used
PyPI's password-reset flow to take over the account, and replaced the
package with versions that read environment variables and exfiltrate them
via HTTP GET to `https://anti-theft-web.herokuapp.com/hacked/...`. The
attack evolved across the malicious releases:

- **`0.1.2-1`** (first malicious upload, 2022-05-14): targets
  `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and the machine hostname
  specifically, sent as plain URL path segments — no encoding at all.
- **`0.2` → `0.2.3`**: narrows to AWS keys only, then widens to *all*
  environment variables, base64-encoded. `0.2.3` has a real bug — it
  references `os.environ`/`base64.b64encode` without importing either,
  so it crashes with `NameError` before exfiltrating anything.
- **`0.2.5` / `0.2.6`** (final, 2022-05-21, days before takedown): same
  full-environment-dump logic, import bug fixed. This is the last code the
  package ever shipped.

On 2022-05-24 the compromise was reported publicly, and PyPI removed the
project entirely — not just the malicious versions, the whole `ctx` listing,
including the original 2014 `0.1.2`. **`ctx` is the only incident in this
corpus with zero live versions today**; `GET https://pypi.org/pypi/ctx/json`
returns `404`.

On 2022-05-25, a security researcher (Yunus AYDIN — the name that appears
as `__author__` in every malicious release) publicly claimed responsibility,
describing it as an unauthorized "demonstration" of package-registry account
security, not a financially-motivated attack. Regardless of motive, it's a
real, unauthorized account takeover and code replacement — the same
ground-truth category as every other incident here.

A companion PHP library, `phpass` (Packagist), was compromised by the same
actor via the same mechanism at the same time, targeting the same
environment variables via the same Heroku endpoint. It is **not**
reconstructed in this corpus — chainwatch's `Ecosystem` enum supports only
`npm` and `pypi` (`src/chainwatch/models.py`); Packagist/PHP is out of
scope.

## Availability of the attack artifacts

Unlike `node-ipc`/`colors` (payload recoverable from git) or `ua-parser-js`
(payload recoverable from vendor writeups onto a still-live base), `ctx`'s
situation is closest to `flatmap-stream`'s: **no live tarball exists on
either side.** Both directories used in this corpus's reconstruction were
assembled from independent archives:

- The original `0.1.2` (benign) was recovered from
  [Software Heritage](https://archive.softwareheritage.org/), which
  crawled the `ctx` PyPI origin continuously from before the incident.
  Byte-identical to the `0.1.2` wheel independently recovered from the
  Wayback Machine — two archives, same bytes.
- Both malicious releases (`0.1.2-1` and `0.2.5`) were recovered as complete,
  real, uploaded sdist tarballs from the Wayback Machine's cache of
  `files.pythonhosted.org`, captured 2022-05-24 — the same day PyPI pulled
  the project.

Full hashes, exact URLs, and cross-corroboration against the officially
published GHSA/`python-security.readthedocs.io` writeup (which happens to
quote the buggy `0.2.3` variant verbatim, an independent confirmation this
recovery didn't derive from) are in `evidence/README.md`.

Checked directly and confirmed empty: `ossf/malicious-packages` (no `ctx`
entry), the Datadog malicious-software-packages-dataset (no `ctx` entry).

## What we ran

No benign "control" pair exists for this package the way other incidents
have one (e.g. `colors@1.3.3→1.4.0`) — `0.1.2` (2014) was `ctx`'s *only*
legitimate release ever, so there is no earlier-version-to-later-version
transition available that doesn't cross into the incident itself. Both
pairs below are reconstructions:

| pair | role | report |
|---|---|---|
| `0.1.2 → 0.1.2-1` (reconstructed) | the first, simplest malicious release — plain-text URL exfiltration, zero obfuscation | `report-0.1.2-to-0.1.2-1-RECONSTRUCTED.json` |
| `0.1.2 → 0.2.5` (reconstructed) | the final, complete malicious release — full-environment base64 exfiltration | `report-0.1.2-to-0.2.5-RECONSTRUCTED.json` |

Both were run directly against the current, fully-fixed codebase (no
before/after — this incident postdates every 2026-08-10 fix) via the same
"diff two local directories, bypass the registry fetch entirely" mechanic
used for `flatmap-stream`/`node-ipc`/`colors`: `chainwatch.diff.engine
.compute_diff()` called directly on the two archived-and-reassembled
directories, then the real LLM analyzer and real feed clients (OSV/Rekor/
Scorecard, queried live by package name and version — no tarball needed for
feed lookups). `from_version_sha256`/`to_version_sha256` are `null` in both
reports, same convention as every other reconstruction in this corpus —
there's no tarball to hash.

**Results (rerun 2026-08-11 after two further diff-engine fixes this
incident's own reconstruction motivated): 42.5/100 MEDIUM (`0.1.2-1`),
56.5/100 HIGH (`0.2.5`).** Original run: 41.5/MEDIUM and 52.0/MEDIUM;
preserved at `pre-pypi-fix-report-*.json`. Neither the `resource_exhaustion`
dimension nor the `_apply_dimension_floor` aggregator rule — the two
mechanisms this incident exists to stress-test — played any role in either
result, before or after the rerun (`resource_exhaustion` scores a correct
0.0 on both; the floor rule never triggers because the base score already
clears 30 through the original five dimensions alone). See `FINDINGS.md`
for the full dimension breakdown, the two diff-engine fixes
(`requirements.txt` parsing, PyPI `maintainer_changed` detection — see
`dataset/findings/README.md` recommendation #10) this incident's own
reconstruction surfaced and then validated the same day, and what all of
this actually means for the overfitting caveat.
