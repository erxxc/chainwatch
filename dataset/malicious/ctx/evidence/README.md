# Recovered payload evidence — ctx (PyPI, 2022)

**Static analysis reference only. Do not execute any file in this directory.**
The exfiltration endpoint (`anti-theft-web.herokuapp.com`) has been dead for
years, but treat these as inert text, not runnable code — same posture
chainwatch itself takes toward untrusted package code.

## Why these files exist

The `ctx` project on PyPI (`https://pypi.org/project/ctx/`) was deleted
outright following the incident — unlike every other package in this corpus,
there is no live version at all to fetch today (confirmed via direct
registry check: `GET https://pypi.org/pypi/ctx/json` returns `404`). Both
sides of every diff in this incident had to be recovered from archives.

## Files

| File | What it is | SHA256 |
|---|---|---|
| `ctx-0.1.2-original.py` | The real, unmodified `ctx.py` as published 2014-12-19 — the only legitimate release this package ever had. | `75052582ac2f956dcc18adcaaa860e402f5029d727e4948cad57ea054b12d33c` |
| `ctx-0.1.2-1-malicious.py` | The **first** malicious release, uploaded 2022-05-14 (hours after the account takeover). Targets `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`/hostname specifically, sent as plain (non-base64) URL path segments — no obfuscation at all. | `bc9ae9cbf598aae3b77beb188569a8cb3a3f0cda84522d7785066a48a26482c9` |
| `ctx-0.2.5-malicious.py` | The **final** malicious release (2022-05-21, days before takedown). Dumps the *entire* environment, base64-encoded, as one query parameter. Functionally identical to `0.2.6`, the last version ever published. | `116f3c4b0e15046dd1540a2b21da38cfc66c3fd1fd3eb218bb911e0df75e6317` |

Both malicious files also changed `__author__` from `'Robert Ledger'` (the
real, original maintainer) to `'Yunus AYDIN'` — the security researcher who
later publicly claimed responsibility for the takeover as an unauthorized
"demonstration." `__email__` (`figlief@figlief.com`) is untouched in every
version — that address, tied to a domain the original maintainer let expire,
is the actual attack vector (see Provenance below), so the attacker had no
reason to change it.

Three intermediate malicious releases exist between these two
(`0.2`, `0.2.2`, `0.2.3`, `0.2.4`, `0.2.6` — full list in
`PYSEC-2022-199`) but aren't separately reconstructed here; `0.2.3`
specifically is worth naming because it's *broken* — its `sendRequest`
references `os.environ.items()` and `base64.b64encode()` without importing
either `os` or `base64` (only `from os import environ, uname` is present),
so instantiating `Ctx` in that exact version raises `NameError` before the
exfiltration request ever fires. `0.2.5` is the same logic with the import
bug fixed. This detail is corroborated independently: the code the official
GHSA/`python-security.readthedocs.io` writeup quotes verbatim is `0.2.3`'s
broken version, not `0.2.5`'s fixed one — meaning our independently-recovered
copy and the officially-published copy agree on which lines were buggy,
without either being derived from the other.

`requirements.txt` also changed in every malicious release — from empty
(confirmed: the original's `requirements.txt` hashes to git's well-known
empty-blob SHA1, `e69de29b...`) to `Flask==2.1.0` (`0.1.2-1` onward) and
`Flask==2.1.0` + `ctx==0.1.2` (`0.2.3` onward — the attacker's own build
apparently depended on the real package they'd just replaced). This is a
real, verified new dependency-file entry, but **chainwatch's diff engine
never sees it** — `requirements.txt` isn't parsed for dependencies (only
`setup.py`/`setup.cfg`/`pyproject.toml` are) and isn't a recognised source
extension either, so it's invisible to both the structured metadata analyzer
and the LLM's file-level diff view. See `../FINDINGS.md` for why this didn't
end up mattering for classification here, and why it's flagged as an open
item rather than fixed this session.

## Provenance

**"From" side (`ctx-0.1.2-original.py`):** recovered from
[Software Heritage](https://archive.softwareheritage.org/), which has
crawled the `ctx` PyPI origin continuously since before the incident (827
recorded visits). The pre-attack snapshot
(`swh:1:snp:ffd08cc56b09a99a193f8e12c6fd773aa2feff74`, last used
2021-09-01) resolves to exactly one release branch, `releases/0.1.2`,
revision `496d827cbc9b7841b47700f025e7c8a0c3d8810c`, dated
**2014-12-19T07:31:04Z** — matching every vendor writeup's claim that 0.1.2
was untouched for eight years. File fetched directly by content hash
(`sha1_git:a5c4acdcf86b0c4021efa38774e6689618c7e5a6`) via Software
Heritage's content API. Independently cross-checked: byte-identical to the
`ctx.py` inside the `0.1.2` wheel recovered separately via the Wayback
Machine below — two unrelated archives, same bytes.

**"To" side (both malicious files):** recovered from the Wayback Machine's
CDX index of `files.pythonhosted.org`, crawled **2022-05-24** (the day
PyPI removed the project, and the same day the disclosure went public) —
narrow enough that Wayback caught the actual uploaded package files before
every CDN edge purged them:

- `ctx-0.1.2-1.tar.gz`: `https://web.archive.org/web/20220524180938/https://files.pythonhosted.org/packages/41/7a/2e658c7805560d0dcce50a469a0b68f48e78b3f3aa1d7431249f046f60f2/ctx-0.1.2-1.tar.gz`
- `ctx-0.2.5.tar.gz`: `https://web.archive.org/web/20220524180941/https://files.pythonhosted.org/packages/1e/4e/8cdcf228d1d2dd666eacbde59a0cfa994fe58af7287f2272dcd30717a584/ctx-0.2.5.tar.gz`
- `ctx-0.2.6-py2.py3-none-any.whl` (corroboration only, not separately reconstructed): `https://web.archive.org/web/20220524180948/https://files.pythonhosted.org/packages/33/ec/7771d928a431dabd4440dc420ed03029eddc4bd7067ffd0af49052174c6a/ctx-0.2.6-py2.py3-none-any.whl`

Both malicious version strings (`0.1.2-1`, `0.2.5`) are independently
confirmed as officially-listed affected versions in OSV's `PYSEC-2022-199`
record (queried live for this write-up), which lists the complete set:
`0.1.2-1, 0.1.2-2, 0.1.4, 0.2, 0.2.1, 0.2.2, 0.2.2.1, 0.2.3, 0.2.4, 0.2.5,
0.2.6`.

Secondary sources for the incident narrative (attribution, domain-takeover
mechanism, discovery timeline — not used for code, only cross-checked
against it):

- [PyPI's own incident writeup, mirrored at python-security.readthedocs.io](https://python-security.readthedocs.io/pypi-vuln/index-2022-05-24-ctx-domain-takeover.html) — the only secondary source found that quotes the malicious code verbatim (the `0.2.3` variant, see above).
- [Sonatype — "PyPI Package 'ctx' and PHP Library 'phpass' Compromised"](https://www.sonatype.com/blog/pypi-package-ctx-compromised-are-you-at-risk)
- [BleepingComputer — "Popular Python and PHP libraries hijacked to steal AWS keys"](https://www.bleepingcomputer.com/news/security/popular-python-and-php-libraries-hijacked-to-steal-aws-keys/)
- [Orca Security — "Supply Chain Attack: CTX and PHPass"](https://orca.security/resources/blog/python-supply-chain-attack-ctx-phpass/)
- [GHSA-4g82-3jcr-q52w](https://github.com/advisories/GHSA-4g82-3jcr-q52w), [GHSA-67r3-h899-9w95](https://github.com/advisories/GHSA-67r3-h899-9w95), [PYSEC-2022-199](https://github.com/pypa/advisory-database/blob/main/vulns/ctx/PYSEC-2022-199.yaml) (all queried live via OSV for this write-up)

`phpass` (the companion PHP/Packagist incident, same attacker, same
exfiltration endpoint, targeting `AWS_ACCESS_KEY`/`AWS_SECRET_KEY` from a
`PasswordHash.php` file) is **not** reconstructed here — chainwatch's
`Ecosystem` enum supports only `npm` and `pypi` (`src/chainwatch/models.py`),
and Packagist/PHP is out of scope.

## Reconstruction run (2026-08-11)

Same "diff two local directories, bypass the registry fetch entirely"
mechanic used elsewhere in this corpus, but closer in shape to
`flatmap-stream` than to `node-ipc`/`colors`/`ua-parser-js`: there is no
live tarball on *either* side, so both directories are assembled from the
archived material above rather than a real chainwatch fetch.

| local directory | contents | source |
|---|---|---|
| `from/` (both pairs) | The real 0.1.2 sdist scaffold (`setup.py`, `setup.cfg`, `MANIFEST.in`, `LICENSE`, `README.rst`, `PKG-INFO`, `requirements.txt`, `requirements-dev.txt`) plus `ctx-0.1.2-original.py` as `ctx.py` | Software Heritage (see above) |
| `to/` (pair 1) | The complete, real `ctx-0.1.2-1.tar.gz` contents as uploaded — `ctx-0.1.2-1-malicious.py` as `ctx.py`, plus that release's real `requirements.txt` (`Flask==2.1.0`) and incidental scaffolding (`test_ctx.py`, `.travis.yml`, `Makefile`, `.gitignore`, `tox.ini`, `ctx.egg-info/`) that the attacker's own rebuild picked up | Wayback Machine (see above) |
| `to/` (pair 2) | The complete, real `ctx-0.2.5.tar.gz` contents as uploaded — `ctx-0.2.5-malicious.py` as `ctx.py`, plus that release's real `requirements.txt` (`Flask==2.1.0` + `ctx==0.1.2`) and the same incidental scaffolding | Wayback Machine (see above) |

Run directly against the current codebase (no monkey-patching, no
allowlist edits) — this is the first incident in the corpus sourced and
reconstructed *after* every 2026-08-10 fix rather than before it, so there's
only one set of numbers, not a before/after pair:

- **`0.1.2` → `0.1.2-1`: 41.5/100, MEDIUM** —
  `../report-0.1.2-to-0.1.2-1-RECONSTRUCTED.json`
- **`0.1.2` → `0.2.5`: 52.0/100, MEDIUM** —
  `../report-0.1.2-to-0.2.5-RECONSTRUCTED.json`

Full dimension breakdown and discussion in `../FINDINGS.md`.
