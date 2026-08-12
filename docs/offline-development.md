# Offline Development

The core CLI pipeline can be developed and tested without live registry, feed, or
LLM calls.

## What Works Offline

- The npm fetcher is unit-tested with `httpx.MockTransport` — no network. See
  `tests/unit/test_npm_fetcher.py`, which builds real `.tgz` bytes in memory and
  serves npm metadata and tarballs from a mock registry (integrity verification,
  scoped-name encoding, and error paths all covered).
- LLM analysis runs in **stub mode** whenever `ANTHROPIC_API_KEY` starts with
  `sk-ant-test`, returning fixture dimensions without calling the API.
- The OSV, Rekor, Scorecard, and new-dependency-provenance feed clients make
  real HTTP calls but degrade gracefully to `no_data` when the network is
  unavailable; pass `--no-feeds` to skip them entirely. The new-dependency
  client additionally short-circuits to a network-free `clean` result
  whenever a diff introduces no new dependencies — the common case.

> Note: the integration smoke tests in `tests/integration/test_smoke.py` drive
> the CLI end-to-end and **do** fetch real registry packages — run those only
> when online. The unit suite is fully network-free.

The reusable npm test helpers live in:

```text
tests/fixtures/npm_registry.py
```

Use `MockNpmRegistry`, `NpmFixtureVersion`, `npm_tgz`, `npm_integrity`, and
`package_json` when adding new offline npm scenarios.

## Local Environment

The project targets Python 3.11 via `.python-version`.

If dependencies are already available in a local wheelhouse:

```bash
WHEELHOUSE=/path/to/wheelhouse ./scripts/install-offline.sh
.venv/bin/python -m pytest
.venv/bin/python -m ruff check .
.venv/bin/python -m mypy src
```

If there is no local wheelhouse or package cache, dependency installation cannot
be completed fully offline. In that case, the checks available with only stdlib
Python are:

```bash
python3 -m compileall -q src tests
git diff --check
```

## Online Phase

When network access is allowed, use the shortest possible online window to build
the local wheelhouse and install from it:

```bash
./scripts/build-wheelhouse.sh
./scripts/install-offline.sh
.venv/bin/python -m pytest
```

The first command downloads wheels and source distributions into `wheelhouse/`.
The second installs using `--no-index`, so it exercises the same path that future
offline installs will use. The scripts explicitly bootstrap `hatchling` and
`editables` because editable installs need the build backend before the project
itself can be installed.

If a previous install failed partway through, remove the partial environment
before retrying:

```bash
rm -rf .venv
./scripts/install-offline.sh
```

Then run the first live npm checkpoint (uses the installed `chainwatch` entry
point; the LLM stays stubbed under the `sk-ant-test` key):

```bash
ANTHROPIC_API_KEY=sk-ant-test-placeholder \
  .venv/bin/chainwatch --json diff npm lodash 4.17.20 4.17.21 --no-feeds
```

`--no-feeds` avoids live OSV/Rekor/Scorecard lookups, and the LLM analyzer
returns stubbed dimensions. The live part being validated is npm metadata fetch,
tarball download, extraction, diffing, chunking, and report assembly.

## Lockfiles

The `wheelhouse/` and `.pip-cache/` directories are git-ignored — they hold local
binary artifacts. Commit a lockfile (`uv.lock`, `poetry.lock`, …) for resolution
reproducibility; keep wheel artifacts local unless we explicitly decide to vendor
them.
