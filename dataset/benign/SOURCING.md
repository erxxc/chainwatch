# benign — corpus sourcing notes

## Selection methodology

This is the false-positive baseline: real version-to-version diffs, all
independently known to be safe, chosen specifically because each one hits a
pattern that *looks* like one of chainwatch's five risk dimensions on paper —
new install hook, minified/obfuscated-looking code, new dependency, network
call, or env/platform conditional — but is legitimate. A baseline built from
boring diffs (no hooks, no deps, no minification) wouldn't test anything;
the point is packages that could plausibly trip the heuristics and don't
deserve to.

Each pair was picked by directly diffing the package's real npm/PyPI version
history for a genuine transition matching the target pattern (e.g. scanning
`registry.npmjs.org/{pkg}`'s `versions[].scripts` across time for a
postinstall/preinstall/install hook going from absent to present), not
hand-picked from memory.

| pair | ecosystem | pattern under test | why |
|---|---|---|---|
| `husky@5.0.9 → 5.1.0` | npm | new `install_hooks` | husky (git-hooks manager, ~40M weekly downloads) added a `postinstall` hook in this exact release — verified via the registry's own version history. Its entire purpose is setting up git hooks, so this is about as legitimate as a new install hook gets. |
| `lodash@4.17.20 → 4.17.21` | npm | minified dist / `obfuscation` | Already the canonical example in this repo's README Quick Start. Turned out (see FINDINGS.md) to be a real ReDoS security patch, not just a boring bump — a stronger test than intended. |
| `esbuild@0.27.4 → 0.27.5` | npm | `network_calls` + `env_conditional` | esbuild's `lib/main.js` has permanent platform/arch-detection logic and downloads a native binary via a separate `@esbuild/*` package at install time. A routine patch bump exercises both dimensions without any real risk. Also npm-provenance-attested, letting us exercise the Rekor signing-identity feature end-to-end for the first time in this dataset. |
| `requests@2.31.0 → 2.32.0` | PyPI | `dependency_changes` / large-diff volume | Already the canonical PyPI example in the README Quick Start. Turned out to be a large refactor (flat → `src/` layout, ~5900 changed lines, 10 LLM chunks) — a good test of chunking/truncation behaviour on a legitimately large, legitimately safe diff, not just a small one. |

## Reproducing

```bash
export ANTHROPIC_API_KEY=sk-ant-...
chainwatch --json diff npm husky 5.0.9 5.1.0 > dataset/benign/husky/report-5.0.9-to-5.1.0.json
chainwatch --json diff npm lodash 4.17.20 4.17.21 > dataset/benign/lodash/report-4.17.20-to-4.17.21.json
chainwatch --json diff npm esbuild 0.27.4 0.27.5 > dataset/benign/esbuild/report-0.27.4-to-0.27.5.json
chainwatch --json diff pypi requests 2.31.0 2.32.0 > dataset/benign/requests/report-2.31.0-to-2.32.0.json
```

All four ran against the live pipeline (real Claude analysis, real feed
lookups) on 2026-08-07 with `claude-sonnet-4-6`, no `--no-feeds`. Findings
in `FINDINGS.md`.
