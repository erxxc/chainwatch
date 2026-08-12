# ctx — chainwatch findings

Two pairs, both directory-level reconstructions (real LLM + real feeds),
`claude-sonnet-4-6`, run 2026-08-11 — the corpus's first incident sourced
and reconstructed *after* every 2026-08-10 fix (`resource_exhaustion`,
`_apply_dimension_floor`, `SOURCE_EXTENSIONS`) rather than before it, so
there is only one set of numbers here, not a before/after pair. See
`SOURCING.md` for why this incident and `evidence/README.md` for exactly
how both sides were recovered (there is no live tarball on either side).

## Summary

| pair | role | risk | LLM base | feed-adjusted | OSV | Rekor | Scorecard |
|---|---|---|---|---|---|---|---|
| `0.1.2 → 0.1.2-1` *(reconstructed)* | first malicious release — plain-text exfil | **MEDIUM** | 41.5 | 41.5 | suspicious (3× advisory) | no_data | no_data |
| `0.1.2 → 0.2.5` *(reconstructed)* | final malicious release — base64 full-env exfil | **MEDIUM** | 52.0 | 52.0 | suspicious (2× advisory) | no_data | no_data |

Both scores are the raw `llm_base_score` — **zero feed modifiers applied to
either pair.** This is the only pair of reports anywhere in this corpus
where the composite score is entirely and exclusively LLM-driven: OSV never
reaches `MAL-*` (see below), and Scorecard has nothing to evaluate because
the GitHub repository chainwatch's Scorecard client tries to resolve no
longer meaningfully exists for a fully-deleted PyPI project. No tarball
hashes — both `from_version_sha256`/`to_version_sha256` are `null`, same
convention as every other reconstruction in this corpus.

## Why this incident matters more than its score

**This is the first ground-truth positive in the corpus that neither
`resource_exhaustion` nor `_apply_dimension_floor` had any hand in
classifying correctly** — the two mechanisms that closed `colors`'/
node-ipc's gaps were designed by observing failures on the four incidents
that predate this one, and this incident is the first genuinely independent
check on whether chainwatch's detection actually generalises past those
four (`dataset/findings/README.md` recommendation #7).

The result: `resource_exhaustion` correctly scores **0.0 at confidence 1.0**
on both pairs (this attack doesn't loop, doesn't recurse, doesn't block —
there's nothing for that dimension to find, and it correctly finds
nothing). `_apply_dimension_floor` never triggers on either pair, not
because it *couldn't* — `env_conditional` reaches exactly 9.0 at confidence
1.0 on pair 1, which meets the trigger threshold — but because the floor
rule is a no-op whenever the base score already clears 30
(`_apply_dimension_floor`'s own short-circuit: `if base_score >=
_DEFINITIVE_DIMENSION_FLOOR_SCORE: return base_score, []`), and pair 1's
base score is already 41.5. Both pairs are classified correctly by the
**original five dimensions working as originally designed**, on an attack
shape none of them were tuned against. That's the reassuring outcome the
overfitting caveat asked for — not proof the newer mechanisms generalise
(this incident doesn't stress either of them), but proof the *rest of the
pipeline* does, on a real attack sourced independently of every incident
that shaped it.

## Per-pair detail

### `0.1.2 → 0.1.2-1` — the first, simplest malicious release

- **What changed.** `__author__`/`import requests`/`from os import environ,
  uname` added; `Ctx.__init__` (previously absent — the original class had
  no constructor at all) reads `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`,
  and the machine hostname, then GETs them as plain URL path segments to
  `anti-theft-web.herokuapp.com`. No encoding, no obfuscation whatsoever —
  the secret values appear in the URL exactly as read from the environment.
  A `test_ctx.py` file is also added (incidental — part of the real uploaded
  tarball, not attack logic; see `evidence/README.md`).
- **LLM dimensions:**

  | dimension | score | confidence | reasoning (abridged) |
  |---|---|---|---|
  | network_calls | 10.0 | 1.0 | "explicit HTTP GET request to 'anti-theft-web...'" |
  | obfuscation | 1.0 | 1.0 | "No obfuscation is present... plain, readable Python" |
  | install_hooks | 0.0 | 1.0 | "No setup.py... postinstall or preinstall hooks" |
  | env_conditional | 9.0 | 1.0 | "explicitly reads AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and COMPUTERNAME env..." |
  | dependency_changes | 6.0 | 0.9 | "`requests` library is newly imported in ctx.py" |
  | resource_exhaustion | 0.0 | 1.0 | "No unbounded loops, recursion... single request" |

  `llm_base_score = 41.5` (`10×0.20 + 1×0.20 + 0×0.15 + 9×0.15 +
  6×0.10 + 0×0.20`, all ×10). No feed modifier — `risk_score = 41.5, MEDIUM`.
- **Free text:** *"This diff is a definitive supply chain attack... The
  added `test_ctx.py` file serves as camouflage to make the change appear
  legitimate. This matches the well-documented 2022 `ctx` PyPI package
  compromise."* — the model recognised the specific incident by name,
  unprompted, exactly as it has for every other reconstruction in this
  corpus (see `dataset/findings/README.md` RQ1).
- **OSV.** `suspicious`, 3 advisories resolved (`GHSA-4g82-3jcr-q52w`,
  `GHSA-67r3-h899-9w95`, `PYSEC-2022-199`). None `MAL-*` — consistent with
  every incident in this corpus except `flatmap-stream`'s late 2025
  reclassification (`dataset/findings/README.md` RQ1/RQ4).
- **Rekor.** `no_data` — "Sigstore attestation lookup is npm-only (PyPI
  PEP 740 support not implemented)." A real, pre-existing gap
  (chainwatch's Rekor client has never covered PyPI), surfaced here for the
  first time in this corpus because every other PyPI report
  (`dataset/benign/requests/`) happens to also get `no_data`, just less
  visibly since those pairs aren't otherwise borderline.
- **Scorecard.** `no_data` — "Could not resolve GitHub repo for ctx."
  `ctx`'s PyPI metadata (unchanged by the attacker, see `evidence/README.md`)
  points to `github.com/figlief/ctx`; whatever that repository's current
  state is, chainwatch's Scorecard client can't resolve a usable result from
  it. Unlike every other malicious pair in this corpus, there is no Scorecard
  signal pushing the score in either direction here.

### `0.1.2 → 0.2.5` — the final, complete malicious release

- **What changed.** Same shape as `0.1.2-1`, evolved: `sendRequest` now
  iterates *all* of `environ.items()` (not just two named keys), joins the
  values, and base64-encodes the result before sending it as a single query
  parameter. `import base64` added. `Ctx.__init__` is now a one-liner
  (`self.sendRequest()`) — no per-key branching left, just an unconditional
  full-environment dump on every instantiation.
- **LLM dimensions:**

  | dimension | score | confidence | reasoning (abridged) |
  |---|---|---|---|
  | network_calls | 10.0 | 1.0 | "HTTP GET request to 'anti-theft-web...'" |
  | obfuscation | 7.0 | 1.0 | "adds `import base64`... encode all environment variable values" |
  | install_hooks | 0.0 | 1.0 | "malicious behavior is triggered at [import/instantiation] time" |
  | env_conditional | 8.0 | 1.0 | "iterates over ALL environment variables via `environ.items()` and exfiltrat[es them]" |
  | dependency_changes | 6.0 | 0.9 | "`requests` library is newly imported in ctx.py" |
  | resource_exhaustion | 0.0 | 1.0 | "No unbounded loops, recursion... introduced" |

  `llm_base_score = 52.0` (`10×0.20 + 7×0.20 + 0×0.15 + 8×0.15 +
  6×0.10 + 0×0.20`, all ×10). No feed modifier — `risk_score = 52.0, MEDIUM`.
- **Free text:** *"This diff represents a confirmed supply chain attack on
  the `ctx` package... a textbook credential/secret harvesting attack
  targeting anyone who instantiates the `Ctx` class."*
- **OSV.** `suspicious`, 2 advisories (`GHSA-67r3-h899-9w95`,
  `PYSEC-2022-199` — `GHSA-4g82-3jcr-q52w`'s affected range tops out at
  `0.1.4`, per that advisory's own data, so it doesn't resolve against
  `0.2.5`; a real artifact of how that specific advisory's version range
  was written, not a chainwatch bug). Still never `MAL-*`.
- **Rekor / Scorecard.** Same `no_data` as the pair above, same reasons.
- **Take.** Higher `obfuscation` (base64 now genuinely present) and one
  point lower `env_conditional` (marginal — both pairs clearly read as
  "harvests environment variables," the model doesn't meaningfully
  distinguish "two named keys" from "the entire environment" on this
  dimension) combine to a higher composite than `0.1.2-1` — the more
  complete, more obfuscated attack scores higher, which is the correct
  relative ordering even though neither pair individually reaches HIGH.

## Cross-cutting observations

### 1. Neither pair reaches HIGH — and that's a real, structural finding, not a miss

Three of the four pre-existing incidents' complete-attack reconstructions
reach HIGH (node-ipc's wiper 62.5, flatmap-stream 60.0, ua-parser-js 67.0);
`colors` reaches MEDIUM (35.0) only via the floor rule. `ctx`'s two pairs
land at 41.5 and 52.0 — both MEDIUM, neither close to the 55.0 HIGH
threshold — **without any code gap to explain it.** The reason is
structural: `ctx`'s attack shape genuinely doesn't touch the two
highest-weighted dimensions that carry the corpus's HIGH scores.
`install_hooks` is correctly 0.0 (this is an import-time attack, not an
install-time one — nothing runs until something actually does
`from ctx import Ctx; Ctx()`). `resource_exhaustion` is correctly 0.0 (no
DoS component at all). That leaves `network_calls` (maxed, 20 points) and
`env_conditional`/`obfuscation`/`dependency_changes` doing the rest of the
work — enough to clear MEDIUM comfortably, not enough to clear HIGH on
their own. This is arguably the correct relative severity: `ctx` steals
credentials on a lucky trigger (something has to actually instantiate
`Ctx()`, which not every importer does) rather than unconditionally on
`require`/`import` the way node-ipc's wiper or ua-parser-js's miner do, and
it does so via one HTTP call rather than an install-time binary download.
Whether a human security reviewer would agree "less severe than a
destructive wiper" is a real ranking judgment, not a scoring bug — noted
here rather than treated as something to fix.

### 2. `env_conditional` is doing double duty, and it happens to work here

The dimension's stated definition (`models.py`) is "conditional logic gated
on env vars, platform, or CI detection" — code that *branches its behavior*
based on environment state, the canonical example being a payload that
checks `if not process.env.CI` to avoid triggering in automated scans.
`ctx`'s actual pattern is different: it *reads and exfiltrates* environment
variable values — there's no branching on them at all, `Ctx.__init__`
unconditionally sends whatever it finds. The model scored this dimension
8–9/10 anyway, and its reasoning (quoted above) makes clear it's rewarding
"this code touches environment variables in a security-relevant way," not
"this code's control flow is gated by an environment check" — a broader
reading than the dimension's own docstring describes. That broader reading
is what makes this incident classify correctly (`env_conditional` is the
second-largest contributor to both scores), so nothing here is a false
positive — but it's worth being honest that the dimension's real behavior is
somewhat wider than its stated definition, discovered only because this
incident happens to sit in the gap between "gates on env vars" and "reads
env vars for exfiltration." Filed as a documentation/scope question, not a
bug — see recommendation #9 in `dataset/findings/README.md`.

### 3. A real diff-engine blind spot, that didn't end up mattering

`requirements.txt` changed in every malicious release (empty → `Flask==2.1.0`,
later `+ ctx==0.1.2` — see `evidence/README.md`), a genuine new
dependency-file entry. **chainwatch's diff engine never sees it**:
`requirements.txt` is neither a recognised `SOURCE_EXTENSIONS` suffix nor a
parsed `METADATA_FILES` entry (only `setup.py`/`setup.cfg`/`pyproject.toml`
are parsed for Python dependencies — see `src/chainwatch/diff/engine.py`).
`diff_summary.new_dependencies` is empty for both pairs, confirmed directly
against the report JSON. In practice this cost nothing: the LLM's
`dependency_changes` score (6.0/10 on both pairs) came entirely from the
model reading the literal `import requests` / `import base64` lines inside
`ctx.py`'s own diff — a real dependency signal, just sourced from prose-level
code reading rather than chainwatch's structured metadata parser. Filed as
recommendation #10 (parse `requirements.txt`, and consider whether new
top-level `import`/`require` statements should feed `new_dependencies`
directly rather than relying on the LLM to notice them) rather than fixed
this session — it didn't cause a misclassification here, and doing it well
is more design work than a quick allowlist edit (unlike the `ua-parser-js`
`SOURCE_EXTENSIONS` fix, which really was a one-line allowlist gap).

### 4. `maintainer_changed` detection is npm-only

`__author__` changed from `'Robert Ledger'` to `'Yunus AYDIN'` in both
malicious releases (see `evidence/README.md`) — a real, verifiable
maintainer-identity change, the same category of signal `_extract_metadata_diff`
already computes for npm's `package.json` `author` field
(`src/chainwatch/diff/engine.py`). There is no equivalent check for Python's
`setup.py`/`PKG-INFO` author fields; `DiffSummary.maintainer_changed` stays
`False` for both pairs regardless. Same story as observation 3: the LLM
caught it anyway from free-text code reading (*"The author name was also
changed from 'Robert Ledger' to 'Yunus AYDIN', indicating a package takeover
or impersonation"*), so nothing was missed in practice, but the structured
signal that npm packages get doesn't exist for PyPI packages. Filed as
recommendation #10 alongside the `requirements.txt` gap.

### 5. The cleanest "no feed contribution at all" result in the corpus

Every other malicious pair in this corpus gets at least a Scorecard modifier
(`colors`, `node-ipc`'s registry pair) or an OSV `malicious_floor` hit
(`flatmap-stream`). `ctx`'s two pairs get neither — Scorecard can't resolve
a usable GitHub repository for a deleted PyPI project, and OSV never
reaches `MAL-*` here either. Both composite scores are the LLM layer's
`llm_base_score`, unmodified, in full. That both pairs still land clearly
above LOW on LLM signal alone is the single most direct evidence this
corpus has that chainwatch's core detection doesn't depend on feed
enrichment to work — feeds add signal and occasionally decide a bucket
boundary (`flatmap-stream`), but here, where feeds contribute literally
nothing, the LLM layer was sufficient on its own.

## Position in the detection matrix

| package | malicious version available? | did diff-level analysis catch it? |
|---|---|---|
| ctx | Yes — reconstructed from independently cross-corroborated archives (Software Heritage for the benign base, Wayback Machine for both real uploaded malicious sdists); no live tarball exists for any version | **Yes, both pairs** — MEDIUM (41.5/100 and 52.0/100), entirely LLM-driven, with zero contribution from either of the two 2026-08-10 fixes this incident exists to stress-test. The first true out-of-corpus positive check this project has run — see `dataset/findings/README.md`'s "overfitting caveat" for why that matters more than the specific numbers. |
