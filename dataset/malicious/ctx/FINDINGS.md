# ctx — chainwatch findings

Two pairs, both directory-level reconstructions (real LLM + real feeds),
`claude-sonnet-4-6`, originally run 2026-08-11 as the corpus's first
incident sourced and reconstructed *after* every 2026-08-10 fix
(`resource_exhaustion`, `_apply_dimension_floor`, `SOURCE_EXTENSIONS`)
rather than before it. **Rerun the same day** after two further fixes
landed — `requirements.txt` dependency parsing and PyPI maintainer-change
detection (`dataset/findings/README.md` recommendation #10, closed by
this incident's own reconstruction). See `SOURCING.md` for why this
incident and `evidence/README.md` for exactly how both sides were
recovered (there is no live tarball on either side).

**Update note:** the pre-PyPI-fix reports are preserved at
`pre-pypi-fix-report-0.1.2-to-0.1.2-1-RECONSTRUCTED.json` and
`pre-pypi-fix-report-0.1.2-to-0.2.5-RECONSTRUCTED.json` for citation. The
second pair's severity bucket changed as a direct result of the fix —
**MEDIUM (52.0) → HIGH (56.5)** — see "The fix, applied to the incident
that motivated it" below.

## Summary

| pair | role | risk | LLM base | feed-adjusted | OSV | Rekor | Scorecard |
|---|---|---|---|---|---|---|---|
| `0.1.2 → 0.1.2-1` *(reconstructed)* | first malicious release — plain-text exfil | **MEDIUM** | 42.5 | 42.5 | suspicious (3× advisory) | no_data | no_data |
| `0.1.2 → 0.2.5` *(reconstructed)* | final malicious release — base64 full-env exfil | **HIGH** | 56.5 | 56.5 | suspicious (2× advisory) | no_data | no_data |

Both scores are the raw `llm_base_score` — **zero feed modifiers applied to
either pair**, unchanged by the fix. This remains the only pair of reports
anywhere in this corpus where the composite score is entirely and
exclusively LLM-driven: OSV never reaches `MAL-*` (see below), and
Scorecard has nothing to evaluate because the GitHub repository
chainwatch's Scorecard client tries to resolve no longer meaningfully
exists for a fully-deleted PyPI project. No tarball hashes — both
`from_version_sha256`/`to_version_sha256` are `null`, same convention as
every other reconstruction in this corpus.

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
because it *couldn't* — `env_conditional` reaches 9.0 at confidence 1.0 on
both pairs post-fix, which meets the trigger threshold — but because the
floor rule is a no-op whenever the base score already clears 30
(`_apply_dimension_floor`'s own short-circuit: `if base_score >=
_DEFINITIVE_DIMENSION_FLOOR_SCORE: return base_score, []`), and both pairs'
base scores already clear 30 on their own. Both pairs are classified
correctly by the **original five dimensions working as originally
designed**, on an attack shape none of them were tuned against. That's the
reassuring outcome the overfitting caveat asked for — not proof the newer
mechanisms generalise (this incident doesn't stress either of them), but
proof the *rest of the pipeline* does, on a real attack sourced
independently of every incident that shaped it.

## The fix, applied to the incident that motivated it

This incident's own reconstruction surfaced two real diff-engine gaps (see
"Cross-cutting observations" below, in their original, pre-fix form,
preserved for history): `requirements.txt` wasn't parsed for dependencies,
and PyPI packages had no `maintainer_changed` equivalent to npm's
`package.json` author check. Both were fixed the same day
(`src/chainwatch/diff/engine.py`; see `dataset/findings/README.md`
recommendation #10 for the full write-up), and this incident was rerun
against the fix — the only incident in the corpus where a diff-engine fix
this session was tested against the *exact* incident that motivated it,
rather than a different one (contrast `ua-parser-js`'s `SOURCE_EXTENSIONS`
fix, motivated by `ua-parser-js` and confirmed there too, versus
`resource_exhaustion`, motivated by `colors` and merely *not regressing*
node-ipc/flatmap-stream/ua-parser-js).

Structurally, post-fix:

- `diff_summary.new_dependencies` now correctly includes `flask` (both
  pairs) and `ctx` (the `0.2.5` pair, whose `requirements.txt` also lists
  the package's own prior version as a dependency — a real artifact of the
  attacker's build process, not a chainwatch bug).
- `diff_summary.maintainer_changed` is now correctly `True` for both pairs
  — closing the exact gap observation 4 (below) described, via the
  module-dunder path specifically, *not* the setup.py path (`ctx`'s
  `setup.py` `author=` kwarg was never touched by the attacker; only
  `ctx.py`'s `__author__` line was — see `src/chainwatch/diff/engine.py`'s
  `_pypi_author` for why both paths are checked independently rather than
  short-circuited).

The LLM layer noticed both changes even before this fix (see the original
cross-cutting observations 3 and 4 below), but only from reading the raw
diff text — the structured signal didn't exist. Post-fix, both dimensions
that use this data moved:

| dimension | `0.1.2-1` pre-fix | `0.1.2-1` post-fix | `0.2.5` pre-fix | `0.2.5` post-fix |
|---|---|---|---|---|
| dependency_changes | 6.0 / conf 0.9 | **7.0 / conf 1.0** | 6.0 / conf 0.9 | **7.0 / conf 1.0** |
| env_conditional | 9.0 / conf 1.0 | 9.0 / conf 1.0 | 8.0 / conf 1.0 | **9.0 / conf 1.0** |

`dependency_changes` went from LLM-inferred (confidence 0.9) to
structurally-confirmed (confidence 1.0) on both pairs, and its score rose
by a point on both — the model treating a diff-summary line reading
`new_dependencies: [flask]` as slightly stronger evidence than spotting
`import requests` unassisted. `env_conditional` only moved on the `0.2.5`
pair (8.0→9.0) — plausibly because the free-text summary now explicitly
names the maintainer-identity change alongside the environment-harvesting
behavior, though the aggregator has no way to attribute *which* input
moved *which* dimension with certainty; this is an LLM-scoring
correlation, not a hardcoded rule. The net effect: `llm_base_score` rose
1.0 point on `0.1.2-1` (41.5→42.5, no bucket change) and 4.5 points on
`0.2.5` (52.0→56.5, **MEDIUM→HIGH**) — `ctx` now has one MEDIUM and one
HIGH pair, joining node-ipc's wiper, flatmap-stream, and ua-parser-js as a
fourth incident whose complete-attack reconstruction reaches HIGH.

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
- **LLM dimensions (post-fix):**

  | dimension | score | confidence | reasoning (abridged) |
  |---|---|---|---|
  | network_calls | 10.0 | 1.0 | "explicit HTTP GET request to 'anti-theft-web...'" |
  | obfuscation | 1.0 | 1.0 | "No obfuscation is present... plain, readable Python" |
  | install_hooks | 0.0 | 1.0 | "No setup.py... postinstall or preinstall hooks" |
  | env_conditional | 9.0 | 1.0 | "explicitly reads AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and COMPU..." |
  | dependency_changes | 7.0 | 1.0 | "Two new dependencies are introduced: `requests`... and `flask`..." |
  | resource_exhaustion | 0.0 | 1.0 | "No unbounded loops, recursion... single request" |

  `llm_base_score = 42.5` (`10×0.20 + 1×0.20 + 0×0.15 + 9×0.15 +
  7×0.10 + 0×0.20`, all ×10). No feed modifier — `risk_score = 42.5, MEDIUM`.
- **Free text:** *"The maintainer field was also changed, indicating a
  possible account takeover or malicious maintainer addition. The addition
  of `flask` as a dependency without any visible usage is suspicious and
  may serve as cover or future payload delivery."* — the model now cites
  the structured `maintainer_changed`/`new_dependencies` signal directly,
  where the pre-fix run could only infer the same facts from prose.
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
- **LLM dimensions (post-fix):**

  | dimension | score | confidence | reasoning (abridged) |
  |---|---|---|---|
  | network_calls | 10.0 | 1.0 | "HTTP GET request to 'anti-theft-web...'" |
  | obfuscation | 8.0 | 1.0 | "encodes all environment variable values using base64..." |
  | install_hooks | 0.0 | 1.0 | "malicious code execute[s]..." (at import/instantiation time, not install time) |
  | env_conditional | 9.0 | 1.0 | "iterates over all environment variables via `environ.items()` and..." |
  | dependency_changes | 7.0 | 1.0 | "Two new dependencies were added: `requests`... and..." |
  | resource_exhaustion | 0.0 | 1.0 | "No unbounded loops, recursion... present" |

  `llm_base_score = 56.5` (`10×0.20 + 8×0.20 + 0×0.15 + 9×0.15 +
  7×0.10 + 0×0.20`, all ×10). No feed modifier — `risk_score = 56.5, HIGH`.
- **Free text:** *"The maintainer field was changed, and the new code
  unconditionally collects all environment variables on every `Ctx()`
  instantiation, base64-encodes them, and exfiltrates them... This is a
  textbook credential-harvesting malware injection targeting any
  environment (CI/CD, development, production) that imports and uses the
  `ctx` package."*
- **OSV.** `suspicious`, 2 advisories (`GHSA-67r3-h899-9w95`,
  `PYSEC-2022-199` — `GHSA-4g82-3jcr-q52w`'s affected range tops out at
  `0.1.4`, per that advisory's own data, so it doesn't resolve against
  `0.2.5`; a real artifact of how that specific advisory's version range
  was written, not a chainwatch bug). Still never `MAL-*`.
- **Rekor / Scorecard.** Same `no_data` as the pair above, same reasons.
- **Take.** Higher `obfuscation` (base64 now genuinely present) and higher
  `env_conditional` (post-fix, both pairs now agree at 9.0 — the model no
  longer meaningfully distinguishes "two named keys" from "the entire
  environment" on this dimension) combine to a higher composite than
  `0.1.2-1` on both the pre- and post-fix runs — the more complete, more
  obfuscated attack scores higher, which is the correct relative ordering,
  and post-fix it's also the correct *absolute* bucket: HIGH for the
  complete attack, MEDIUM for the earlier, cruder one.

## Cross-cutting observations

### 1. HIGH is now reached — a real, structural result, not a miss

Pre-fix, neither `ctx` pair reached HIGH, and that was argued to be a
structural, defensible non-miss (`ctx`'s attack shape doesn't touch
`install_hooks` or `resource_exhaustion`, the two dimensions carrying the
corpus's other HIGH scores). **That argument no longer fully holds for the
`0.2.5` pair** — the fix didn't add a new attack-relevant dimension, it
gave `dependency_changes`/`env_conditional` the structured signal they'd
been missing, and that alone was enough to cross the 55.0 threshold
(56.5). The `0.1.2-1` pair still doesn't reach HIGH (42.5) — its simpler,
narrower payload (two named environment variables, no base64) generates
correspondingly less signal even with the fix applied, which is the
correct relative ordering: **the less complete/severe of the two real
attacks stays MEDIUM, the more complete one reaches HIGH**, matching every
other "complete attack reconstruction" in this corpus. `install_hooks` and
`resource_exhaustion` are still both correctly 0.0 on both pairs — the fix
didn't touch either dimension, it only closed a metadata-parsing gap.

### 2. `env_conditional` is doing double duty, and it happens to work here

The dimension's stated definition (`models.py`) is "conditional logic gated
on env vars, platform, or CI detection" — code that *branches its behavior*
based on environment state, the canonical example being a payload that
checks `if not process.env.CI` to avoid triggering in automated scans.
`ctx`'s actual pattern is different: it *reads and exfiltrates* environment
variable values — there's no branching on them at all, `Ctx.__init__`
unconditionally sends whatever it finds. The model scores this dimension
9/10 on both pairs post-fix anyway, and its reasoning (quoted above) makes
clear it's rewarding "this code touches environment variables in a
security-relevant way," not "this code's control flow is gated by an
environment check" — a broader reading than the dimension's own docstring
describes. That broader reading is what makes this incident classify
correctly (`env_conditional` is the second-largest contributor to both
scores), so nothing here is a false positive — but it's worth being honest
that the dimension's real behavior is somewhat wider than its stated
definition, discovered only because this incident happens to sit in the
gap between "gates on env vars" and "reads env vars for exfiltration."
Filed as a documentation/scope question, not a bug — see recommendation #9
in `dataset/findings/README.md`.

### 3. A real diff-engine blind spot — fixed the same day, tested against this exact incident

`requirements.txt` changed in every malicious release (empty →
`Flask==2.1.0`, later `+ ctx==0.1.2`), a genuine new dependency-file entry.
**chainwatch's diff engine originally never saw it**: `requirements.txt`
was neither a recognised `SOURCE_EXTENSIONS` suffix nor a parsed
`METADATA_FILES` entry. `diff_summary.new_dependencies` was empty for both
pairs in the original run. In practice this cost nothing at the time: the
LLM's `dependency_changes` score (6.0/10, confidence 0.9) came entirely
from the model reading the literal `import requests` / `import base64`
lines inside `ctx.py`'s own diff. **Fixed the same day**
(`src/chainwatch/diff/engine.py`'s `_requirements_txt_dependencies`, see
`dataset/findings/README.md` recommendation #10) and reconfirmed on a
real, non-monkey-patched rerun against this exact incident:
`new_dependencies` now correctly includes `flask` (both pairs) and `ctx`
(the `0.2.5` pair), and `dependency_changes` moved from confidence 0.9 to
1.0 on both pairs. Pre-fix report preserved at
`pre-pypi-fix-report-0.1.2-to-0.1.2-1-RECONSTRUCTED.json` and its `0.2.5`
counterpart.

### 4. `maintainer_changed` detection was npm-only — fixed the same day, via a path this incident specifically needed

`__author__` changed from `'Robert Ledger'` to `'Yunus AYDIN'` in both
malicious releases — a real, verifiable maintainer-identity change, the
same category of signal `_extract_metadata_diff` already computed for
npm's `package.json` `author` field. There was no equivalent check for
Python packages; `DiffSummary.maintainer_changed` stayed `False` for both
pairs regardless, pre-fix. The LLM caught it anyway from free-text code
reading at the time. **Fixed the same day** — but notably, `ctx`'s own
`setup.py` `author=`/`author_email=` kwargs were *never touched* by the
attacker (confirmed by diffing the real recovered `setup.py` files
byte-for-byte — identical across every version, benign and malicious
alike); only `ctx.py`'s module-level `__author__` dunder was. A first
implementation of this fix that checked `setup.py`/`pyproject.toml`
*before* falling back to the module-dunder check would have silently
missed this incident entirely — an unchanged `setup.py` author on both
sides would have short-circuited past the one signal that actually
changed. The shipped fix (`_pypi_author` in
`src/chainwatch/diff/engine.py`) combines all three sources rather than
short-circuiting between them, specifically to avoid that failure mode —
a regression test for exactly this scenario is in
`tests/unit/test_diff_engine.py::TestPyPIMaintainerChanged::test_unchanged_setup_py_author_does_not_short_circuit_dunder_check`.
Post-fix, `diff_summary.maintainer_changed` is correctly `True` on both
pairs, confirmed on a real, non-monkey-patched rerun.

### 5. The cleanest "no feed contribution at all" result in the corpus

Every other malicious pair in this corpus gets at least a Scorecard modifier
(`colors`, `node-ipc`'s registry pair) or an OSV `malicious_floor` hit
(`flatmap-stream`). `ctx`'s two pairs get neither — Scorecard can't resolve
a usable GitHub repository for a deleted PyPI project, and OSV never
reaches `MAL-*` here either. Both composite scores are the LLM layer's
`llm_base_score`, unmodified, in full — unchanged by the diff-engine fix
above, since that fix only affects structured inputs to the LLM layer, not
the feed layer. That both pairs still land clearly above LOW (and, now,
one of them clearly in HIGH) on LLM signal alone is the single most direct
evidence this corpus has that chainwatch's core detection doesn't depend
on feed enrichment to work — feeds add signal and occasionally decide a
bucket boundary (`flatmap-stream`), but here, where feeds contribute
literally nothing, the LLM layer was sufficient on its own, and became
more accurate (not just more confident) once given the structured
metadata it had been missing.

## Position in the detection matrix

| package | malicious version available? | did diff-level analysis catch it? |
|---|---|---|
| ctx | Yes — reconstructed from independently cross-corroborated archives (Software Heritage for the benign base, Wayback Machine for both real uploaded malicious sdists); no live tarball exists for any version | **Yes, both pairs** — MEDIUM (42.5/100) and **HIGH (56.5/100)**, entirely LLM-driven, with zero contribution from either of the two 2026-08-10 fixes this incident exists to stress-test. The corpus's first true out-of-corpus positive check, and the incident whose own reconstruction motivated and validated two further diff-engine fixes (`requirements.txt` parsing, PyPI `maintainer_changed`) the same day — see `dataset/findings/README.md`'s "overfitting caveat" and recommendation #10. |
