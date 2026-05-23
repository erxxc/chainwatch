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
- `flatmap-stream@0.1.1` published 2018-09-09 by right9ctrl — benign-looking placeholder.
- `flatmap-stream@0.1.2` published 2018-09-09 by right9ctrl — contained malicious payload.
- Incident disclosed publicly 2018-11-20 (npm advisory, GitHub issue #116).
- npm unpublished `event-stream@3.3.6` and both `flatmap-stream` versions shortly after.

## Availability of the attack artifacts

| version | npm registry | Wayback `.tgz` | ossf/malicious-packages | Datadog dataset |
|---|---|---|---|---|
| `event-stream@3.3.4` | available | n/a | — | — |
| `event-stream@3.3.5` | available | n/a | — | — |
| `event-stream@3.3.6` | **unpublished** | 404 on archived tarball URL | advisory JSON only | not present |
| `event-stream@4.0.0` | available (post-incident) | n/a | — | — |
| `flatmap-stream@0.1.1` | **unpublished** | not checked (Wayback rarely caches `.tgz`) | advisory JSON only | not present |
| `flatmap-stream@0.1.2` | **unpublished** | not checked | advisory `MAL-2025-20690` (metadata only) | not present |

The malicious artifacts are **not recoverable from any of the standard public
sources we checked**. The OSV-format advisory JSON in `ossf/malicious-packages`
records the existence of the incident but does not preserve the package contents.

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

## Future work

If the project requires the actual attack diff, possible paths:

- Contact npm Inc. directly — npm retains internal copies of unpublished
  packages for legal/audit purposes and may release them for security research
  under agreement.
- Search older Docker images, university dependency caches, or `node_modules`
  snapshots from late-2018 builds that pinned `event-stream@3.3.6`.
- Reconstruct the payload from public deobfuscation writeups (Snyk, npm,
  several blog posts) — but the result is no longer a real-world artifact and
  weakens the research framing.
