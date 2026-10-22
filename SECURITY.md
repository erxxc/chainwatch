# Security policy

chainwatch is a research tool that deliberately downloads, extracts, and
analyses packages that may be malicious. Its threat model is hostile
package contents and hostile registry or feed responses reaching a
developer's machine through the tool itself. Reports about that boundary
are the ones that matter most here.

## Reporting a vulnerability

Please do not open a public issue for a security problem.

Use GitHub's private vulnerability reporting on this repository
("Security" tab, "Report a vulnerability"). If that option is not
available, open an issue that says only that you have a security report
to make, without details, and a private channel will be arranged.

You can expect an acknowledgement within a week. This is a single-
maintainer research project, not a staffed security team, so fixes are
made on a best-effort basis and credited in the changelog unless you
prefer otherwise.

## Supported versions

Only the latest tagged release and the `main` branch receive fixes. Each
release is archived on Zenodo for citation; archived versions are not
patched in place.

## In scope

- Archive handling: path traversal, symlink or hardlink escapes, size and
  count limit bypasses in the npm and PyPI fetchers.
- Any way package contents, registry metadata, or feed responses can
  execute code, read or write files outside the temp directories, or
  reach hosts other than the configured registries and feeds.
- Leakage of the Anthropic API key or other secrets into logs, reports,
  or requests.
- Prompt-injection paths where package content changes what the tool
  does, as opposed to what the model scores. Scoring itself is the
  subject of the research; see `dataset/findings/README.md` for the
  documented narrative-leakage findings.

## Out of scope

- The model mis-scoring a diff. That is a research finding, not a
  vulnerability; please contribute it to the corpus instead.
- Vulnerabilities in the packages chainwatch is pointed at.
- Denial of service through deliberately enormous packages beyond the
  configured `CHAINWATCH_MAX_*` limits on a machine you control.
