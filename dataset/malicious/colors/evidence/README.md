# Recovered evidence — colors.js (2022)

**Static analysis reference only. Do not execute `index.js` in this
directory** — it contains a live infinite loop by design.

## Why this was easy

Unlike event-stream and ua-parser-js, the colors sabotage was committed by
the *legitimate* maintainer (Marak Squires) to his own GitHub repository —
there was no account hijack, so nothing needed hiding from git. The malicious
commit is still sitting in `Marak/colors.js`'s history, fully attributed.
This is real git provenance, not a CDN cache or a third-party
reconstruction — a stronger source than anything recovered for the other two
incidents in this dataset.

## Files

| File | What it is |
|---|---|
| `american.js` | New file added by the sabotage commit (`lib/custom/american.js`). Prints "LIBERTY LIBERTY LIBERTY" and an ASCII-art flag. |
| `index.js` | The package's entry point (`lib/index.js`) as of the sabotage commit — legitimate code unchanged, with the payload appended: `require('../lib/custom/american')`, call it, then `for (let i = 666; i < Infinity; i++) console.log(...zalgo)` — an unconditional infinite loop that runs on `require('colors')`, i.e. on every process that imports the package. |
| `commit-074a0f8ed0c3.diff` | The exact sabotage commit, `074a0f8ed0c31c35d13d28632bd8a049ff136fb6`, authored by Marak Squires, 2022-01-08T04:19:03Z, message: "Adds new American flag module." This became the npm-published `1.4.44-liberty-2`. |
| `revert-pr-286.diff` | The community's fix, [PR #286](https://github.com/Marak/colors.js/pull/286), reverting the above and bumping to `1.5.0`. |

## Provenance

- Repository: <https://github.com/Marak/colors.js>
- Sabotage commit: `074a0f8ed0c31c35d13d28632bd8a049ff136fb6`
  (author `Marak <marak.squires@gmail.com>`, 2022-01-08T04:19:03Z, parent
  `7ddd6a3d657e...`)
- Immediately followed by two same-day commits: `137c6dae3339` ("Bump to
  `v1.4.44-liberty`") and `6bc50e79eeaa` ("Bump to `v1.4.44-liberty-2`") —
  the latter is the exact tree published to npm as `colors@1.4.44-liberty-2`
  and is `revert-pr-286.diff`'s base.
- Fetched directly via GitHub's commit/PR `.diff` endpoints
  (`github.com/Marak/colors.js/commit/<sha>.diff`), not a third-party mirror.

## What's still not recovered

- The actual `colors@1.4.1` / `colors@1.4.2` npm tarballs (present in the
  registry's `time` metadata, confirming they were published and later
  unpublished, but absent from `versions{}` — no corresponding git commit
  was identified for these two specific version numbers; the git history
  jumps straight to the `v1.4.44-liberty`/`-liberty-2` commits above). CDN
  archaeology (unpkg/jsDelivr via Wayback) found no cached copies of any of
  `1.4.1`, `1.4.2`, or `1.4.44-liberty-2`. Given the git-level source for the
  actual payload is fully recovered and these are almost certainly minor
  version-string variants of the same content, this wasn't pursued further.
