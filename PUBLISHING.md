# Publishing agentscan

agentscan ships as an npm package so `npx agentscan` works for anyone. This is the
release checklist.

## One-time setup

1. Create the GitHub repo and push (CI runs automatically via `.github/workflows/ci.yml`).
2. Claim the npm name and log in: `npm login`.
3. Decide the public scope. The package is currently unscoped (`agentscan`); if
   the name is taken, switch to a scope like `@yourorg/agentscan` and update
   `package.json` `name` + the README install commands.

## Pre-flight (every release)

```bash
node test/run.js          # must print "N passed, 0 failed"
node bin/agentscan.js --help
npm pack --dry-run        # confirm only bin/, src/, README.md ship (see package.json "files")
```

Verify the tarball does **not** contain: `test/`, `.github/`, `examples/`, any
`.env`, or a `.agentscan/` cache. (`package.json` `files` already restricts this —
double-check the `npm pack` output.)

## Release

```bash
npm version patch     # or minor/major — updates package.json + git tag
git push --follow-tags
npm publish --access public
```

Then smoke-test the published artifact from a clean dir:

```bash
cd /tmp && npx agentscan@latest --help
```

## Versioning

- **Code** changes → bump the npm `version` (semver).
- **Blocklist / CVE feed** changes do **not** require an npm release — bump the
  `version` field inside `src/data/malicious-skills.json` / `src/data/advisories.json`
  and serve them from the remote feed. Users get them via `agentscan --update-feed`.
  (The bundled copies are a floor; see `src/feed.js`.)

## Hosting the live feed (the moat)

The bundled blocklist/advisories are a floor. To keep detection current without
shipping npm releases, host the feeds and point users at them:

1. Serve `blocklist.json` over HTTPS (default URL `https://feed.agentscan.dev/blocklist.json`,
   overridable via `--feed-url` or `AGENTSCAN_FEED_URL`).
2. **Production hardening (do before relying on it):** sign the feed with an
   Ed25519 key and verify a pinned public key in `src/feed.js` before accepting
   an update. Without this, the update path is the weakest link.
3. Keep the `version` date current; the client refuses any feed older than the
   bundled floor.

## What NOT to ship

- No telemetry. A scan makes zero network calls; keep it that way. The only
  network action is the explicit `--update-feed`.
- No new runtime dependencies. The zero-dependency property is a core trust
  feature — a reviewer can read the whole tool. Keep `dependencies` empty.
