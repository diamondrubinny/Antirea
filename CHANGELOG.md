# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and this project adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.2.0] - 2026-11-10

First release intended for npm. Read the upgrade notes at the end of this
section before updating a running collector.

### Security

- **Collector admin auth is now constant-time.** The admin token and the
  honeypot `site-key` are compared via SHA-256 + `crypto.timingSafeEqual`; the
  previous comparison leaked the secret's length and mismatch position.
- **Brute-force protection** on all admin endpoints and `/api/site-config`:
  30 rejected credentials (401/403) per IP per 15 minutes, then `429`; the
  first throttled attempt of each window is audited. Successful requests and
  ordinary 400/404s never count. IPv6 clients are grouped by /56, so rotating
  addresses within one allocation buys no extra attempts.
- `express-rate-limit` 7 → 8 in the collector **and `secure-fn`**: the
  session-issuing limiter of the hermetic core keyed on the full IPv6 address,
  letting one client mint unlimited session tokens by rotating addresses.
- **Client IPs can no longer be forged.** `TRUST_PROXY` now means a number of
  trusted proxy hops; only that hop of `X-Forwarded-For` is used. Previously the
  leftmost (client-supplied) value was trusted, which allowed rate-limit
  bypass and fake geolocation.
- **Audit trail:** structured JSON lines for failed authentication, config
  changes, proposal approve/reject and AI auto-applied changes. Salted IP hash
  only — never the token or raw IP.
- **`secure-fn`: client IP could be forged behind a proxy.** `trustProxy` used
  the leftmost (client-supplied) `X-Forwarded-For` entry; it now means a number
  of trusted hops (`true` = 1), like the collector. The session-issuing limit
  is keyed on that address.
- `secure-fn`: replay nonces are scoped to their session (one session can no
  longer burn another's nonce), must be 1–128 characters, and expired
  rate-limit windows are pruned (memory grew with every session).
- `secure-fn`: the per-session rate limit now runs before the nonce is stored
  (a throttled session could grow the nonce table without bound); anomalies are
  reported once per window; client-supplied function names are escaped in logs.
- `secure-fn` (Express): malformed or oversized JSON returned Express's default
  error page — with a stack trace outside production. It now returns a clean
  `400`/`413`, and non-JSON content types get `415`.
- Alert webhooks: the URL must be `https` (the collector refuses to start
  otherwise), requests time out after 5 s, a non-2xx answer is no longer
  reported as sent, chat text is stripped of control characters, and the
  cooldown table is bounded (it grew with every distinct key).
- Startup warning when `ADMIN_TOKEN` is shorter than 32 characters.
- Docker image runs as the unprivileged `node` user with read-only app code.
- Website CSP: `style-src 'self'` — `'unsafe-inline'` removed (no inline styles
  remain).
- Dependencies: **0 known vulnerabilities** (`minimatch` override for a ReDoS
  advisory in lint tooling). CI now fails on high-severity runtime advisories.

### Changed

- **Node.js 22+ required** (Node 18/20 are end-of-life). CI tests Node 22, 24
  and 26; Docker image uses Node 24 LTS.
- `better-sqlite3` 11 → 13 (the collector could not install on Node 26 before).
- ESLint 9 (end of support) → 10; GitHub Actions moved to current majors
  (Node 24 action runtime).
- Control panel: 9 → **20 languages**, with complete AI-advisor and
  knowledge-base strings in every language (RTL for Hebrew, Arabic, Persian).
- Website: **6 languages** (en, he, es, fr, de, ar) with RTL, localized cookie
  banner and privacy policy; the privacy policy is final (owner-approved).

### Fixed

- Guard lockout page (Hebrew): typo "הזוהתה" → "זוהתה".
- **Docker image failed to build**: it never built `@antirea/watermark`, which
  the collector imports.
- **README Quickstart failed on a fresh clone** for the same reason; it now
  builds all packages from the repo root first.
- Published packages now include `LICENSE` and `NOTICE` (Apache-2.0 §4).
- Build plugin (Vite): now runs after Vite's own plugins (`order: "post"`);
  Vite still rewrote the entry chunk after the plugin ran.
- Honeypot: a real browser's `fetch()`/XHR to a protected non-script path was
  scored 0.2 (`accept.wildcard`) as if it were a navigation — found by the new
  fixture suite; subresource requests are no longer counted.
- Website: horizontal overflow on RTL pages and on the privacy table (mobile).
- Website: links in running text were distinguished by colour alone (WCAG
  1.4.1); the donation section sat outside any landmark; the header forced
  horizontal scrolling at 320px with enlarged text (WCAG 1.4.10).
- Website privacy policy now lists every browser-storage key (`norea_lang` was
  missing; `norea_a11y` is new).
- GitHub Pages deploy now publishes `.well-known/` (hidden directories were
  silently dropped from the artifact).

### Added

- **Typed `secure-fn` client**: `createSecureClient<Api>()` and `call()` check
  the function name, argument and result against the server's function map,
  through a type-only import. `invoke()` is unchanged.
- **webpack 5 canary plugin** (`SourceMapCanaryWebpackPlugin` from
  `@antirea/honeypot/build`) with the same behaviour as the Vite/Rollup one.
- **SRI manifest**: the `sriManifest` option of both build plugins emits
  `sha384` integrity values for every JavaScript file, computed after the
  canary line is added.

- **REA view in the control panel**: a card listing REA-specific signals
  (client `rea.*`, honeypot `rea.*` and the source-map canary) with counts,
  the number of distinct events and when one was last seen; in all 20 panel
  languages. `/api/stats` gains a `rea` field.
- **REA 6.8.0 signature pack** (verified against `morluto/rea` 6.8.0 source and
  measured on real Node and Chromium; see `docs/REA-SIGNATURES.md`):
  - Honeypot: `ua.runtimeFetch` (Node/Bun/Deno built-in fetch),
    `forgery.partialSecFetch` (Sec-Fetch-Mode without Site/Dest — 0 of 11 real
    Chromium request types do this), `acceptLanguage.wildcard`, and
    `ua.headlessClientHint` (HeadlessChrome brand in Client Hints despite a
    spoofed UA). The Node-runtime markers count as **one** fingerprint (0.6),
    below the decoy threshold: a plain Node script harvesting `/assets/app.js`
    scored 0.00 before and 0.60 now (reported), and is decoyed only when
    corroborated — e.g. a REA fork with a changed `Accept` fetching a `.map`
    scores 1.00. A real Chrome request still scores 0, and a real Chrome behind a
    header-stripping proxy is not penalised by the partial-Sec-Fetch rule.
  - Honeypot: **source-map canary** — `sourceMapCanaryComment()` plus the
    `sourceMapCanary` option. REA fetches every map a page declares, browsers
    only with DevTools open, so a hit is strong evidence of analysis (not proof
    of REA). Prefixes match on a directory boundary; the canary path must reach
    the origin (CDN pass-through).
  - Guard: `rea.scenarioSwPolicy` (REA's unique `rea-restore-*` /
    `rea-service-workers-*` markers, also when REA attaches to an open tab) and
    `automation.swBlockPatch` (Playwright's service-worker block; report-only at
    0.5, never halts the app on its own). A zone.js-style prototype wrapper does
    not trigger it.
  - Docs: an honest "what REA can and cannot defeat" table — including that a
    CDP tool attaching *after* an encrypted bundle was decrypted can read it, and
    that the key gate's attestation is forgeable and not a security boundary.
- **`@antirea/secure-fn/web`**: a Fetch-API handler
  (`createSecureFnHandler`) with the same guards as the Express router, for
  Next.js App Router and other Node.js frameworks; Express is now an optional
  peer dependency. Adapters, guards and a migration guide in
  `docs/SECURE-FN.md`.
- **Website accessibility & compliance:**
  - Accessibility statement (`accessibility.html`, 6 languages; WCAG 2.1 AA /
    IS 5568 target, self-assessed — not yet externally audited).
  - Accessibility toolbar (larger text, high contrast, underline links,
    readable font, stop animations); keyboard and screen-reader operable,
    stays above the cookie banner.
  - Localized `404.html`; RFC 9116 `/.well-known/security.txt`; sitemap with
    `hreflang` alternates for every page.
  - Verified with axe-core: 0 violations on every page × 6 languages, toolbar
    open and closed, including high-contrast mode.
- **`@antirea/honeypot/build`**: a Vite/Rollup plugin
  (`sourceMapCanaryPlugin`) that appends a per-chunk source-map canary after
  minification; skipped with a warning when the build emits linked source
  maps. Verified on Vite 8.3 and Rollup 4.68.
- **Release workflow** (`.github/workflows/release.yml`): manual, dry-run by
  default, publishes the seven public packages to npm with provenance. Needs
  the `@antirea` npm scope and an `NPM_TOKEN` secret before a real publish.
- **Collector HTTP tests + native-driver CI job**: a real collector process is
  started on Node 22, 24 and 26; every admin route must reject a missing or
  wrong token, and the brute-force limiter must engage.
- **Canary alerts** (collector): a webhook alert when the honeypot reports a
  source-map canary read (`ALERT_ON_CANARY`, on by default when a webhook is
  set), alongside the existing spike alert. Alerts can be HMAC-signed
  (`ALERT_WEBHOOK_SECRET`) and carry no IP, IP hash, User-Agent or session id.
- **Signature packs** (honeypot): scorer weights and match patterns are data.
  The built-in pack ships as `signatures/default.json`; `honeypot({
  signaturePack })` accepts a strictly validated partial override, so a
  signature update no longer needs a code release. Packs are never fetched
  over the network.
- **Signature regression + false-positive gate** (honeypot): recorded request
  fixtures — measured from real headed Chromium, Playwright-default headless
  Chromium and Node `fetch` with REA's options, plus clearly labelled synthetic
  Firefox/Safari/proxy/service shapes — are scored on every CI run; a signature
  that stops firing or a legitimate client that would be decoyed fails the
  build. Coverage matrix in `docs/REA-SIGNATURES.md`.
- **REA upstream watch**: weekly workflow opens an issue when REA publishes a
  release newer than the verified one.
- Collector test suite (auth, IP extraction, ingest validation).
- npm metadata (`repository`, `homepage`, `bugs`, `keywords`) on all packages.

### Upgrade notes

- **`TRUST_PROXY`**: `true` now trusts exactly **one** proxy. If a CDN *and* a
  reverse proxy sit in front of the collector, set `TRUST_PROXY=2`.
- **Existing Docker volumes** were created by the old root-run image. Make the
  data directory writable by the new non-root user once:
  `docker compose run --rm -u root collector chown -R node:node /data`
- **Docker without compose:** the image now defaults `DB_FILE` to
  `/data/antirea.db`. If you ran the old image without setting `DB_FILE`, your
  database lives inside the old container at `/app/packages/collector/`, so a
  new container cannot see it. Migrate it once with the steps below (verified:
  migrates all rows; refuses to overwrite a volume that already holds a
  database; aborts before touching the volume if the copy fails). Stop the old
  container first — SQLite runs in WAL mode, and a copy taken while it runs can
  miss the schema and recent rows.
  ```bash
  set -e
  docker stop <old-container>
  mkdir antirea-migrate && cd antirea-migrate                    # fresh, empty staging directory
  docker cp <old-container>:/app/packages/collector/antirea.db . # required: fails loudly if missing
  for f in antirea.db-wal antirea.db-shm; do                     # optional (absent after a clean stop)
    docker cp <old-container>:/app/packages/collector/$f . 2>/dev/null || true
  done
  docker run --rm -u root -v antirea-data:/data -v "$PWD":/src --entrypoint sh <new-image> -c '
    set -e
    if ls /data/antirea.db* >/dev/null 2>&1; then echo "refusing: /data already holds a database" >&2; exit 1; fi
    cp /src/antirea.db* /data/ && chown node:node /data/antirea.db*'
  ```
  Then start the new image with `-v antirea-data:/data`. Keep the old container
  until you have checked the data in the control panel.
- **`secure-fn` `trustProxy`**: `true` now trusts exactly one proxy and reads
  the rightmost `X-Forwarded-For` entry. Behind two proxies set `trustProxy: 2`.
  If the app sets Express's own `trust proxy`, that setting wins. A request
  without a nonce now gets `400` instead of `409`; `/invoke` requires
  `Content-Type: application/json` (`415` otherwise).
- **`ALERT_WEBHOOK_URL`** must now be `https` (`http` only for `localhost`);
  the collector exits at startup with a clear message otherwise.
- `TRUST_PROXY` accepts `false`, `true` (= 1) or `1`–`10`; anything else now
  refuses to start instead of silently trusting no proxy. Expose the collector
  only through that proxy chain.

## [0.1.0] - 2026-11-05

Initial public release.

### Added

- **`@antirea/secure-fn`** — server-side execution of proprietary functions
  (the hermetic core): HMAC-signed sessions, nonce anti-replay, per-session
  rate limiting, anomaly reporting. Browser client ships no logic or secrets.
- **`@antirea/guard`** — browser detection library: DevTools/CDP probes
  (`debugger`-timing, stack/RegExp console traps), automation/headless signals,
  integrity (anti-tamper) checks, and a verified REA Playwright-default
  fingerprint. Privacy-preserving, batched telemetry. Ships as ESM + IIFE.
- **`@antirea/honeypot`** — Express middleware with a behavioural detection
  engine that does not trust client headers (velocity, timing regularity,
  harvesting shape, header instability) plus decoy serving with canary tokens.
  Shadow mode by default; optional live config from the control panel.
- **`@antirea/adaptive`** — learns from attacks, builds a knowledge base, and
  proposes bounded defense changes. Optional AI advisor (BYO key); suggest-only
  by default, all proposals clamped to safe bounds.
- **`@antirea/collector`** — ingest API (strict validation, rate limits,
  security headers), optional GeoIP country enrichment, salted-IP storage,
  retention pruning, and a token-gated control panel in 9 languages with RTL.
- **REA signature pack** verified against `morluto/rea` source
  (`docs/REA-SIGNATURES.md`): server-side source-map Accept signature and the
  client-side Playwright-default fingerprint.
- Docker (`Dockerfile` + `docker-compose.yml`), CI (build/test on Node 20 & 22,
  lint + format check), demo GIF/webm, and screenshots.

### Security

- No raw IP persisted (country + salted hash only); minimal telemetry.
- Adaptive AI is human-in-the-loop and bounds-clamped; only aggregated,
  non-PII summaries are sent to the model.
- Zero known dependency vulnerabilities at release (`npm audit` clean).

### Notes

- Honest scope: only server-side execution (`secure-fn`) is hermetic;
  client-side layers are deterrence and intelligence, with per-signal
  evadability documented.
- Privacy policy / lawful basis (GDPR / IL) flagged as requiring legal review.

[0.2.0]: https://github.com/diamondrubinny/Antirea/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/diamondrubinny/Antirea/releases/tag/v0.1.0
