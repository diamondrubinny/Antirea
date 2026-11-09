# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and this project adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

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
- Startup warning when `ADMIN_TOKEN` is shorter than 32 characters.
- Docker image runs as the unprivileged `node` user with read-only app code.
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

- **Docker image failed to build**: it never built `@antirea/watermark`, which
  the collector imports.
- **README Quickstart failed on a fresh clone** for the same reason; it now
  builds all packages from the repo root first.
- Published packages now include `LICENSE` and `NOTICE` (Apache-2.0 §4).
- Website: horizontal overflow on RTL pages and on the privacy table (mobile).

### Added

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
  database is inside the old container at `/app/packages/collector/`. **Stop the
  container first** — SQLite runs in WAL mode, and a copy taken while it runs can
  be missing the schema and recent rows. Then copy the database (and any
  `-wal`/`-shm` files) out and onto the new volume, owned by `node`:
  ```bash
  docker stop <old-container>
  for f in antirea.db antirea.db-wal antirea.db-shm; do
    docker cp <old-container>:/app/packages/collector/$f . 2>/dev/null
  done
  docker run --rm -u root -v antirea-data:/data -v "$PWD":/src --entrypoint sh <new-image> \
    -c 'cp /src/antirea.db* /data/ && chown node:node /data/antirea.db*'
  ```
  Then start the new image with `-v antirea-data:/data`. (Alternatively keep the
  old location by setting `DB_FILE` explicitly.)
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

[0.1.0]: https://github.com/diamondrubinny/Antirea/releases/tag/v0.1.0
