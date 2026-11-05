# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and this project adheres to
[Semantic Versioning](https://semver.org/).

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
