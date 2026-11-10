# Roadmap — making Antirea the leading defence against REA

Scope: **defensive only** — detect, report, and keep proprietary logic off the
client. Nothing here acts on REA itself or on third parties.

Honest framing: "leading" must be earned with published measurements, not
claimed. Only server-side execution (`@antirea/secure-fn`) is hermetic; every
client-side layer is deterrence and intelligence.

## Status (2026-11-09)

- Phase 1 — done (#35).
- Phase 2 — 2.1 done for Express + Fetch-API/Next.js, 2.2 done (#36). 2.3 (typed client) open; Fastify/serverless bridges not verified.
- Phase 3 — 3.1 canary plugin for Vite/Rollup done (#37; SRI insertion and webpack still open). 3.2 signature packs done as validated value overrides, not a rule engine (#38). 3.3 canary webhook alert with HMAC signing done; dashboard REA view done; configurable alert rules still open.
- Phase 4 — 4.1 release workflow prepared (dry-run verified locally; first real publish waits for the npm scope and token). 4.2 done: native-driver job on Node 22/24/26 and HTTP tests for every admin route. 4.3 and 4.4 need the owner.

## Phase 1 — Prove it (measurement)

| # | Item | Outcome |
|---|---|---|
| 1.1 | Signature regression suite: recorded request fixtures per REA version (headers only), asserted against the scorer | Every signature has a test tied to a REA version |
| 1.2 | False-positive corpus: recorded headers of real browsers (Chrome, Firefox, Safari, mobile, proxied) and legitimate server clients | Published FP rate; CI fails if it rises |
| 1.3 | Upstream watch: scheduled CI job that checks for a new REA release and opens an issue to re-verify | Signatures never go silently stale |
| 1.4 | Public compatibility matrix in `docs/REA-SIGNATURES.md` (REA version × signature × verified date) | Users can see what is covered |

## Phase 2 — Make the hermetic layer easy (biggest real protection)

| # | Item | Outcome |
|---|---|---|
| 2.1 | `secure-fn` adapters: Next.js route handler, Fastify, serverless | Moving logic server-side takes minutes |
| 2.2 | Migration guide: how to pick which functions to move, with worked examples | Clear path from "obfuscate" to "do not ship" |
| 2.3 | Typed client generation from the server function registry | No hand-written client stubs |

## Phase 3 — Integration

| # | Item | Outcome |
|---|---|---|
| 3.1 | Vite / webpack plugin: inserts the source-map canary and SRI hashes at build time | One-line setup |
| 3.2 | Versioned signature pack (JSON data, schema-validated) loaded by honeypot | Signature updates without a code release |
| 3.3 | Dashboard: REA view (signals by version), alert rules, webhook on canary hit | Attempts are actionable, not just logged |

## Phase 4 — Release and trust

| # | Item | Needs the owner |
|---|---|---|
| 4.1 | npm publish workflow with provenance | Create the `@antirea` npm scope |
| 4.2 | Already planned: Node 26 native-addon smoke test; HTTP tests for admin routes | — |
| 4.3 | Independent penetration test and accessibility audit | Hire reviewers |
| 4.4 | Docs site with quickstarts per framework | Enable GitHub Pages |

## Risks

- A fork of REA can change every client-visible marker; Phase 2 is the answer,
  not more signatures.
- Fixtures must contain headers only — no captured personal data.
- The signature pack must be data, never executable code.

## Order

Phase 1 first (it tells us where we are actually weak), then 2, 3, 4.
Each item ships as its own small PR with tests.
