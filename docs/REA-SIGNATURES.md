# REA signature pack

Defensive fingerprints for the `morluto/rea` reverse-engineering MCP tool,
derived from its public source. Each entry names the **source file it was
verified against**, the **layer** that detects it, and its **evadability** — we
do not claim a signature is conclusive when it is not.

> These detect REA running **against your own site**. They let your server
> serve decoys or your telemetry flag the attempt. They do nothing to REA
> itself or to third parties.

## How REA touches a target (so you know what is detectable)

| REA path | Source | Reaches your origin? | Detect at |
|---|---|---|---|
| CDP attach + source read | `src/browser/CdpEndpoint.ts` | No — loopback `127.0.0.1/json/*` only | **Client** (guard: `cdp.ts`) |
| Source-map fetch | `src/browser/WebSourceMapFetcher.ts` | **Yes** — direct `fetch` to your origin | **Server** (honeypot: `scoring.ts`) |
| Playwright scenario requests | `src/browser/PlaywrightScenarioRequest.ts` | Yes, but via the page's own `fetch` (looks like the real browser) | **Client** (guard: `rea.ts`, launch defaults) |
| Static bundle analysis | `analyze-javascript-application` | No — reads local files | n/a (nothing served) |

## Server-side signatures (`@antirea/honeypot`)

### `rea.sourceMapAccept` — near-certain
REA's source-map fetcher sends:
```
Accept: application/json, application/source-map+json;q=0.9
credentials: "omit"          // no Cookie
referrerPolicy: "no-referrer" // no Referer
redirect: "manual"
```
*(verified: `src/browser/WebSourceMapFetcher.ts`, `fetchFollowingApprovedRedirects`)*

No browser sends the `application/source-map+json` media type. Matching that
token alone scores **0.85**. **Evadability:** low — the Accept value is
hardcoded in REA; an attacker would have to patch REA's source.

### `rea.sourceMapShape` — supporting
A `.map` request with **no `Cookie`, no `Referer`, no `Sec-Fetch-*`** matches
the fetcher's shape (`credentials:"omit"`, `referrerPolicy:"no-referrer"`,
native `fetch`, no browser metadata). Scores **0.5**. **Evadability:** medium —
other CLI fetchers (curl, wget, scripts) look similar, which is fine: they are
also not your app.

## Client-side signature (`@antirea/guard`)

### `rea.playwrightDefaults` — strong-but-evadable
REA's scripted-browser scenarios launch Playwright with these **defaults**:
```
headless: true · locale: "en-US" · timezone: "UTC" · color_scheme: "light"
reduced_motion: "reduce" · viewport: 1280x720 · device_scale_factor: 1
service_workers: "block"
```
*(verified: `src/domain/browserScenarioValues.ts`)* plus Playwright's
`navigator.webdriver = true`.

`rea.ts` scores the **combination**: it fires only when a strong core
(`navigator.webdriver` or an exact 1280×720 viewport) is present **and** at
least 4 of the 7 markers align — a profile a real user almost never produces
(UTC + reduced-motion + 1280×720 + DPR 1 + webdriver together). Confidence
scales with the number of matching markers (up to 0.9).

**Evadability:** medium. An operator can override `locale`, `timezone`,
`viewport`, and `color_scheme` in the scenario spec, defeating those markers.
`navigator.webdriver` and headless are harder to hide. This catches REA's
out-of-the-box configuration.

## What is NOT a usable signature (and why)

- **Playwright request headers.** Scenario requests use the page's own `fetch`
  with the real browser's headers/cookies (`src/browser/PlaywrightScenarioRequest.ts`),
  and REA's spec **forbids** setting `cookie`/`referer`/`user-agent`/`sec-*`
  (`browserScenarioValues.ts`). So these requests look legitimate at the header
  level — blocking on headers would hit real users. Use the launch-defaults
  fingerprint and behaviour instead.
- **CDP endpoint.** Loopback only; never reaches your origin. Only the
  client-side effects of an attached debugger are observable — see `cdp.ts`
  (`debugger`-timing, which REA's passive capture does not suppress).

## The honest bottom line

These raise the cost of an out-of-the-box REA run and make attempts visible in
the dashboard. A patient operator who patches the Accept header and overrides
the Playwright defaults evades the client/header layer. The only hermetic
protection for proprietary logic remains server-side execution
(`@antirea/secure-fn`). Signatures are deterrence and intelligence, layered on
top of that.

## Verify for yourself

```bash
# Confirm the signatures against the current source before relying on them.
git clone https://github.com/morluto/rea && cd rea
grep -n "source-map+json" src/browser/WebSourceMapFetcher.ts
grep -n "default(true)\|1280\|\"UTC\"\|reduce" src/domain/browserScenarioValues.ts
```
Signatures were verified against the `main` branch; re-check after REA updates.
