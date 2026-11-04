# Antirea

**Drop-in protection against reverse-engineering and cloning, with a control panel that shows who tried, from where, and how often.**

Any website, SaaS, or app can add Antirea to deter analysis tools (including CDP/DevTools-based ones such as REA), serve decoys to detected harvesters, and — for the logic that actually matters — run it on the server where it can never be reverse-engineered.

> 🌍 Control panel available in English, עברית, Español, Français, Deutsch, العربية, Português, Русский, 中文.

---

## ⚠️ Read this first — what is hermetic, and what is not

Shipping a security tool means being honest about its guarantees. Antirea has **two regimes**:

| What you protect | Can CDP/REA reverse-engineer it? | Antirea's answer |
|---|---|---|
| **Your proprietary logic / algorithm** | **No** — if it never reaches the browser, there is nothing to read | ✅ **`@antirea/secure-fn` — runs it on the server. Hermetic.** |
| **Code that must ship to the browser (UI)** | Yes, eventually — anything sent to a browser can be read | ⚠️ Detection + honeypot + behavioural engine. **Raises cost, not a wall.** |

**There is no client-side technique that makes delivered JavaScript impossible to reverse-engineer.** Anyone claiming otherwise is selling false security. Antirea's *hermetic* guarantee is server-side execution; everything client-side is defense-in-depth that deters, detects, and reports. Use both.

---

## Packages

| Package | Role |
|---|---|
| **`@antirea/secure-fn`** | **The hermetic core.** Runs proprietary functions on the server; client sends inputs, gets outputs. CDP never sees the algorithm. |
| `@antirea/honeypot` | Express/connect middleware. Behavioural detection (IP, cadence, timing, header instability) + serves decoys. Shadow mode by default. |
| `@antirea/guard` | Browser library. Detects DevTools/CDP/automation and reports telemetry. `<script>` or npm. |
| `@antirea/adaptive` | **Learns from attacks** and proposes bounded defense changes. Heuristics always; AI optional (BYO key). Suggest-only by default. |
| `@antirea/collector` | Ingest API + GeoIP + SQLite + the **multi-language control panel** (stats, settings, AI advisor). |

---

## Quickstart

### 1. Run the collector + control panel

```bash
npm install
cd packages/collector && cp .env.example .env
node -e "console.log('IP_SALT='+require('crypto').randomBytes(32).toString('hex'))"
node -e "console.log('ADMIN_TOKEN='+require('crypto').randomBytes(32).toString('hex'))"
# paste both into .env, then:
npm run build && npm start
```

Open `http://localhost:8080/`, enter your `ADMIN_TOKEN`, pick a language.

### 2. Add the honeypot to your server (one middleware)

```ts
import express from "express";
import { honeypot } from "@antirea/honeypot";

const app = express();
app.use(honeypot({
  siteId: "my-site",
  protect: [/^\/assets\/.*\.js$/, /\.map$/],  // the files you want to protect
  mode: "shadow",                              // start here; switch to "live" after tuning
  reportUrl: "https://collector.example.com/api/events",
  allowlist: { verifyReverseDns: true },       // protects Googlebot/Bing → SEO safe
  // Optional: control mode/threshold/allow/block lists live from the panel:
  // config: { url: "https://collector.example.com/api/site-config", siteKey: "<the panel's Site key>" },
}));
app.use(express.static("public"));
```

### 3. Add the guard to your pages (one script tag)

```html
<script src="https://your-cdn/antirea-guard.iife.js"
        data-site-id="my-site"
        data-endpoint="https://collector.example.com/api/events"
        data-mode="silent"></script>
```

### 4. Protect the logic that matters — hermetically

```ts
// SERVER — the algorithm lives here forever; CDP/REA never sees it
import { createSecureFnRouter } from "@antirea/secure-fn";
app.use("/secure", createSecureFnRouter({
  secret: process.env.SECUREFN_SECRET,
  reportUrl: "https://collector.example.com/api/events",
  maxInvokesPerMin: 60,
  functions: { pricing: (args) => ({ result: args.x * 1337 + 17 }) },
}));
```
```ts
// BROWSER — zero proprietary logic, zero secret
import { createSecureClient } from "@antirea/secure-fn/client";
const api = createSecureClient({ endpoint: "/secure" });
const { result } = await api.invoke("pricing", { x: 2 });
```

---

## Control panel

At `http://<collector>/` (behind your `ADMIN_TOKEN`):

- **Live stats** — events, unique sources, timeline, by country, by signal.
- **Top sources** — the most active (hashed) sources and their last action.
- **Protection settings (live)** — toggle protection, switch Shadow/Live, set the detection threshold, manage **Allow/Block IP lists**, and set the **Site key**. Changes are pulled by your honeypot within ~30s — no redeploy. (Requires wiring the honeypot `config` option in step 2.)
- **Languages** — switch instantly; RTL for Hebrew/Arabic.

---

## Behavioural detection — resistant to header tampering

Attackers spoof the `User-Agent` and other headers. Antirea's engine (`@antirea/honeypot`) **does not trust client headers.** It scores server-observed facts:

- **Velocity** — requests per 10s from an IP.
- **Timing regularity** — scripts fire at suspiciously even intervals (low coefficient of variation).
- **Fast cadence** — sustained sub-human request spacing.
- **Harvesting shape** — many distinct asset paths with zero real page navigations.
- **Header instability** — one IP presenting several identities ⇒ forged/rotated headers → **raises** the score. *Tampering with the header works against the attacker, not for them.*
- **Header forgery** — a UA claiming modern Chromium but missing Client-Hints/Sec-Fetch is detected as a lie.

**Honest scope:** this is statistical deterrence. A slow, single-identity scraper can stay under thresholds. For logic that must stay secret, use `@antirea/secure-fn`.

---

## REA signature pack

Antirea ships fingerprints for the `morluto/rea` tool, each **verified against
its public source** and documented with its evadability in
[`docs/REA-SIGNATURES.md`](./docs/REA-SIGNATURES.md):

- **Server (`rea.sourceMapAccept`)** — REA's source-map fetcher sends a
  distinctive `Accept: application/source-map+json` with no cookie and no
  referer (`WebSourceMapFetcher.ts`). No browser does this → near-certain, hard
  to evade (hardcoded in REA).
- **Client (`rea.playwrightDefaults`)** — REA's default Playwright profile
  (headless + `navigator.webdriver` + 1280×720 + DPR 1 + UTC + en-US +
  reduced-motion + light; `browserScenarioValues.ts`). The *combination* is
  distinctive; individual markers are overridable, so this catches defaults.

These are deterrence + intelligence. The hermetic protection remains
`@antirea/secure-fn`.

## CDP / REA specifics

A tool attached via the Chrome DevTools Protocol reads source directly from the engine. For **client code** Antirea adds: a CDP probe in the guard (`debugger`-timing — REA's passive capture does not suppress pauses — plus `Error.stack`/`RegExp.toString` console traps) and **attestation-gated delivery** (`importProtected`) so protected modules are fetched out-of-band and replaced with decoys under CDP. These raise cost; `blackboxing` and a forged attestation header defeat them. For **logic**, `@antirea/secure-fn` is the real answer.

---

## Adaptive AI advisor (optional, `@antirea/adaptive`)

Learns from the attacks it sees and proposes defense changes. **Off by default; turn it on in the collector's `.env` (`AI_ENABLED=true` + an API key).**

- **Heuristics run always** (no key needed): they summarize recent events, build a **knowledge base** of recurring attack signatures (signal combos, with confidence that grows as a pattern recurs), and propose bounded tweaks.
- **AI advisor (BYO key, default Claude `claude-opus-5-5`)**: sends only an **aggregated, non-PII summary** (counts, country codes, signal names — never raw IPs or User-Agents) and returns analysis + proposals.
- **Control panel → AI Advisor tab**: run analysis, review proposals, **Approve & apply** or **Reject**.

**Safety design (important for a feedback-driven system):**
- **Suggest-only by default.** A human approves every change. `AI_AUTO_APPLY` is off by default and, even on, only applies *small threshold steps* — never mode switches, never IP blocks.
- **Model output is untrusted.** Every proposal is clamped to hard bounds (`threshold ∈ [0.4, 0.95]`, `mode ∈ {shadow, live}`) before storage, so a poisoned or prompt-injected model cannot push a defense outside the safe envelope.
- **Poisoning is possible in principle** — an attacker who feeds crafted traffic could try to nudge recommendations. Human-in-the-loop + bounds + no auto-hard-block are the mitigations. Review proposals; don't enable auto-apply unless you understand this.
- **No raw IPs leave the collector**, so the AI never proposes IP blocks (that stays a manual operator action from the Top-sources view).

## Security & privacy (GDPR / IL Privacy Law — draft, needs legal review)

- **No raw IP is stored.** The collector derives a country and stores `sha256(ip + secret salt)` only.
- Telemetry is minimal: event type, signal names, path (query stripped by default), UA, language, screen, timezone.
- Admin panel + APIs require a bearer token; the per-site config read requires a Site key.
- Automatic retention pruning (`RETENTION_DAYS`, default 90).
- Payload caps, rate limiting, strict validation, security headers, configurable CORS.
- You must provide a privacy policy and a lawful basis for processing. **Have a lawyer review it.**

---

## Limitations (please read before relying on it)

1. **Client code cannot be made unreadable.** Only `secure-fn` (server execution) is hermetic.
2. **Behavioural detection is statistical** — false positives are possible, so **Shadow mode is the default**; tune before going Live. Keep the bot allowlist current to protect SEO.
3. **CDP source reads bypass client defenses**; a determined operator with blackboxing evades the client layer.
4. In-process behavioural state and rate limits are **per-instance**; multi-instance deployments need a shared store (e.g. Redis).
5. **GeoLite2 (geoip-lite) licensing** for commercial use needs verification.

---

## Development & tests

```bash
npm install
npm run build:guard
# verified test suites:
node packages/secure-fn/test/e2e.mjs      # 6 checks: session, server-side result, replay, forgery, rate limit
node packages/honeypot/test/behavior.mjs  # 4 checks: cadence, header churn, harvesting, human-like
```

See the end-to-end demo in `examples/protected-site/`.

## Contributing translations

Add a language by adding one entry (same keys) to `packages/collector/public/i18n.js`. English is authoritative; other translations are community-provided and not professionally reviewed — corrections welcome.

Hebrew docs: [`README.he.md`](./README.he.md). Design notes: [`PLAN.md`](./PLAN.md).

## Author & credit

Created and maintained by **Diamond Rubinny**.

Every source file carries a credit header, and the minified guard bundle keeps
a credit banner. **This credit must be preserved** in any copy or derivative
work (Apache-2.0 §4 + [`NOTICE`](./NOTICE)). Don't strip the `Diamond Rubinny`
notices.

## License

Licensed under the **Apache License 2.0** — see [`LICENSE`](./LICENSE) and
[`NOTICE`](./NOTICE). Using, modifying, or redistributing the code requires
retaining its copyright and attribution notices.
