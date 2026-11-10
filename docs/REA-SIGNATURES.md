# REA signature pack

Defensive fingerprints for the `morluto/rea` reverse-engineering MCP tool,
derived from its public source (MIT). Each entry names the **source file it was
verified against**, the **layer** that detects it, and its **evadability** — we
do not claim a signature is conclusive when it is not.

> **Verified against REA `rea-agents` 6.8.0** (`main` @ `e9b6c87`, 2026-11-09).
> Header values were also **measured** (Node 22 `fetch`, Playwright/Chromium
> headless), not only read. Re-check after REA updates — see the end of this file.

These detect REA running **against your own site**. They let your server serve
decoys or your telemetry flag the attempt. They do nothing to REA itself or to
third parties. REA's own `DISCLAIMER.md` forbids "bypassing … bot protection or
access controls on systems you are not authorized to test" and "copying
proprietary software or reproducing its protected code" — exactly the use these
signatures surface.

## Coverage matrix

| Signature | Layer | REA 6.8.0 | How it is verified | Last verified |
|---|---|---|---|---|
| `rea.sourceMapAccept` | server | ✅ | **Measured fixture** (Node `fetch` with REA's exact options) | 2026-11-09 |
| `ua.runtimeFetch` / `forgery.partialSecFetch` / `acceptLanguage.wildcard` | server | ✅ (report; decoy when corroborated) | **Measured fixture** | 2026-11-09 |
| `rea.sourceMapShape` (fork with changed `Accept`) | server | ✅ | **Measured fixture** | 2026-11-09 |
| `ua.headless` / `ua.headlessClientHint` (launch mode) | server | ✅ | **Measured fixture** (Playwright-default Chromium) | 2026-11-09 |
| `canary.sourceMap` | server | ✅ | Unit + end-to-end test | 2026-11-09 |
| `rea.scenarioSwPolicy` | client | ✅ | Unit test + Chromium run; source read | 2026-11-09 |
| `automation.swBlockPatch` | client | ✅ (report-only) | Unit test + Chromium run | 2026-11-09 |
| `cdp.debuggerPause` | client | ✅ | Source read (no pause suppression in REA) | 2026-11-09 |
| `rea.playwrightDefaults` | client | ✅ | Source read + Chromium run | 2026-11-09 |

**Regression and false-positive gate.** `packages/honeypot/test/fixtures.mjs`
runs on every CI build. It scores recorded requests and fails if a signature
stops firing **or if any legitimate client would be decoyed**:

- `fixtures/captured.json` — **measured**: headers recorded from real headed
  Chromium (a normal user), Playwright-default headless Chromium (REA launch
  mode) and Node `fetch` with REA's options. Regenerate with
  `xvfb-run -a node packages/honeypot/test/fixtures/capture.mjs`.
- `fixtures/synthetic.json` — **not measured**: Firefox, Safari, a proxied
  Chrome, a legitimate Node service and curl, written from documented
  behaviour and labelled as such until real captures replace them.

Current result: **0 of 10 legitimate request shapes decoyed** (5 measured, 5
synthetic). This is a small corpus, not a field
false-positive rate — run shadow mode on your own traffic before going live.

A weekly workflow (`.github/workflows/rea-watch.yml`) opens an issue when REA
publishes a release newer than the one in this table.

## Signature packs — updating without a code release

The weights and match patterns of the server-side scorer are data. The built-in
pack ships as [`signatures/default.json`](../packages/honeypot/signatures/default.json);
to follow a tool that changed (a renamed header, a new runtime), pass a pack
that overrides only what moved:

```ts
import { readFileSync } from "node:fs";
import { honeypot } from "@antirea/honeypot";

const signaturePack = JSON.parse(readFileSync("./antirea-signatures.json", "utf8"));
app.use(honeypot({ siteId, protect: [/\.js$/], signaturePack }));
```

```json
{
  "format": 1,
  "version": "2026-12-01",
  "reaVersion": "6.9.0",
  "weights": { "runtimeFetch.combined": 0.6 },
  "patterns": { "sourceMapAccept": "application\\/source-map\\+json" }
}
```

- **Data, not code.** A pack tunes values; the scoring logic stays in the
  library. Unknown keys, weights outside 0–1, patterns longer than 512
  characters, patterns that do not compile, patterns that match the empty
  string and patterns that nest a quantifier inside a quantified group (such as
  `(a+)+`) are rejected, and `honeypot()` refuses to start with an invalid
  pack.
- **Loaded by you, from a file you control.** The library never fetches a pack
  over the network. Patterns are regular expressions: review a pack as you
  would review code, because a hostile pattern can be slow on purpose. The
  nested-quantifier check and the 1,024-character cap on matched header values
  reduce that risk; they do not remove it.
- **Check before going live.** Raising a weight can turn a "report" into a
  "decoy". Re-run the fixture suite with your pack, or run shadow mode first.

## How REA touches a website

REA drives a browser for an AI coding agent over MCP (`npx rea-agents mcp`,
configured for Claude Code, Codex, Cursor and ~25 other clients).

| REA tool | What it does | Reaches your origin? | Detect at |
|---|---|---|---|
| `inspect_web_page`, `analyze_web_bundle`, `observe_web_session`, `observe_web_execution`, `inspect_web_event_listeners` | Attach over **loopback CDP** to a Chrome the operator started; read DOM, scripts, network, storage; enable the `Debugger` domain | No (the human's normal browsing only) | **Client** — debugger pause (`cdp.ts`) |
| `analyze_web_bundle` with `fetch_source_maps` | Fetches every source map the page **declares**, from **Node** (`src/browser/WebSourceMapFetcher.ts:476-486`) | **Yes** | **Server** — see below |
| `capture_browser_scenario` (launch mode) | Launches headless Chromium via Playwright with fixed defaults (`src/browser/PlaywrightScenarioBrowser.ts`) | Yes (a real browser) | **Client + server** |
| `capture_browser_scenario` (connect mode) | Attaches to an existing tab; injects a service-worker policy (`src/browser/PlaywrightScenarioServiceWorkers.ts`) | Yes | **Client** — unique markers |
| Static / offline tools (`export_web_scripts`, `recover_javascript_sources`, `inspect_web_network_capture`, HAR/pcap, `inspect_wasm_artifact`, …) | Analyse files already captured | No | n/a |

REA has **no stealth code at all**: no `navigator.webdriver` hiding, no
`AutomationControlled` flag, no UA override, no plugin/WebGL faking, and no code
to detect or bypass honeypots, canaries, proof-of-work or bot protection.

## Server-side signatures (`@antirea/honeypot`)

### `rea.sourceMapAccept` — near-certain
REA's source-map fetcher sends (`WebSourceMapFetcher.ts:479-483`) — the rule
matches the `application/source-map+json` **token anywhere in the header**, not
the exact value:
```
Accept: application/json, application/source-map+json;q=0.9
credentials: "omit" · referrerPolicy: "no-referrer" · redirect: "manual"
```
No browser sends the `application/source-map+json` media type. Scores **0.85**.
**Evadability:** low for stock REA (hard-coded); a fork can change it — which
the rules below still catch.

### `ua.runtimeFetch` + `forgery.partialSecFetch` + `acceptLanguage.wildcard` — one combined fingerprint
The fetch runs on Node's built-in `fetch` (undici). Measured on Node 22, it adds:
```
user-agent: node · accept-language: * · sec-fetch-mode: cors   (no sec-fetch-site / -dest)
```
- `ua.runtimeFetch`: UA exactly `node` / `undici`, or `Bun/…`, `Deno/…`.
- `forgery.partialSecFetch`: `Sec-Fetch-Mode` without `-Site`/`-Dest`.
  Measured on 11 real Chromium request types (document, script, module, CSS,
  image, iframe, fetch GET/POST, dynamic import, beacon): browsers send all three
  or none — **0 partial sets**. Not counted when the UA claims Chromium: a proxy
  that strips headers from a real browser is already covered by
  `forgery.noSecFetch`, and is not penalised twice.
- `acceptLanguage.wildcard`: browsers never send a bare `*`.

All three come from the **same source** — the runtime's defaults — so they are
scored as **one** piece of evidence: **0.6** with the runtime UA or ≥2 markers,
0.2 for a lone non-UA marker. That is deliberately **below the default threshold
(0.7)**: a legitimate server-side Node client (monitoring, SSR prefetch) is
*reported*, not decoyed. It crosses the threshold only with an independent
signal — e.g. a `.map` request (`rea.sourceMapShape` + `request.sourceMap`), so a
REA fork with a changed `Accept` still scores **1.00**. A plain Node script
harvesting `/assets/app.js` scored **0.00** before these rules and **0.60** now
(visible in the dashboard). **Evadability:** medium — setting explicit headers
removes them.

### `rea.sourceMapShape` — supporting
A `.map` request with no `Cookie`, `Referer` or `Sec-Fetch-Dest` (0.5).

### `canary.sourceMap` — strong (opt-in)
REA fetches the maps a page **declares** and never guesses `.map` URLs
(`src/browser/CdpCaptureEventHandlers.ts:179-235`). Browsers fetch source maps
only while DevTools is open. So point a bundle at a map URL that is linked
nowhere else, and any request for it is a source-map consumer:

```ts
import { honeypot, sourceMapCanaryComment } from "@antirea/honeypot";
app.use(honeypot({ siteId, protect: [/\.js$/, /\.map$/], sourceMapCanary: "/__antirea/m/" }));
bundleSource += "\n" + sourceMapCanaryComment("/__antirea/m/");   // unique random token
```
With Vite or Rollup, let the build add the comment to every JavaScript chunk:

```ts
// vite.config.ts (or rollup.config.js → plugins)
import { sourceMapCanaryPlugin } from "@antirea/honeypot/build";

export default {
  build: { sourcemap: false }, // or "hidden"; with linked maps the canary is skipped
  plugins: [sourceMapCanaryPlugin({ prefix: "/__antirea/m/", seed: process.env.CANARY_SEED })],
};
```

Each chunk gets its own URL, derived from the secret `seed` and the chunk name
(random per build when no seed is given; a fixed seed keeps hashed files
byte-identical between builds). `onCanary` reports which URL belongs to which
file. Verified on Vite 8.3, Rollup 4.68 and webpack 5.112.

webpack 5 uses the class form; the canary is added after minification and
before `[contenthash]` is finalised:

```js
import { SourceMapCanaryWebpackPlugin } from "@antirea/honeypot/build";

export default {
  devtool: false, // or "hidden-source-map"; other devtools skip the canary
  plugins: [new SourceMapCanaryWebpackPlugin({ seed: process.env.CANARY_SEED })],
};
```

**Subresource Integrity.** With `sriManifest: "sri-manifest.json"` either plugin
also emits `{ "<file>": "sha384-…" }` for every JavaScript file, hashed after
the canary line was added. Put the value in the `integrity` attribute of the
matching `<script>` tag (with `crossorigin="anonymous"`); the browser then
refuses a tampered copy. The plugins write the manifest only — adding the
attribute to your HTML is up to your template or framework. Dynamically
imported chunks are listed too, but browsers do not check integrity for
`import()` unless your loader passes it.

A hit scores **1.0** and, in live mode, gets an empty decoy map. REA accepts
maps without authenticity checks (`trace_web_source_location`: "Deployment
authenticity and execution remain unknown"), so decoys are taken at face value.

What a hit does and does **not** tell you:
- It means *a source-map consumer* read the map — REA, a harvesting script, or a
  developer with **DevTools open**. It does not identify REA; pair it with the
  other reasons on the same event.
- The prefix is matched on a **directory boundary** (`/maps` matches
  `/maps/…`, never `/maps-ui/…`); `/` and `""` are refused.
- It is checked even when the path is not in `protect`, but it is **not
  scored** for requests the middleware skips entirely: protection switched off
  from the control panel, or an allowlisted IP / verified bot.
- **CDN / static hosting:** the canary path must reach the origin running the
  middleware. If a CDN or static host serves (or 404s) `/__antirea/m/*` itself,
  the hit is never seen — add a pass-through rule for the prefix, and do not
  cache it.

**Evadability:** low — REA must fetch declared maps to use the feature.

### `ua.headlessClientHint` — strong-but-evadable
REA's launch mode sets no UA, so Chromium reports `HeadlessChrome` in both the UA
and the `sec-ch-ua` Client Hint (measured). Already caught by `ua.headless`; the
Client-Hint rule (0.6) also catches automation that spoofed only the UA string.

## Client-side signatures (`@antirea/guard`)

### `rea.scenarioSwPolicy` — near-certain
Connect mode (default `service_workers: "block"`, `src/domain/browserScenarioValues.ts:307`)
injects into the main world (`PlaywrightScenarioServiceWorkers.ts:222-243`):
- replaces `ServiceWorkerContainer.prototype.register`, tagged with
  `Symbol.for("rea-service-workers-<uuid>")`;
- defines a hidden global `rea-restore-<uuid>`.

`detectors/scenario.ts` matches those exact shapes (0.99). It runs at load and
on the periodic sweep, so REA attaching to an **already-open tab** is caught too
(verified in Chromium). **Evadability:** low (fixed prefixes; a fork could rename).

### `automation.swBlockPatch` — report-only
Launch mode passes `serviceWorkers: "block"` to Playwright, which sets an own,
non-native `register` on the `navigator.serviceWorker` **instance** (measured).
Scores **0.5** — below the 0.7 at which `aggressive` mode halts the app, because
another script could also wrap the instance method; real Playwright is still
stopped by its independent signals (`navigator.webdriver`, 0.8).
Prototype-level wrappers are ignored on purpose (frameworks such as zone.js
patch prototypes); verified no signal on such a wrapper.
**Evadability:** medium (`service_workers: "allow"`).

### `cdp.debuggerPause` — strong
Every live CDP tool enables the `Debugger` domain and **never suppresses pauses**:
"Enabling Debugger can make target-authored debugger statements pause execution;
observation does not suppress or resume these pauses"
(`src/inspector/V8InspectorCaptureProjection.ts:33`; no `setSkipAllPauses` /
`setBreakpointsActive` anywhere in `src/`). The guard's `debugger`-timing probe
fires; with REA attached the page actually freezes at the probe until REA detaches.

### `rea.playwrightDefaults` — strong-but-evadable
Launch defaults, unchanged in 6.8.0 (`browserScenarioValues.ts:269-318`): headless,
1280×720, DPR 1, `en-US`, `UTC`, light, `reduced_motion: reduce`, service workers
blocked; plus `navigator.webdriver === true` (measured). Fires on a strong core
plus ≥4 of 7 markers. **Evadability:** medium — the operator can override these.

## What REA can and cannot defeat (honest)

| Our protection | Against REA 6.8.0 |
|---|---|
| **Server-side execution** (`secure-fn`) | **Not defeated** — the algorithm never reaches the browser. The only hermetic layer. |
| **Encrypted bundle delivery** | **Defeated if REA attaches after decryption.** `observe_web_execution` reads every main-frame, default-world script via `Debugger.getScriptSource` and checks the frame and world, **not the URL** (`src/browser/execution/CdpRuntimeSources.ts:119-150`), so eval'd and blob-imported code is captured, including scripts compiled before it attached. **Not defeated if REA is attached first:** the guard's attestation runs a `debugger` probe *before* requesting the key, and REA's attached debugger freezes the page there, so decryption never runs while it observes. Code in Workers, child frames and WASM is outside that capture path. |
| **WASM tier** | **Partially.** `inspect_wasm_artifact` disassembles to WAT (WABT `wasm2wat`); no decompiler. Our AssemblyScript build emits **no custom sections** (no `name` section), so function names do not leak. |
| **Obfuscation** (string arrays, control-flow flattening, renaming) | **Not undone statically** — REA has no deobfuscator; its own docs say obfuscation leaves paths "unresolved". **Partially bypassed at runtime:** precise coverage shows which code ran, and network initiator stacks reveal real endpoint URLs. Hide endpoints by gating them server-side, not by encoding strings. |
| **Decoy source maps** | **Work** — accepted without verification. |
| **Detection** (debugger, webdriver, scenario patches, Node fetch) | **Not evaded** — REA has no stealth. Node-fetch markers alone are reported, not decoyed (see above). |

## What is NOT a usable signature

- **Scenario `request` steps.** They use the page's own `fetch` with the real
  browser's headers and cookies (`PlaywrightScenarioRequest.ts:200-292`).
- **The CDP endpoint.** Loopback only; never reaches your origin.
- **Branding.** REA sends no `rea` User-Agent and no `x-rea-*` headers to targets.

## The honest bottom line

These raise the cost of an out-of-the-box REA run and make attempts visible in
the dashboard. A patient operator who forks REA, sets explicit headers, renames
its markers and overrides the Playwright defaults can evade the client/header
layer, and an analyst who attaches **after** a protected bundle has been
decrypted can read it. The only hermetic protection for proprietary logic
remains server-side execution (`@antirea/secure-fn`). Signatures are
deterrence and intelligence, layered on top of that.

## Verify for yourself

```bash
git clone https://github.com/morluto/rea && cd rea
grep -n "source-map+json" src/browser/WebSourceMapFetcher.ts
grep -n "default(true)\|1280\|\"UTC\"\|reduce\|service_workers" src/domain/browserScenarioValues.ts
grep -n "rea-service-workers-\|rea-restore-" src/browser/PlaywrightScenarioServiceWorkers.ts
grep -rn "setSkipAllPauses\|setBreakpointsActive" src/   # expect: nothing
```
