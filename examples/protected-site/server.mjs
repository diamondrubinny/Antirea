/**
 * Example: a tiny site that serves a protected JS bundle behind the honeypot,
 * and loads the antirea guard on its pages.
 *
 * Run (after building packages — see root README):
 *   IP irrelevant here; this is a demo.
 *   node examples/protected-site/server.mjs
 *
 * Then:
 *   - Normal browser  -> GET /assets/app.js returns the REAL bundle.
 *   - Headless fetch  -> in "live" mode returns a DECOY; in "shadow" the real
 *                        file but the attempt is reported.
 *
 * Point COLLECTOR at a running collector to see events in the dashboard.
 */
import express from "express";
import { honeypot } from "@antirea/honeypot";
import { createSecureFnRouter } from "@antirea/secure-fn";

const COLLECTOR = process.env.COLLECTOR ?? "http://localhost:8080/api/events";
const MODE = process.env.HONEYPOT_MODE ?? "shadow"; // "shadow" | "live"
const SECRET = process.env.SECUREFN_SECRET ?? "dev-only-insecure-secret-change-me";

const app = express();

// --- THE CDP-PROOF CORE: proprietary logic runs ONLY here, on the server ---
// A CDP/REA client sees the request { x: 2 } and response { result: 2674 } —
// never the formula below. There is no client code to reverse-engineer.
app.use(
  "/secure",
  createSecureFnRouter({
    secret: SECRET, // in production: a strong random value from env
    reportUrl: COLLECTOR,
    siteId: "demo-site",
    maxInvokesPerMin: 60, // a scraper spiking past this is reported to the dashboard
    functions: {
      // The proprietary algorithm. Stays server-side forever.
      pricing: (args) => {
        const x = Number((args && args.x) || 0);
        return { result: x * 1337 + 17 }; // "secret" formula
      },
    },
  }),
);

// Protect the proprietary bundle. Mount BEFORE static serving.
app.use(
  honeypot({
    siteId: "demo-site",
    protect: [/^\/assets\/app\.js$/, /\.map$/, /^\/__p\//],
    mode: MODE,
    threshold: 0.7,
    reportUrl: COLLECTOR,
    allowlist: { verifyReverseDns: false }, // enable in production (SEO safety)
    // Behavioural engine: scores IP + request cadence + timing regularity +
    // header INSTABILITY, so forging the User-Agent does not help an attacker.
    behavior: { velocityPer10s: 25, harvestAssetPaths: 8, fingerprintChurn: 3 },
    // Optional: let the control panel change mode/threshold/lists live.
    // config: { url: "http://localhost:8080/api/site-config", siteKey: process.env.SITE_KEY },
    onEvent: (ev) => console.log("[honeypot]", ev.action, ev.score.toFixed(2), ev.reasons.join(",")),
    onDecoyServed: (info) => console.log("[honeypot] decoy canary served:", info.canary),
  }),
);

// The "real" proprietary bundle (demo content).
app.get("/assets/app.js", (_req, res) => {
  res.type("application/javascript").send(
    `"use strict";\n// REAL proprietary bundle (demo)\nexport const secret = () => 42;\n`,
  );
});

// --- CDP solution: attestation-gated delivery of the proprietary module ---
// The honeypot middleware above also protects /__p/* . A request arrives with
// an X-Antirea-Attest header (from the guard's importProtected). If the probe
// reported CDP, or the request independently scores as automation, the
// middleware already served a decoy and this handler never runs. Clean
// requests fall through to here and get the REAL module.
app.get("/__p/:name", (req, res) => {
  // In production, read the real module from a NON-public directory.
  res.type("application/javascript").send(
    `"use strict";\n// REAL protected module: ${req.params.name}\n` +
      `export const compute = (x) => x * 1337; // proprietary\n`,
  );
});

// A page that loads the guard.
app.get("/", (_req, res) => {
  // A per-page nonce would be generated + stored server-side for replay limits.
  const nonce = Math.random().toString(36).slice(2);
  res.type("html").send(`<!doctype html>
<html lang="he" dir="rtl"><head><meta charset="utf-8"><title>Demo</title>
  <meta name="antirea-nonce" content="${nonce}">
  <!-- CSP must allow blob: in script-src for importProtected() -->
</head>
<body>
  <h1>אתר מוגן (דמו)</h1>
  <script src="/guard/antirea-guard.iife.js"
          data-site-id="demo-site"
          data-endpoint="${COLLECTOR}"
          data-mode="silent"></script>
  <script type="module">
    import { importProtected } from "/guard/antirea-guard.js";
    // Layer 2 (client code): fetched only after the CDP probe; decoy under CDP.
    try {
      const mod = await importProtected("core", { endpoint: "/__p/" });
      console.log("compute(2) =", mod.compute ? mod.compute(2) : "(decoy)");
    } catch (e) { /* never leak the gate */ }

    // THE REAL SOLUTION (server-side logic): the pricing algorithm never
    // reaches the browser. We only send inputs and read outputs.
    const { createSecureClient } = await import("/securefn/client.js");
    const api = createSecureClient({ endpoint: "/secure" });
    const priced = await api.invoke("pricing", { x: 2 });
    console.log("pricing(2) =", priced.result, "— CDP never sees the formula");
  </script>
</body></html>`);
});

// Serve the built guard (after `npm run build:guard`).
app.use("/guard", express.static(new URL("../../packages/guard/dist", import.meta.url).pathname));
// Serve the built secure-fn browser client (after building @antirea/secure-fn).
app.use("/securefn", express.static(new URL("../../packages/secure-fn/dist", import.meta.url).pathname));

app.listen(3000, () => console.log(`demo on http://localhost:3000 (honeypot=${MODE})`));
