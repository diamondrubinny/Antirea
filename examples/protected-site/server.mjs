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

const COLLECTOR = process.env.COLLECTOR ?? "http://localhost:8080/api/events";
const MODE = process.env.HONEYPOT_MODE ?? "shadow"; // "shadow" | "live"

const app = express();

// Protect the proprietary bundle. Mount BEFORE static serving.
app.use(
  honeypot({
    siteId: "demo-site",
    protect: [/^\/assets\/app\.js$/, /\.map$/],
    mode: MODE,
    threshold: 0.7,
    reportUrl: COLLECTOR,
    allowlist: { verifyReverseDns: false }, // enable in production
    onEvent: (ev) => console.log("[honeypot]", ev.action, ev.score, ev.reasons.join(",")),
    onDecoyServed: (info) => console.log("[honeypot] decoy canary served:", info.canary),
  }),
);

// The "real" proprietary bundle (demo content).
app.get("/assets/app.js", (_req, res) => {
  res.type("application/javascript").send(
    `"use strict";\n// REAL proprietary bundle (demo)\nexport const secret = () => 42;\n`,
  );
});

// A page that loads the guard.
app.get("/", (_req, res) => {
  res.type("html").send(`<!doctype html>
<html lang="he" dir="rtl"><head><meta charset="utf-8"><title>Demo</title></head>
<body>
  <h1>אתר מוגן (דמו)</h1>
  <!-- In production, point src to the built guard and your collector -->
  <script src="/guard/antirea-guard.iife.js"
          data-site-id="demo-site"
          data-endpoint="${COLLECTOR}"
          data-mode="silent"></script>
  <script type="module" src="/assets/app.js"></script>
</body></html>`);
});

// Serve the built guard (after `npm run build:guard`).
app.use("/guard", express.static(new URL("../../packages/guard/dist", import.meta.url).pathname));

app.listen(3000, () => console.log(`demo on http://localhost:3000 (honeypot=${MODE})`));
