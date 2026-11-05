/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * Tests the JA3 (TLS fingerprint) signal and the tarpit delay in the honeypot
 * middleware. Build honeypot first, then: node test/ja3-tarpit.mjs
 */
import express from "express";
import { honeypot } from "../dist/index.js";

let pass = 0,
  fail = 0;
const ok = (c, m) => {
  if (c) pass++;
  else {
    fail++;
    console.log("FAIL:", m);
  }
};

const app = express();
app.use(
  honeypot({
    siteId: "t",
    protect: [/^\/app\.js$/],
    mode: "live",
    blockJa3: ["BADJA3HASH"],
    tarpitMs: 300,
    allowlist: { verifyReverseDns: false },
  }),
);
app.get("/app.js", (_req, res) => res.type("application/javascript").send("REAL-BUNDLE"));

const srv = app.listen(0);
const port = srv.address().port;
const base = `http://127.0.0.1:${port}`;

const BROWSER = {
  "user-agent":
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
  accept: "application/javascript,*/*;q=0.8",
  "accept-language": "en-US,en;q=0.9",
  "sec-ch-ua": '"Chromium";v="130"',
  "sec-fetch-dest": "script",
  "sec-fetch-site": "same-origin",
  cookie: "sid=1",
};

try {
  // 1. Flagged by JA3 → decoy (not the real bundle) AND tarpit delay applied.
  {
    const t0 = Date.now();
    const r = await fetch(`${base}/app.js`, { headers: { ...BROWSER, "x-ja3": "badja3hash" } });
    const body = await r.text();
    const ms = Date.now() - t0;
    ok(!body.includes("REAL-BUNDLE"), "JA3-blocked request gets a decoy, not the real bundle");
    ok(ms >= 280, `tarpit delayed the flagged response (${ms}ms)`);
  }

  // 2. Clean browser (no bad JA3) → real bundle, fast.
  {
    const t0 = Date.now();
    const r = await fetch(`${base}/app.js`, { headers: { ...BROWSER, "x-ja3": "a-normal-browser-ja3" } });
    const body = await r.text();
    const ms = Date.now() - t0;
    ok(body.includes("REAL-BUNDLE"), "clean client gets the real bundle");
    ok(ms < 250, `clean request not tarpitted (${ms}ms)`);
  }
} catch (e) {
  fail++;
  console.log("FAIL (harness):", e.message);
} finally {
  srv.close();
}

console.log(`\nRESULT: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
