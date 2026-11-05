/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * End-to-end proof that the toolkit solves the problem. Starts the real example
 * server (honeypot in LIVE mode + secure-fn) and asserts:
 *   1. An analysis-shaped request (headless UA) gets an inert DECOY, not the code.
 *   2. A real browser-shaped request gets the REAL asset.
 *   3. A REA source-map fetch (Accept: application/source-map+json) gets a
 *      neutered, empty source map.
 *   4. secure-fn runs proprietary logic server-side: the client gets the OUTPUT,
 *      and the proprietary constant never appears in anything served to clients.
 *
 * Build honeypot + secure-fn first, then: node test/integration.mjs
 */
import { spawn } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";

const BASE = "http://127.0.0.1:3000";
let pass = 0;
let fail = 0;
const ok = (c, m) => {
  if (c) pass++;
  else {
    fail++;
    console.log("FAIL:", m);
  }
};

const server = spawn("node", ["examples/protected-site/server.mjs"], {
  env: { ...process.env, HONEYPOT_MODE: "live", COLLECTOR: "http://127.0.0.1:9/none" },
  stdio: "ignore",
});

async function waitUp() {
  for (let i = 0; i < 50; i++) {
    try {
      const r = await fetch(`${BASE}/assets/app.js`, { headers: { "user-agent": "probe" } });
      if (r.status) return true;
    } catch {
      /* not up yet */
    }
    await sleep(100);
  }
  throw new Error("server did not start");
}

const REAL_BROWSER = {
  "user-agent":
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
  accept: "application/javascript,*/*;q=0.8",
  "accept-language": "en-US,en;q=0.9",
  "sec-ch-ua": '"Chromium";v="130", "Not?A_Brand";v="24"',
  "sec-fetch-dest": "script",
  "sec-fetch-mode": "no-cors",
  "sec-fetch-site": "same-origin",
  cookie: "sid=real-user",
};

try {
  await waitUp();

  // 1. Analysis-shaped request → decoy.
  {
    const r = await fetch(`${BASE}/assets/app.js`, { headers: { "user-agent": "HeadlessChrome/130" } });
    const body = await r.text();
    ok(!body.includes("secret = () => 42"), "decoy: real code is NOT served to a headless client");
    ok(/Intentionally inert|build:ac_/.test(body), "decoy: inert decoy with canary is served instead");
  }

  // 2. Real browser request → real asset.
  {
    const r = await fetch(`${BASE}/assets/app.js`, { headers: REAL_BROWSER });
    const body = await r.text();
    ok(body.includes("secret = () => 42"), "real client receives the real bundle");
  }

  // 3. REA source-map fetch → neutered empty map.
  {
    const r = await fetch(`${BASE}/assets/app.js.map`, {
      headers: { "user-agent": "node", accept: "application/json, application/source-map+json;q=0.9" },
    });
    const body = await r.text();
    let mappings = "unparsed";
    try {
      mappings = JSON.parse(body).mappings;
    } catch {
      /* keep */
    }
    ok(mappings === "", "REA source-map fetch gets an empty, useless source map");
  }

  // 4. secure-fn: proprietary logic runs server-side; client gets only output.
  {
    const s = await fetch(`${BASE}/secure/session`, { method: "POST" }).then((x) => x.json());
    const inv = await fetch(`${BASE}/secure/invoke`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${s.token}` },
      body: JSON.stringify({ name: "pricing", args: { x: 2 }, nonce: "int-" + Date.now() }),
    });
    const data = await inv.json();
    ok(inv.status === 200 && data.result && data.result.result === 2691, "secure-fn returns the computed output (2*1337+17)");

    // The proprietary constant must never be in anything served to clients.
    const realAsset = await fetch(`${BASE}/assets/app.js`, { headers: REAL_BROWSER }).then((x) => x.text());
    const invokeRaw = JSON.stringify(data);
    ok(!realAsset.includes("1337") && !invokeRaw.includes("1337"), "proprietary constant (1337) never reaches the client");
  }
} catch (e) {
  fail++;
  console.log("FAIL (harness):", e.message);
} finally {
  server.kill("SIGTERM");
}

console.log(`\nRESULT: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
