/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * End-to-end proof that ALL layers work together against the real app.
 * Build all packages first, then: node examples/full-stack/test.mjs
 */
import { createApp } from "./app.mjs";
import { recover } from "@antirea/watermark";
import { solvePow } from "@antirea/challenge/client";
import { decryptBundle } from "@antirea/harden";

let pass = 0,
  fail = 0;
const ok = (c, m) => {
  if (c) pass++;
  else {
    fail++;
    console.log("FAIL:", m);
  }
};

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

const { app, store, encKey, powDifficulty } = await createApp();
const srv = app.listen(0);
const base = `http://127.0.0.1:${srv.address().port}`;

try {
  // harden — security headers present on responses.
  {
    const r = await fetch(`${base}/app/core.js`, { headers: { ...BROWSER, "x-session": "sh" } });
    ok(!!r.headers.get("content-security-policy"), "harden: CSP header set");
    ok(r.headers.get("x-frame-options") === "DENY", "harden: X-Frame-Options DENY");
    ok(!!r.headers.get("strict-transport-security"), "harden: HSTS set");
  }

  // honeypot — decoy for headless, real bundle for a browser.
  {
    const decoy = await (await fetch(`${base}/assets/app.js`, { headers: { "user-agent": "HeadlessChrome/130" } })).text();
    ok(!decoy.includes("secret = () => 42"), "honeypot: decoy served to headless");
    const real = await (await fetch(`${base}/assets/app.js`, { headers: BROWSER })).text();
    ok(real.includes("secret = () => 42"), "honeypot: real bundle for a browser");
  }

  // secure-fn — server-side logic; output only, constant never leaks.
  {
    const s = await (await fetch(`${base}/secure/session`, { method: "POST" })).json();
    const inv = await fetch(`${base}/secure/invoke`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${s.token}` },
      body: JSON.stringify({ name: "pricing", args: { x: 2 }, nonce: "fd-" + Date.now() }),
    });
    const data = await inv.json();
    ok(inv.status === 200 && data.result?.result === 2691, "secure-fn: pricing(2)=2691 server-side");
  }

  // challenge — 402 without proof, 200 after solving.
  {
    const unsolved = await fetch(`${base}/api/export`);
    const ch = await unsolved.json();
    ok(unsolved.status === 402 && ch.error === "proof_required", "challenge: 402 without proof");
    const nonce = solvePow(ch.c, powDifficulty);
    const solved = await fetch(`${base}/api/export`, {
      headers: { "X-Antirea-PoW-Token": ch.token, "X-Antirea-PoW-Nonce": nonce },
    });
    const body = await solved.json();
    ok(solved.status === 200 && body.data === "sensitive-export", "challenge: 200 with a solved proof");
  }

  // watermark — per-viewer token recoverable, traced back to the viewer.
  {
    const wm = await (await fetch(`${base}/app/core.js`, { headers: { "x-session": "viewer-42" } })).text();
    const tokens = recover(wm);
    ok(tokens.length === 1 && store.get(tokens[0])?.viewer === "viewer-42", "watermark: module traced to the viewer");
  }

  // harden encrypted bundle — payload hides the code; the key decrypts it.
  {
    const payload = await (await fetch(`${base}/enc/bundle`)).json();
    ok(!JSON.stringify(payload).includes("1337") && !JSON.stringify(payload).includes("compute"), "harden: encrypted payload hides the code");
    const plain = await decryptBundle(payload, encKey);
    ok(plain.includes("1337"), "harden: key decrypts the real bundle");
  }
} catch (e) {
  fail++;
  console.log("FAIL (harness):", e.message);
} finally {
  srv.close();
}

console.log(`\nRESULT: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
