/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * End-to-end test for @antirea/secure-fn (the CDP-proof core).
 * Run after building:  npm run build  (from repo root, with deps installed)
 *   node packages/secure-fn/test/e2e.mjs
 *
 * Verifies that the proprietary function runs server-side only, and that the
 * session/replay/rate-limit guards behave. No test framework needed.
 */
import express from "express";
import { createSecureFnRouter } from "../dist/index.js";

const app = express();
app.use(
  "/secure",
  createSecureFnRouter({
    secret: "test-secret",
    maxInvokesPerMin: 3,
    functions: { pricing: (a) => ({ result: Number(a.x) * 1337 + 17 }) },
  }),
);
const srv = app.listen(0);
const port = srv.address().port;
const base = `http://127.0.0.1:${port}/secure`;

let pass = 0;
let fail = 0;
const ok = (c, m) => {
  if (c) pass++;
  else {
    fail++;
    console.log("FAIL:", m);
  }
};
const invoke = (token, body) =>
  fetch(`${base}/invoke`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
    body: JSON.stringify(body),
  });

const s = await fetch(`${base}/session`, { method: "POST" }).then((r) => r.json());
ok(typeof s.token === "string", "session returns token");

const n1 = "nonce-" + Math.random();
const r1 = await invoke(s.token, { name: "pricing", args: { x: 2 }, nonce: n1 });
const d1 = await r1.json();
ok(r1.status === 200 && d1.result.result === 2691, "pricing(2)=2691 (computed server-side)");

const r2 = await invoke(s.token, { name: "pricing", args: { x: 2 }, nonce: n1 });
ok(r2.status === 409, "replay rejected (409)");

const r3 = await invoke("garbage.token", { name: "pricing", args: { x: 1 }, nonce: "x1" });
ok(r3.status === 401, "forged token rejected (401)");

const r4 = await invoke(s.token, { name: "nope", args: {}, nonce: "x2" });
ok(r4.status === 404, "unknown fn rejected (404)");

let got429 = false;
for (let i = 0; i < 6; i++) {
  const r = await invoke(s.token, { name: "pricing", args: { x: i }, nonce: "rl" + i });
  if (r.status === 429) got429 = true;
}
ok(got429, "rate limit triggers 429");

// Behind one trusted proxy, a client-supplied X-Forwarded-For entry is ignored.
{
  let seen = "";
  const app2 = express();
  app2.use(
    "/secure",
    createSecureFnRouter({
      secret: "test-secret",
      trustProxy: true,
      functions: { whoami: (_a, ctx) => ((seen = ctx.ip), "ok") },
    }),
  );
  const srv2 = app2.listen(0);
  const base2 = `http://127.0.0.1:${srv2.address().port}/secure`;
  const xff = { "X-Forwarded-For": "6.6.6.6, 203.0.113.9" };
  const s2 = await fetch(`${base2}/session`, { method: "POST", headers: xff }).then((r) => r.json());
  await fetch(`${base2}/invoke`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${s2.token}`, ...xff },
    body: JSON.stringify({ name: "whoami", nonce: "n-" + Math.random() }),
  });
  ok(seen === "203.0.113.9", `forged leftmost X-Forwarded-For entry is not trusted (got ${seen})`);
  srv2.close();
}

// Without the trustProxy option, the app's own Express "trust proxy" setting
// still decides the client address (no shared rate-limit bucket behind a proxy).
{
  let seen = "";
  const app3 = express();
  app3.set("trust proxy", 1);
  app3.use(
    "/secure",
    createSecureFnRouter({ secret: "test-secret", functions: { whoami: (_a, ctx) => ((seen = ctx.ip), "ok") } }),
  );
  const srv3 = app3.listen(0);
  const base3 = `http://127.0.0.1:${srv3.address().port}/secure`;
  const from = (ip) => ({ "X-Forwarded-For": ip });
  const s3 = await fetch(`${base3}/session`, { method: "POST", headers: from("203.0.113.50") }).then((r) => r.json());
  await fetch(`${base3}/invoke`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${s3.token}`, ...from("203.0.113.50") },
    body: JSON.stringify({ name: "whoami", nonce: "n-" + Math.random() }),
  });
  ok(seen === "203.0.113.50", `Express "trust proxy" is honoured when the option is unset (got ${seen})`);
  // One client exhausting its session quota must not lock out another client.
  let limited = false;
  for (let i = 0; i < 31; i++) {
    const r = await fetch(`${base3}/session`, { method: "POST", headers: from("203.0.113.51") });
    if (r.status === 429) limited = true;
  }
  const other = await fetch(`${base3}/session`, { method: "POST", headers: from("203.0.113.52") });
  ok(limited && other.status === 200, "session limit is per client behind a proxy, not one shared bucket");
  srv3.close();
}

console.log(`\nRESULT: ${pass} passed, ${fail} failed`);
srv.close();
process.exit(fail ? 1 : 0);
