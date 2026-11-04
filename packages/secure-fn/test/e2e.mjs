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

console.log(`\nRESULT: ${pass} passed, ${fail} failed`);
srv.close();
process.exit(fail ? 1 : 0);
