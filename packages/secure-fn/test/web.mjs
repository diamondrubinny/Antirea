/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * Tests for the Fetch-API handler (@antirea/secure-fn/web) and the shared
 * core helpers. Build first, then: node packages/secure-fn/test/web.mjs
 */
import { createSecureFnHandler, MAX_BODY_BYTES } from "../dist/web.js";
import { addressKey, forwardedIp, trustHops, SESSIONS_PER_MIN } from "../dist/core.js";
import { RateLimiter } from "../dist/guards.js";

let pass = 0;
let fail = 0;
const ok = (c, m) => {
  if (c) pass++;
  else {
    fail++;
    console.log("FAIL:", m);
  }
};

const seenIps = [];
const handler = createSecureFnHandler({
  secret: "test-secret",
  maxInvokesPerMin: 3,
  trustProxy: 1,
  functions: {
    pricing: (a, ctx) => {
      seenIps.push(ctx.ip);
      return Number(a.x) * 1337 + 17;
    },
    boom: () => {
      throw new Error("SECRET internal detail");
    },
  },
});
const B = "https://app.example/api/secure";
const post = (path, { token, body, headers = {}, raw } = {}) =>
  handler(
    new Request(B + path, {
      method: "POST",
      headers: {
        ...(body !== undefined || raw !== undefined ? { "content-type": "application/json" } : {}),
        ...(token ? { authorization: `Bearer ${token}` } : {}),
        ...headers,
      },
      body: raw ?? (body !== undefined ? JSON.stringify(body) : undefined),
    }),
    { ip: "10.0.0.1" },
  );
const session = async (headers) => (await post("/session", { headers })).json();

// --- routing ---
ok((await handler(new Request(B + "/session"))).status === 405, "GET is rejected (405)");
ok((await post("/other")).status === 404, "unknown path is 404");
{
  const r = await post("/session/");
  ok(r.status === 200 && r.headers.get("cache-control") === "no-store", "session issued; never cached");
}

// --- invoke: same guards as the Express router ---
const s = await session({ "x-forwarded-for": "198.51.100.1" });
ok(typeof s.token === "string" && s.ttlMs === 600_000, "session returns token + ttl");
{
  const r = await post("/invoke", {
    token: s.token,
    body: { name: "pricing", args: { x: 2 }, nonce: "nonce-aaaa" },
    headers: { "x-forwarded-for": "6.6.6.6, 203.0.113.9" },
  });
  ok(r.status === 200 && (await r.json()).result === 2691, "pricing(2)=2691, computed server-side");
  ok(seenIps[0] === "203.0.113.9", `client IP is the trusted hop, not the forged leftmost (got ${seenIps[0]})`);
}
ok(
  (await post("/invoke", { token: s.token, body: { name: "pricing", args: { x: 2 }, nonce: "nonce-aaaa" } })).status === 409,
  "replay rejected (409)",
);
ok((await post("/invoke", { token: "garbage.token", body: { name: "pricing", nonce: "n1" } })).status === 401, "forged token rejected (401)");
ok((await post("/invoke", { body: { name: "pricing", nonce: "n1" } })).status === 401, "missing token rejected (401)");
ok((await post("/invoke", { token: s.token, body: { name: "pricing", args: {} } })).status === 400, "missing nonce rejected (400)");
ok(
  (await post("/invoke", { token: s.token, body: { name: "pricing", args: {}, nonce: "n".repeat(129) } })).status === 400,
  "oversized nonce rejected (400)",
);
ok((await post("/invoke", { token: s.token, body: { name: "__proto__", nonce: "n-proto" } })).status === 404, "prototype keys are not callable (404)");
{
  const r = await post("/invoke", { token: s.token, body: { name: "boom", nonce: "n-boom" } });
  const text = await r.text();
  ok(r.status === 500 && !text.includes("SECRET"), "function errors do not leak internals");
}
{
  // A second session may reuse a nonce value: replay scope is per session.
  const s2 = await session({ "x-forwarded-for": "198.51.100.2" });
  const r = await post("/invoke", { token: s2.token, body: { name: "pricing", args: { x: 1 }, nonce: "nonce-aaaa" } });
  ok(r.status === 200, "nonce scope is per session (no cross-session burn)");
  let got429 = false;
  for (let i = 0; i < 5; i++) {
    const rr = await post("/invoke", { token: s2.token, body: { name: "pricing", args: { x: i }, nonce: "rl-" + i } });
    if (rr.status === 429) got429 = true;
  }
  ok(got429, "per-session rate limit triggers 429");
}

// --- body handling ---
ok((await post("/invoke", { token: s.token, raw: "{not json" })).status === 400, "invalid JSON rejected (400)");
ok(
  (await post("/invoke", { token: s.token, raw: JSON.stringify({ name: "pricing", nonce: "big", args: "x".repeat(MAX_BODY_BYTES) }) })).status === 413,
  "oversized body rejected (413)",
);
ok(
  (await handler(new Request(B + "/invoke", { method: "POST", headers: { authorization: `Bearer ${s.token}`, "content-type": "text/plain" }, body: "{}" }))).status === 415,
  "non-JSON content type rejected (415)",
);

// --- session issuing is limited per client address ---
{
  let limited = 0;
  for (let i = 0; i < SESSIONS_PER_MIN + 5; i++) {
    if ((await post("/session", { headers: { "x-forwarded-for": "2001:db8:aa:bb00::" + (i + 1).toString(16) } })).status === 429) limited++;
  }
  ok(limited === 5, `session limit holds across rotated IPv6 addresses in one /56 (limited ${limited})`);
  ok((await post("/session", { headers: { "x-forwarded-for": "192.0.2.77" } })).status === 200, "another client is unaffected");
}

// --- helpers ---
ok(trustHops(true) === 1 && trustHops(2) === 2 && trustHops(false) === 0 && trustHops(-1) === 0 && trustHops(1.5) === 0 && trustHops(99) === 10, "trustHops normalisation");
ok(forwardedIp("1.1.1.1, 2.2.2.2, 3.3.3.3", 1, "s") === "3.3.3.3", "1 hop → rightmost");
ok(forwardedIp("1.1.1.1, 2.2.2.2, 3.3.3.3", 2, "s") === "2.2.2.2", "2 hops → second from right");
ok(forwardedIp("1.1.1.1", 5, "s") === "1.1.1.1", "more hops than entries → leftmost available");
ok(forwardedIp("1.1.1.1", 0, "sock") === "sock" && forwardedIp(undefined, 1, "sock") === "sock", "untrusted or absent header → socket address");
ok(addressKey("203.0.113.9") === "203.0.113.9", "IPv4 key unchanged");
ok(addressKey("2001:db8:aa:bb01::1") === addressKey("2001:db8:aa:bbff:1:2:3:4"), "same /56 → same key");
ok(addressKey("2001:db8:aa:bb01::1") !== addressKey("2001:db8:aa:cc01::1"), "different /56 → different key");
ok(addressKey("::ffff:203.0.113.9") === "::ffff:203.0.113.9", "IPv4-mapped address left as is");
{
  const rl = new RateLimiter(1, 20);
  for (let i = 0; i < 50; i++) rl.hit("k" + i);
  await new Promise((r) => setTimeout(r, 50));
  rl.hit("fresh");
  ok(rl.size === 1, `expired rate-limit windows are pruned (size ${rl.size})`);
}

console.log(`\nRESULT: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
