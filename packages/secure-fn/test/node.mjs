/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * Tests for the Node bridge (@antirea/secure-fn/node) over a real node:http
 * server. Build first, then: node packages/secure-fn/test/node.mjs
 */
import http from "node:http";
import { createSecureFnHandler, MAX_BODY_BYTES } from "../dist/web.js";
import { createNodeListener } from "../dist/node.js";
import { createSecureClient } from "../dist/client.js";

let pass = 0;
let fail = 0;
const ok = (c, m) => {
  if (c) pass++;
  else {
    fail++;
    console.log("FAIL:", m);
  }
};

const seen = [];
const listener = createNodeListener(
  createSecureFnHandler({
    secret: "test-secret",
    maxInvokesPerMin: 50,
    functions: {
      pricing: (a, ctx) => {
        seen.push(ctx.ip);
        return Number(a.x) * 1337 + 17;
      },
      boom: () => {
        throw new Error("SECRET internal detail");
      },
    },
  }),
);
const server = http.createServer(listener);
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const B = `http://127.0.0.1:${server.address().port}/api/secure`;
const post = (path, { token, body, raw, headers = {} } = {}) =>
  fetch(B + path, {
    method: "POST",
    headers: {
      ...(body !== undefined || raw !== undefined ? { "content-type": "application/json" } : {}),
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      ...headers,
    },
    body: raw ?? (body !== undefined ? JSON.stringify(body) : undefined),
  });

try {
  const s = await (await post("/session")).json();
  ok(typeof s.token === "string" && s.ttlMs === 600_000, "session over node:http");
  {
    const r = await post("/invoke", {
      token: s.token,
      body: { name: "pricing", args: { x: 2 }, nonce: "node-n1" },
    });
    ok(r.status === 200 && (await r.json()).result === 2691, "invoke computes server-side");
    ok(
      r.headers.get("cache-control") === "no-store" &&
        (r.headers.get("content-type") ?? "").includes("application/json"),
      "response headers are passed through",
    );
    ok(
      seen[0] === "127.0.0.1" || seen[0] === "::ffff:127.0.0.1",
      `socket address reaches the function (got ${seen[0]})`,
    );
  }
  ok(
    (await post("/invoke", { token: s.token, body: { name: "pricing", args: { x: 2 }, nonce: "node-n1" } }))
      .status === 409,
    "replay rejected (409)",
  );
  ok(
    (await post("/invoke", { body: { name: "pricing", nonce: "n" } })).status === 401,
    "missing token rejected (401)",
  );
  ok((await fetch(B + "/session")).status === 405, "GET rejected (405)");
  ok((await post("/nope")).status === 404, "unknown path is 404");
  ok(
    (await post("/invoke", { token: s.token, raw: "{not json" })).status === 400,
    "invalid JSON rejected (400)",
  );
  {
    const r = await post("/invoke", {
      token: s.token,
      raw: JSON.stringify({ name: "pricing", nonce: "big", args: "x".repeat(MAX_BODY_BYTES) }),
    });
    ok(r.status === 413, `oversized streamed body rejected (413, got ${r.status})`);
  }
  {
    const r = await post("/invoke", { token: s.token, body: { name: "boom", nonce: "node-boom" } });
    const text = await r.text();
    ok(r.status === 500 && !text.includes("SECRET"), "function errors do not leak internals");
  }
  {
    // The bundled browser client works against the bridge unchanged.
    const api = createSecureClient({ endpoint: B });
    ok((await api.invoke("pricing", { x: 3 })) === 4028, "the browser client works end to end");
  }
  {
    // A handler that throws is answered generically.
    const broken = http.createServer(
      createNodeListener(() => {
        throw new Error("SECRET handler crash");
      }),
    );
    await new Promise((r) => broken.listen(0, "127.0.0.1", r));
    const r = await fetch(`http://127.0.0.1:${broken.address().port}/x`, { method: "POST" });
    const text = await r.text();
    ok(r.status === 500 && text === '{"error":"internal"}', "a crashing handler gives a generic 500");
    broken.close();
  }
} finally {
  server.close();
}

console.log(`\nRESULT: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
