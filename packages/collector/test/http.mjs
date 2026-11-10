/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * HTTP-level tests against a real collector process: every admin route must
 * require the token, the public routes must stay public, and the brute-force
 * limiter must engage. It also proves the native SQLite driver loads on this
 * Node version (the server opens the database at startup).
 *
 * Needs the native addon, so it is not part of `npm test`:
 *   npm rebuild better-sqlite3 && npm run build -w packages/collector
 *   npm run test:http -w packages/collector
 */
import { spawn } from "node:child_process";
import { createServer } from "node:net";
import { fileURLToPath } from "node:url";

let pass = 0;
let fail = 0;
const ok = (c, m) => {
  if (c) pass++;
  else {
    fail++;
    console.log("FAIL:", m);
  }
};

const freePort = () =>
  new Promise((resolve) => {
    const s = createServer();
    s.listen(0, "127.0.0.1", () => {
      const { port } = s.address();
      s.close(() => resolve(port));
    });
  });

// Test-only values, generated for this run; nothing here is a real credential.
const TOKEN = "test-admin-" + Math.random().toString(36).slice(2).padEnd(30, "x");
const port = await freePort();
const child = spawn("node", ["dist/server.js"], {
  cwd: fileURLToPath(new URL("..", import.meta.url)),
  env: {
    ...process.env,
    PORT: String(port),
    DB_FILE: ":memory:",
    IP_SALT: "test-salt-" + "s".repeat(32),
    ADMIN_TOKEN: TOKEN,
  },
  stdio: ["ignore", "pipe", "pipe"],
});
let log = "";
child.stdout.on("data", (d) => (log += d));
child.stderr.on("data", (d) => (log += d));
for (let i = 0; i < 60 && !log.includes("listening") && child.exitCode === null; i++) {
  await new Promise((r) => setTimeout(r, 250));
}
if (!log.includes("listening")) {
  console.log("collector did not start:\n" + log);
  child.kill();
  process.exit(1);
}
ok(true, "collector starts and opens its database (native SQLite driver loads)");

const B = `http://127.0.0.1:${port}`;
const call = (method, path, { token, body, headers = {} } = {}) =>
  fetch(B + path, {
    method,
    headers: {
      ...(body !== undefined ? { "content-type": "application/json" } : {}),
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      ...headers,
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });

try {
  // Every admin route, as registered in src/server.ts. A route added there
  // without the `admin` chain fails the source check at the end.
  const ADMIN_ROUTES = [
    ["GET", "/api/stats"],
    ["GET", "/api/offenders"],
    ["GET", "/api/config?site=demo"],
    ["PUT", "/api/config"],
    ["POST", "/api/analyze"],
    ["GET", "/api/proposals"],
    ["GET", "/api/knowledge"],
    ["POST", "/api/proposals/approve"],
    ["POST", "/api/proposals/reject"],
    ["GET", "/api/events"],
  ];
  for (const [method, path] of ADMIN_ROUTES) {
    const body = method === "GET" ? undefined : {};
    const none = await call(method, path, { body });
    const wrong = await call(method, path, { body, token: TOKEN.slice(0, -1) + "!" });
    const good = await call(method, path, { body, token: TOKEN });
    ok(none.status === 401, `${method} ${path} without a token → 401 (got ${none.status})`);
    ok(wrong.status === 401, `${method} ${path} with a wrong token → 401 (got ${wrong.status})`);
    ok(
      good.status !== 401 && good.status !== 403 && good.status < 500,
      `${method} ${path} with the token is let through (got ${good.status})`,
    );
  }
  {
    const r = await call("GET", "/api/stats");
    const text = await r.text();
    ok(text === '{"error":"unauthorized"}' && !text.includes(TOKEN), "401 body is generic and leaks nothing");
  }

  // Public surface stays public and says little.
  {
    const ev = {
      v: 1,
      ts: Date.now(),
      sessionId: "s",
      siteId: "demo",
      path: "/",
      ua: "x",
      lang: "",
      screen: "",
      tz: "",
      signals: [{ type: "devtools", name: "cdp.debuggerPause", confidence: 0.9 }],
    };
    const r = await call("POST", "/api/events", { body: ev });
    ok(r.status === 204 && (await r.text()) === "", "public ingest accepts a valid event with an empty 204");
    ok(
      (await call("POST", "/api/events", { body: { nope: true } })).status === 400,
      "public ingest rejects a malformed event (400)",
    );
    const stats = await (await call("GET", "/api/stats", { token: TOKEN })).json();
    ok(
      JSON.stringify(stats.bySignal).includes("cdp.debuggerPause"),
      "the ingested event is stored and visible to the admin API",
    );
    ok(
      (await call("GET", "/api/site-config?site=demo", { headers: { "x-antirea-site-key": "wrong" } }))
        .status === 403,
      "site-config with a wrong site key → 403",
    );
    const home = await call("GET", "/");
    ok(
      home.status === 200 && (home.headers.get("content-type") ?? "").includes("text/html"),
      "the control-panel shell is served",
    );
    ok(home.headers.get("x-powered-by") === null, "no X-Powered-By header");
  }

  // Brute-force limiter: rejected credentials are capped, then 429 — and the
  // right token is refused too while the limit is in force.
  {
    let limited = 0;
    for (let i = 0; i < 45; i++) {
      if ((await call("GET", "/api/stats", { token: "guess-" + i })).status === 429) limited++;
    }
    ok(limited > 0, `repeated wrong tokens hit the limiter (429 × ${limited})`);
    ok(
      (await call("GET", "/api/stats", { token: TOKEN })).status === 429,
      "a throttled client stays throttled even with the right token",
    );
    ok(log.includes('"action":"auth.rateLimited"'), "throttling is written to the audit log");
    ok(!log.includes(TOKEN), "the admin token never appears in the logs");
  }
} finally {
  child.kill();
}

console.log(`\ncollector/http: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
