/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * Re-captures the MEASURED request fixtures in captured.json.
 *
 * It starts a loopback server, drives real clients at it and records the
 * headers they send. Nothing leaves the machine and no personal data is
 * involved (loopback only; no cookies beyond a fixed test value).
 *
 * Clients:
 *  - Chromium, headed (a normal user's browser). Needs a display: run under
 *    `xvfb-run -a` on a server.
 *  - Chromium, headless via Playwright defaults — the launch mode REA's
 *    `capture_browser_scenario` uses.
 *  - Node's built-in fetch with the options REA's source-map fetcher passes
 *    (morluto/rea src/browser/WebSourceMapFetcher.ts), and two variants.
 *
 * Usage (Playwright must be resolvable, e.g. NODE_PATH=$(npm root -g)):
 *   xvfb-run -a node packages/honeypot/test/fixtures/capture.mjs
 *
 * Re-run after a new REA, Chromium or Node release, review the diff, and
 * update the `expect` fields only when the new behaviour is understood.
 */
import http from "node:http";
import { createRequire } from "node:module";
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";

const OUT = fileURLToPath(new URL("./captured.json", import.meta.url));
const { chromium } = createRequire(import.meta.url)("playwright");

const seen = new Map();
const server = http.createServer((req, res) => {
  const path = new URL(req.url, "http://x").pathname;
  seen.set(path, { ...req.headers });
  if (path === "/") {
    res.writeHead(200, { "content-type": "text/html", "set-cookie": "sid=test; Path=/" });
    return res.end(
      `<!doctype html><title>t</title><link rel="stylesheet" href="/assets/app.css">` +
        `<script src="/assets/app.js"></script><script type="module" src="/assets/mod.mjs"></script>` +
        `<script>fetch("/api/data").then(()=>document.title="done")</script>`,
    );
  }
  const type = path.endsWith(".css")
    ? "text/css"
    : path.startsWith("/api")
      ? "application/json"
      : "text/javascript";
  res.writeHead(200, { "content-type": type });
  res.end(path.startsWith("/api") ? "{}" : "");
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const port = server.address().port;
const base = `http://127.0.0.1:${port}`;

/** Drop transport noise and make host/port stable so re-captures diff cleanly. */
function clean(headers) {
  const out = {};
  for (const [k, v] of Object.entries(headers)) {
    if (k === "connection" || k === "host") continue;
    out[k] = String(v).replaceAll(base, "https://example.test");
  }
  return out;
}
const take = (path) => {
  const h = seen.get(path);
  if (!h) throw new Error(`no request recorded for ${path}`);
  seen.delete(path);
  return clean(h);
};

const fixtures = [];
const add = (id, client, path, expect, note) => {
  const headers = take(path);
  fixtures.push({ id, client, path, expect, note, userAgent: headers["user-agent"] ?? "", headers });
};

async function browser(label, launch, expectScript, note) {
  const b = await chromium.launch(launch);
  const version = b.version();
  const page = await b.newPage();
  await page.goto(base + "/");
  await page.waitForFunction(() => document.title === "done");
  await b.close();
  const client = `${label} ${version}`;
  add(`${label}.navigation`, client, "/", expectScript === "clean" ? "clean" : expectScript, note);
  add(`${label}.script`, client, "/assets/app.js", expectScript, note);
  add(`${label}.module`, client, "/assets/mod.mjs", expectScript, note);
  add(`${label}.fetch`, client, "/api/data", expectScript, note);
  seen.clear();
}

await browser(
  "chromium-headed",
  { headless: false },
  "clean",
  "A normal user's browser. Must never be reported.",
);
await browser(
  "chromium-headless",
  {},
  "decoy",
  "Playwright default launch — what REA's capture_browser_scenario launch mode sends.",
);

const node = `node ${process.version}`;
// Exactly the init REA's fetcher passes (WebSourceMapFetcher.ts).
const REA = {
  headers: { Accept: "application/json, application/source-map+json;q=0.9" },
  redirect: "manual",
  credentials: "omit",
  referrerPolicy: "no-referrer",
};
await fetch(base + "/assets/app.js.map", REA);
add("rea-6.8.0.sourceMapFetch", node, "/assets/app.js.map", "decoy", "REA 6.8.0 source-map fetcher, stock.");
await fetch(base + "/assets/app.js.map", { ...REA, headers: { Accept: "*/*" } });
add(
  "rea-fork.sourceMapFetch",
  node,
  "/assets/app.js.map",
  "decoy",
  "A fork that changed only the Accept header.",
);
await fetch(base + "/assets/app.js");
add(
  "node.fetchScript",
  node,
  "/assets/app.js",
  "report",
  "Plain Node fetch of a script: could be a harvester or a legitimate service — report, never decoy on this alone.",
);

server.close();
const previous = existsSync(OUT) ? JSON.parse(readFileSync(OUT, "utf8")) : null;
const doc = {
  $comment:
    "MEASURED fixtures — generated by capture.mjs, do not edit header values by hand. reaVersion is the REA release whose fetch options were replicated.",
  reaVersion: "6.8.0",
  capturedAt: new Date().toISOString().slice(0, 10),
  fixtures,
};
writeFileSync(OUT, JSON.stringify(doc, null, 2) + "\n");
console.log(`wrote ${fixtures.length} fixtures to ${OUT}${previous ? " (replaced previous capture)" : ""}`);
