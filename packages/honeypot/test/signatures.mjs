/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * Tests for signature packs (data-driven weights and patterns).
 * Build first, then: node packages/honeypot/test/signatures.mjs
 */
import { readFileSync } from "node:fs";
import express from "express";
import { DEFAULT_SIGNATURE_PACK, honeypot, loadSignaturePack, scoreRequest } from "../dist/index.js";

let pass = 0;
let fail = 0;
const ok = (c, m) => {
  if (c) pass++;
  else {
    fail++;
    console.log("FAIL:", m);
  }
};
const rejects = (input, expected, label) => {
  try {
    loadSignaturePack(input);
    ok(false, `${label}: accepted`);
  } catch (e) {
    ok(String(e.message).includes(expected), `${label}: rejected with "${expected}" (got "${e.message}")`);
  }
};
const base = { format: 1, version: "t" };
const nodeReq = {
  userAgent: "node",
  headers: { accept: "*/*", "accept-language": "*", "sec-fetch-mode": "cors" },
  path: "/assets/app.js",
};

// --- the shipped JSON is exactly the built-in pack ---
{
  const shipped = JSON.parse(readFileSync(new URL("../signatures/default.json", import.meta.url), "utf8"));
  const { $comment, ...rest } = shipped;
  ok(typeof $comment === "string", "default.json carries a usage comment");
  ok(
    JSON.stringify(rest) === JSON.stringify(DEFAULT_SIGNATURE_PACK),
    "signatures/default.json matches the built-in pack (regenerate it if this fails)",
  );
  const loaded = loadSignaturePack(shipped);
  ok(
    scoreRequest(nodeReq, loaded).score === scoreRequest(nodeReq).score,
    "loading default.json scores identically to the built-in pack",
  );
}

// --- partial override ---
{
  const tuned = loadSignaturePack({
    ...base,
    reaVersion: "6.9.0",
    weights: { "runtimeFetch.combined": 0.9 },
  });
  ok(
    scoreRequest(nodeReq).score === 0.6 && scoreRequest(nodeReq, tuned).score === 0.9,
    "a weight override changes the score",
  );
  ok(
    tuned.pack.weights["ua.headless"] === 0.6 && tuned.pack.reaVersion === "6.9.0",
    "unspecified values keep their defaults",
  );
  ok(
    DEFAULT_SIGNATURE_PACK.weights["runtimeFetch.combined"] === 0.6,
    "the built-in pack is not mutated by an override",
  );
  const renamed = loadSignaturePack({
    ...base,
    patterns: { sourceMapAccept: "application\\/x-newtool-map" },
  });
  const hit = { userAgent: "x", headers: { accept: "application/x-newtool-map" }, path: "/a.js" };
  ok(
    scoreRequest(hit, renamed).reasons.includes("rea.sourceMapAccept") &&
      !scoreRequest(hit).reasons.includes("rea.sourceMapAccept"),
    "a pattern override follows a tool that changed its header",
  );
  ok(
    scoreRequest(nodeReq, loadSignaturePack({ ...base, weights: { "runtimeFetch.combined": 0 } })).score ===
      0,
    "a weight of 0 switches a signal off",
  );
}

// --- strict validation ---
rejects(null, "expected an object", "null");
rejects([], "expected an object", "array");
rejects({ ...base, format: 2 }, "unsupported format", "wrong format");
rejects({ format: 1 }, "version must be", "missing version");
rejects({ ...base, extra: 1 }, 'unknown key "extra"', "unknown top-level key");
rejects({ ...base, weights: { "ua.nope": 0.5 } }, 'unknown weight "ua.nope"', "unknown weight");
rejects({ ...base, weights: { "ua.headless": 1.5 } }, "between 0 and 1", "weight above 1");
rejects({ ...base, weights: { "ua.headless": -0.1 } }, "between 0 and 1", "negative weight");
rejects({ ...base, weights: { "ua.headless": "0.5" } }, "between 0 and 1", "string weight");
rejects({ ...base, weights: { "ua.headless": NaN } }, "between 0 and 1", "NaN weight");
rejects({ ...base, patterns: { headlessUa: "(" } }, "not a valid regular expression", "broken regex");
rejects({ ...base, patterns: { headlessUa: "a".repeat(513) } }, "at most 512", "oversized pattern");
rejects({ ...base, patterns: { headlessUa: "" } }, "non-empty string", "empty pattern");
rejects({ ...base, patterns: { headlessUa: ".*" } }, "matches the empty string", "match-everything pattern");
rejects({ ...base, patterns: { nope: "x" } }, 'unknown pattern "nope"', "unknown pattern");
rejects({ ...base, weights: [] }, "weights must be an object", "weights as array");
// Prototype-pollution shaped input must not leak into the pack or Object.prototype.
{
  const hostile = JSON.parse('{"format":1,"version":"t","weights":{"__proto__":{"polluted":1}}}');
  rejects(hostile, 'unknown weight "__proto__"', "__proto__ key in weights");
  ok({}.polluted === undefined, "Object.prototype is not polluted");
}

// --- middleware: pack is validated at creation and used for scoring ---
{
  let threw = false;
  try {
    honeypot({
      siteId: "t",
      protect: [/\.js$/],
      signaturePack: { format: 1, version: "t", weights: { "ua.headless": 5 } },
    });
  } catch {
    threw = true;
  }
  ok(threw, "honeypot() refuses to start with an invalid pack");

  const events = [];
  const app = express();
  app.use(
    honeypot({
      siteId: "t",
      protect: [/\.js$/],
      mode: "live",
      allowlist: { verifyReverseDns: false },
      onEvent: (e) => events.push(e),
      signaturePack: { format: 1, version: "tuned", weights: { "runtimeFetch.combined": 0.9 } },
    }),
  );
  app.get("/assets/app.js", (_q, r) => r.type("js").send("window.realApp=1;"));
  const srv = app.listen(0);
  const res = await fetch(`http://127.0.0.1:${srv.address().port}/assets/app.js`);
  const text = await res.text();
  srv.close();
  ok(!text.includes("realApp"), "with the tuned pack a plain Node fetch is now decoyed (0.9 ≥ threshold)");
}

console.log(`\nRESULT: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
