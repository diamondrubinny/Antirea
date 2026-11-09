/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * Tests for collector auth helpers and client-IP extraction.
 * Build first (tsc), then: node packages/collector/test/auth.mjs
 */
import {
  audit,
  bearerToken,
  MIN_STRONG_TOKEN,
  parseTrustProxy,
  safeEqual,
  tokenStrengthWarning,
} from "../dist/auth.js";
import { extractIp, hashIp } from "../dist/geo.js";

let pass = 0;
let fail = 0;
const ok = (c, m) => {
  if (c) pass++;
  else {
    fail++;
    console.log("FAIL:", m);
  }
};

// --- safeEqual ---
ok(safeEqual("s3cret-token", "s3cret-token"), "equal secrets match");
ok(!safeEqual("s3cret-tokeN", "s3cret-token"), "one-char difference rejected");
ok(!safeEqual("short", "a-much-longer-secret-value"), "different lengths rejected (no length leak path)");
ok(!safeEqual("", ""), "empty expected secret never matches");
ok(!safeEqual("anything", ""), "empty expected secret rejects any input");
ok(!safeEqual("", "s3cret"), "empty provided rejected");
ok(safeEqual("ünïcödé-🔑", "ünïcödé-🔑"), "unicode secrets compare correctly");

// --- bearerToken ---
ok(bearerToken("Bearer abc123") === "abc123", "parses Bearer token");
ok(bearerToken("bearer   abc123  ") === "abc123", "case-insensitive scheme, trims whitespace");
ok(bearerToken("Basic abc123") === "", "rejects non-Bearer scheme");
ok(bearerToken(undefined) === "", "missing header → empty");
ok(bearerToken("Bearer") === "", "scheme without token → empty");

// --- tokenStrengthWarning ---
ok(tokenStrengthWarning("x".repeat(MIN_STRONG_TOKEN - 1)) !== null, "short token warns");
ok(tokenStrengthWarning("a".repeat(64)) !== null, "repeated-char token warns");
ok(tokenStrengthWarning("f3a9c2e8b1d4a7c6e5f0b9a8d7c6e5f4a3b2c1d0") === null, "long random token passes");

// --- parseTrustProxy ---
ok(parseTrustProxy(undefined) === 0, "unset → 0 hops");
ok(parseTrustProxy("false") === 0, "false → 0 hops");
ok(parseTrustProxy("true") === 1, "true → exactly 1 hop (never trust-all)");
ok(parseTrustProxy("2") === 2, "numeric hops honoured");
ok(parseTrustProxy("10") === 10, "upper bound 10 accepted");
for (const bad of ["-1", "abc", "11", "99", "1.5", " 2", "TRUE"]) {
  ok(parseTrustProxy(bad) === null, `invalid TRUST_PROXY ${JSON.stringify(bad)} → null (refuse to start)`);
}

// --- extractIp: forged X-Forwarded-For must not win ---
{
  const headers = { "x-forwarded-for": "6.6.6.6, 203.0.113.7" }; // client forged 6.6.6.6; nginx appended real IP
  ok(extractIp(headers, "10.0.0.1", 1) === "203.0.113.7", "1 hop → rightmost entry (real client), not forged leftmost");
  ok(extractIp(headers, "10.0.0.1", 0) === "10.0.0.1", "0 hops → socket address, header ignored");
  ok(extractIp(headers, "10.0.0.1", 2) === "6.6.6.6", "2 hops → entry two from the right");
  ok(extractIp(headers, "10.0.0.1", 5) === "6.6.6.6", "more hops than entries → leftmost, no crash");
  ok(extractIp({}, "10.0.0.1", 1) === "10.0.0.1", "no header → socket address");
  ok(extractIp({ "x-forwarded-for": ["1.1.1.1", "2.2.2.2"] }, "10.0.0.1", 1) === "2.2.2.2", "array header joined");
}

// --- hashIp never returns the raw address ---
{
  const h = hashIp("203.0.113.7", "salt");
  ok(h.length === 32 && !h.includes("203"), "hashIp is a 32-hex digest, not the raw IP");
  ok(hashIp("203.0.113.7", "salt") !== hashIp("203.0.113.7", "other-salt"), "salt changes the hash");
}

// --- audit: structured, no secrets ---
{
  const lines = [];
  audit({ action: "admin.auth", outcome: "denied", ipHash: "abc" }, (l) => lines.push(l));
  const rec = JSON.parse(lines[0]);
  ok(rec.audit === true && rec.action === "admin.auth" && rec.outcome === "denied", "audit line is structured JSON");
  ok(typeof rec.ts === "string" && !Number.isNaN(Date.parse(rec.ts)), "audit line has ISO timestamp");
}

console.log(`collector/auth: ${pass} passed, ${fail} failed`);
if (fail > 0) process.exit(1);
