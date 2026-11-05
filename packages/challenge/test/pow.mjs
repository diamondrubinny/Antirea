/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * Tests the proof-of-work flow. Build first (tsc), then: node test/pow.mjs
 */
import { createHash, randomBytes } from "node:crypto";
import { issueChallenge, verifySolution, ReplayCache, leadingZeroBits } from "../dist/index.js";
import { sha256hex } from "../dist/client.js";

let pass = 0,
  fail = 0;
const ok = (c, m) => {
  if (c) pass++;
  else {
    fail++;
    console.log("FAIL:", m);
  }
};

// 1. The browser SHA-256 matches node's for random inputs (so client solutions verify).
{
  let allMatch = true;
  for (let i = 0; i < 200; i++) {
    const s = randomBytes(1 + (i % 40)).toString("hex") + (i % 2 ? "é✓ß" : "");
    if (sha256hex(s) !== createHash("sha256").update(s).digest("hex")) {
      allMatch = false;
      break;
    }
  }
  ok(allMatch, "browser sha256 == node sha256 (200 random inputs incl. unicode)");
}

// Helper: solve with node crypto (same algorithm/format as the browser solver).
function solve(c, difficulty) {
  for (let n = 0; n < 50_000_000; n++) {
    const nonce = n.toString(36);
    if (leadingZeroBits(createHash("sha256").update(`${c}:${nonce}`).digest("hex")) >= difficulty) return nonce;
  }
  throw new Error("no solution");
}

const cfg = { secret: "test-secret", difficulty: 12, ttlMs: 60_000 };

// 2. issue → solve → verify ok
{
  const ch = issueChallenge(cfg);
  const nonce = solve(ch.c, ch.difficulty);
  ok(verifySolution(cfg, ch.token, nonce).ok, "valid solution verifies");
}

// 3. tampered token rejected
{
  const ch = issueChallenge(cfg);
  const nonce = solve(ch.c, ch.difficulty);
  const bad = ch.token.slice(0, -2) + (ch.token.endsWith("aa") ? "bb" : "aa");
  ok(!verifySolution(cfg, bad, nonce).ok, "tampered token rejected");
}

// 4. wrong secret rejected
{
  const ch = issueChallenge(cfg);
  const nonce = solve(ch.c, ch.difficulty);
  ok(!verifySolution({ ...cfg, secret: "other" }, ch.token, nonce).ok, "wrong secret rejected");
}

// 5. insufficient work rejected (nonce "0" almost never meets difficulty 12)
{
  const ch = issueChallenge(cfg);
  const r = verifySolution(cfg, ch.token, "0");
  ok(!r.ok && r.reason === "insufficient_work", "insufficient work rejected");
}

// 6. expired rejected
{
  const ch = issueChallenge({ ...cfg, ttlMs: -1 });
  const nonce = solve(ch.c, ch.difficulty);
  const r = verifySolution(cfg, ch.token, nonce);
  ok(!r.ok && r.reason === "expired", "expired challenge rejected");
}

// 7. replay rejected
{
  const replay = new ReplayCache();
  const ch = issueChallenge(cfg);
  const nonce = solve(ch.c, ch.difficulty);
  const first = verifySolution(cfg, ch.token, nonce, replay);
  const second = verifySolution(cfg, ch.token, nonce, replay);
  ok(first.ok && !second.ok && second.reason === "replay", "replayed solution rejected");
}

console.log(`\nRESULT: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
