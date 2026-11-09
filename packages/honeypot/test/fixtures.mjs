/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * Signature regression + false-positive gate.
 *
 * Scores every recorded request in fixtures/captured.json (measured from real
 * clients, see fixtures/capture.mjs) and fixtures/synthetic.json (documented
 * header sets, clearly labelled) and checks the outcome each one must get at
 * the default threshold:
 *   clean  — score 0, no reasons (a normal browser)
 *   report — visible in the dashboard, NOT decoyed (0 < score < threshold)
 *   decoy  — score >= threshold
 * A legitimate client that gets decoyed is a false positive and fails the run.
 */
import { readFileSync } from "node:fs";
import { scoreRequest } from "../dist/index.js";

const THRESHOLD = 0.7; // honeypot default
const load = (f) => JSON.parse(readFileSync(new URL(`./fixtures/${f}`, import.meta.url), "utf8"));
const captured = load("captured.json");
const synthetic = load("synthetic.json");

let pass = 0;
let fail = 0;
let legit = 0;
let falsePositives = 0;

function outcome(score) {
  if (score >= THRESHOLD) return "decoy";
  return score === 0 ? "clean" : "report";
}

for (const [kind, set] of [
  ["measured", captured.fixtures],
  ["synthetic", synthetic.fixtures],
]) {
  for (const f of set) {
    const r = scoreRequest({ userAgent: f.userAgent, headers: f.headers, path: f.path });
    const got = outcome(r.score);
    if (f.expect !== "decoy") {
      legit++;
      if (got === "decoy") falsePositives++;
    }
    const ok = got === f.expect && (f.expect !== "clean" || r.reasons.length === 0);
    if (ok) pass++;
    else {
      fail++;
      console.log(
        `FAIL [${kind}] ${f.id}: expected ${f.expect}, got ${got} (score ${r.score.toFixed(2)}; ${r.reasons.join(",") || "no reasons"})`,
      );
    }
  }
}

console.log(
  `fixtures: REA ${captured.reaVersion}, captured ${captured.capturedAt}; ` +
    `${captured.fixtures.length} measured + ${synthetic.fixtures.length} synthetic`,
);
console.log(`false positives (legitimate client decoyed): ${falsePositives}/${legit}`);
console.log(`\nRESULT: ${pass} passed, ${fail} failed`);
process.exit(fail || falsePositives ? 1 : 0);
