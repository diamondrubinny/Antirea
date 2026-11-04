/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * Unit test for the behavioural engine. Proves detection works on
 * server-observed facts even when the client header is forged.
 * Build first (tsc), then: node packages/honeypot/test/behavior.mjs
 */
import { BehaviorTracker } from "../dist/behavior.js";

let pass = 0;
let fail = 0;
const ok = (c, m) => {
  if (c) pass++;
  else {
    fail++;
    console.log("FAIL:", m);
  }
};

// 1. Robotic cadence: perfectly even 40ms intervals => flagged, regardless of UA.
{
  const t = new BehaviorTracker();
  let v;
  for (let i = 0; i < 12; i++) {
    v = t.record({ ip: "1.1.1.1", path: "/a.js", fingerprint: "fp", isAsset: true, isNavigation: false, now: 1000 + i * 40 });
  }
  ok(v.score >= 0.4 && v.reasons.some((r) => r.startsWith("cadence") || r.startsWith("fastCadence")), "robotic cadence flagged");
}

// 2. Header churn: same IP, 4 different fingerprints (forged UA rotation) => flagged.
{
  const t = new BehaviorTracker();
  let v;
  for (let i = 0; i < 4; i++) {
    v = t.record({ ip: "2.2.2.2", path: "/p" + i, fingerprint: "fp" + i, isAsset: false, isNavigation: true, now: 1000 + i * 3000 });
  }
  ok(v.reasons.some((r) => r.startsWith("headerChurn")), "forged header rotation flagged (server-truth)");
}

// 3. Harvesting: many assets, zero navigations => flagged.
{
  const t = new BehaviorTracker();
  let v;
  for (let i = 0; i < 10; i++) {
    v = t.record({ ip: "3.3.3.3", path: "/asset" + i + ".js", fingerprint: "fp", isAsset: true, isNavigation: false, now: 1000 + i * 1500 });
  }
  ok(v.reasons.some((r) => r.startsWith("harvest")), "asset harvesting flagged");
}

// 4. Human-like: irregular intervals, a navigation, few assets => low score.
{
  const t = new BehaviorTracker();
  const jitter = [0, 1200, 300, 4500, 800, 2600];
  let now = 1000;
  let v;
  v = t.record({ ip: "4.4.4.4", path: "/", fingerprint: "fp", isAsset: false, isNavigation: true, now });
  for (const d of jitter) {
    now += d;
    v = t.record({ ip: "4.4.4.4", path: "/app.js", fingerprint: "fp", isAsset: true, isNavigation: false, now });
  }
  ok(v.score < 0.4, `human-like stays low (got ${v.score.toFixed(2)})`);
}

console.log(`\nRESULT: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
