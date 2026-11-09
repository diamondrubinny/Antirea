/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * Tests for strict ingest validation (never trust the client).
 * Build first (tsc), then: node packages/collector/test/validate.mjs
 */
import { validateEvent } from "../dist/validate.js";

let pass = 0;
let fail = 0;
const ok = (c, m) => {
  if (c) pass++;
  else {
    fail++;
    console.log("FAIL:", m);
  }
};

const base = () => ({
  v: 1,
  ts: Date.now(),
  sessionId: "s1",
  siteId: "my-site",
  signals: [{ type: "devtools", name: "cdp.debuggerPause", confidence: 0.9 }],
  path: "/",
  ua: "Mozilla/5.0",
  lang: "en",
  screen: "1280x720",
  tz: "UTC",
});

// Valid event passes.
{
  const r = validateEvent(base());
  ok(r.ok && r.value.siteId === "my-site" && r.value.signals.length === 1, "valid event accepted");
  ok(r.ok && r.value.source === "client", "default source is client");
}

// Rejections.
ok(!validateEvent(null).ok, "null rejected");
ok(!validateEvent("str").ok, "string rejected");
ok(!validateEvent({ ...base(), v: 2 }).ok, "unknown version rejected");
ok(!validateEvent({ ...base(), siteId: "" }).ok, "empty siteId rejected");
ok(!validateEvent({ ...base(), siteId: 42 }).ok, "non-string siteId rejected");
ok(!validateEvent({ ...base(), signals: "x" }).ok, "non-array signals rejected");
ok(!validateEvent({ ...base(), signals: [] }).ok, "no signals rejected");
ok(
  !validateEvent({ ...base(), signals: [{ type: "evil", name: "x", confidence: 1 }] }).ok,
  "unknown signal type dropped → no valid signals → rejected",
);

// Bounding / sanitising.
{
  const r = validateEvent({ ...base(), signals: [{ type: "automation", name: "n", confidence: 7 }] });
  ok(r.ok && r.value.signals[0].confidence === 1, "confidence clamped to <= 1");
}
{
  const r = validateEvent({ ...base(), signals: [{ type: "automation", name: "n", confidence: -3 }] });
  ok(r.ok && r.value.signals[0].confidence === 0, "confidence clamped to >= 0");
}
{
  const many = Array.from({ length: 500 }, () => ({ type: "console", name: "c", confidence: 0.5 }));
  const r = validateEvent({ ...base(), signals: many });
  ok(r.ok && r.value.signals.length === 50, "signals capped at 50");
}
{
  const r = validateEvent({ ...base(), ua: "A".repeat(10_000) });
  ok(r.ok && r.value.ua.length === 1024, "user-agent truncated to 1024");
}
{
  const r = validateEvent({ ...base(), siteId: "s".repeat(1000) });
  ok(r.ok && r.value.siteId.length === 128, "siteId truncated to 128");
}
{
  const r = validateEvent({ ...base(), ts: 1 });
  ok(r.ok && Math.abs(r.value.ts - Date.now()) < 5000, "absurd past timestamp clamped to now");
}
{
  const r = validateEvent({ ...base(), ts: Date.now() + 30 * 864e5 });
  ok(r.ok && Math.abs(r.value.ts - Date.now()) < 5000, "far-future timestamp clamped to now");
}
{
  const r = validateEvent({ ...base(), source: "admin" });
  ok(r.ok && r.value.source === "client", "unknown source coerced to client");
}
{
  const r = validateEvent({ ...base(), source: "honeypot", honeypot: { action: "decoy", score: 0.91 } });
  ok(r.ok && r.value.source === "honeypot" && r.value.honeypot.score === 0.91, "honeypot source + details kept");
}
{
  const r = validateEvent({ ...base(), __proto__: { polluted: true }, extra: "<script>" });
  ok(r.ok && !("extra" in r.value) && !("polluted" in r.value), "unknown fields are not copied through");
}

console.log(`collector/validate: ${pass} passed, ${fail} failed`);
if (fail > 0) process.exit(1);
