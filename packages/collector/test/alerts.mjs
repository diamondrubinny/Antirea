/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * Tests for the webhook alert payloads — in particular, what leaves the server.
 * Build first, then: node packages/collector/test/alerts.mjs
 */
import { canaryAlert, spikeAlert } from "../dist/alerts.js";

let pass = 0;
let fail = 0;
const ok = (c, m) => {
  if (c) pass++;
  else {
    fail++;
    console.log("FAIL:", m);
  }
};

const UA = "Mozilla/5.0 SECRET-UA-MARKER";
const event = (over = {}) => ({
  v: 1,
  ts: 1,
  sessionId: "SESSION-MARKER",
  siteId: "my-site",
  source: "honeypot",
  path: "/__antirea/m/44a3a356bc14d54ee3a0f699.map",
  ua: UA,
  lang: "",
  screen: "",
  tz: "",
  signals: [
    { type: "automation", name: "honeypot:canary.sourceMap", confidence: 1 },
    { type: "automation", name: "honeypot:rea.sourceMapAccept", confidence: 1 },
  ],
  honeypot: { action: "decoy", score: 1 },
  ...over,
});

{
  const a = canaryAlert(event(), "IL");
  ok(a !== null && a.key === "canary:my-site", "canary hit → alert keyed per site");
  ok(
    a.extra.event === "canary" && a.extra.site === "my-site" && a.extra.path.endsWith(".map"),
    "carries site and canary path",
  );
  ok(
    a.extra.action === "decoy" && a.extra.score === 1 && a.extra.country === "IL",
    "carries action, score and country",
  );
  ok(
    JSON.stringify(a.extra.reasons) === '["canary.sourceMap","rea.sourceMapAccept"]',
    "reasons listed without the honeypot: prefix",
  );
  const wire = JSON.stringify({ text: a.text, ...a.extra });
  ok(
    !wire.includes("SECRET-UA-MARKER") && !wire.includes("SESSION-MARKER"),
    "no User-Agent and no session id leave the server",
  );
  ok(!/\bip\b|ip_hash|"ua"/i.test(Object.keys(a.extra).join(",")), "payload has no IP, IP-hash or UA field");
}
ok(
  canaryAlert(
    event({ signals: [{ type: "automation", name: "honeypot:ua.headless", confidence: 0.6 }] }),
    null,
  ) === null,
  "non-canary honeypot event → no alert",
);
ok(
  canaryAlert(event({ source: "client" }), null) === null,
  "a browser-sourced event cannot raise a canary alert",
);
ok(
  canaryAlert(event({ source: undefined }), null) === null,
  "an event without a source cannot raise a canary alert",
);
ok(
  canaryAlert(event(), null).extra.country === null && canaryAlert(event(), "").extra.country === null,
  "unknown country is null",
);
{
  // Hostile strings are bounded and stripped of control characters.
  const a = canaryAlert(
    event({ siteId: "s\n@channel\u0000" + "x".repeat(500), path: "/p\r\n" + "y".repeat(900) }),
    null,
  );
  ok(a.extra.site.length <= 64 && a.extra.path.length <= 200, "site and path are length-capped");
  // eslint-disable-next-line no-control-regex
  ok(
    !/[\u0000-\u001f]/.test(a.text) && !/[\u0000-\u001f]/.test(a.extra.site + a.extra.path),
    "control characters are removed from chat text",
  );
  const many = canaryAlert(
    event({
      signals: Array.from({ length: 40 }, (_, i) => ({
        type: "automation",
        name: i ? "honeypot:r" + i : "honeypot:canary.sourceMap",
        confidence: 1,
      })),
    }),
    null,
  );
  ok(many.extra.reasons.length === 12, "reasons are capped");
}
{
  const prefix = "p".repeat(64);
  const a = canaryAlert(event({ siteId: prefix + "-one" }), null);
  const b = canaryAlert(event({ siteId: prefix + "-two" }), null);
  ok(a.key !== b.key && a.extra.site === b.extra.site, "sites sharing a 64-character prefix keep separate cooldown keys");
}
{
  const s = spikeAlert("site\nX", 50, 5);
  ok(
    s.key === "spike" && s.extra.event === "spike" && s.extra.threshold === 50 && s.extra.window_min === 5,
    "spike alert fields",
  );
  ok(!s.text.includes("\n"), "spike text has no injected newline");
}

console.log(`\ncollector/alerts: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
