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
import {
  canaryAlert,
  parseAlertSignals,
  parseMinConfidence,
  signalAlerts,
  spikeAlert,
} from "../dist/alerts.js";

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
  ok(
    a.key !== b.key && a.extra.site === b.extra.site,
    "sites sharing a 64-character prefix keep separate cooldown keys",
  );
}
{
  const s = spikeAlert("site\nX", 50, 5);
  ok(
    s.key === "spike" && s.extra.event === "spike" && s.extra.threshold === 50 && s.extra.window_min === 5,
    "spike alert fields",
  );
  ok(!s.text.includes("\n"), "spike text has no injected newline");
}

// --- configurable signal rules ---
{
  const pats = parseAlertSignals(" rea.* , honeypot:rea.sourceMapAccept ,, cdp.debuggerPause ");
  ok(
    pats.length === 3 && pats[0].prefix && pats[0].value === "rea." && !pats[1].prefix,
    "patterns are parsed; a trailing * is a prefix",
  );
  ok(
    parseAlertSignals(undefined).length === 0 && parseAlertSignals("").length === 0,
    "unset or empty → no rules",
  );
  let rejected = 0;
  for (const bad of [
    "*",
    "re a",
    "rea.*.x",
    "a*b",
    "<script>",
    "x".repeat(65),
    Array(21).fill("a").join(","),
  ]) {
    try {
      parseAlertSignals(bad);
    } catch {
      rejected++;
    }
  }
  ok(rejected === 7, `invalid patterns are rejected (${rejected}/7)`);
  ok(parseMinConfidence(undefined) === 0 && parseMinConfidence("0.8") === 0.8, "minimum confidence parses");
  let badConf = 0;
  for (const bad of ["2", "-0.1", "abc"]) {
    try {
      parseMinConfidence(bad);
    } catch {
      badConf++;
    }
  }
  ok(badConf === 3, "out-of-range confidence is rejected");

  // First alert of an event, or null — most cases below match a single rule.
  const signalAlert = (...args) => signalAlerts(...args)[0] ?? null;
  const client = (names, conf = 0.99, over = {}) =>
    event({
      source: "client",
      path: "/app",
      signals: names.map((name) => ({ type: "automation", name, confidence: conf })),
      ...over,
    });
  const a = signalAlert(client(["rea.scenarioSwPolicy", "cdp.debuggerPause", "ua.other"]), "IL", pats, 0);
  ok(
    a !== null && a.extra.event === "signal" && a.extra.rule === "rea.*",
    "a matching signal raises an alert, tagged with its rule",
  );
  ok(
    JSON.stringify(a.extra.signals) === '["rea.scenarioSwPolicy"]',
    "an alert lists only the signals of its own rule",
  );
  {
    // One alert per distinct rule: a rule in cooldown must not hide another.
    const all = signalAlerts(client(["rea.x", "rea.y", "cdp.debuggerPause", "ua.other"]), null, pats, 0);
    ok(
      all.length === 2 && all.map((x) => x.extra.rule).join() === "rea.*,cdp.debuggerPause",
      "one alert per distinct matching rule",
    );
    ok(
      all[0].key === "signal:my-site:rea.*" && all[1].key === "signal:my-site:cdp.debuggerPause",
      "each rule has its own cooldown key",
    );
    ok(
      JSON.stringify(all[0].extra.signals) === '["rea.x","rea.y"]' &&
        JSON.stringify(all[1].extra.signals) === '["cdp.debuggerPause"]',
      "signals are grouped under their rule",
    );
    ok(
      signalAlerts(client(Array.from({ length: 50 }, (_, i) => "rea.n" + i)), null, pats, 0).length === 1,
      "many names under one prefix still give one alert",
    );
    ok(signalAlerts(client(["ua.other"]), null, pats, 0).length === 0, "no match → empty list");
  }
  ok(
    a.extra.source === "client" && a.extra.country === "IL" && a.extra.site === "my-site",
    "payload carries source, country and site",
  );
  const wire = JSON.stringify({ text: a.text, ...a.extra });
  ok(
    !wire.includes("SECRET-UA-MARKER") && !wire.includes("SESSION-MARKER"),
    "no User-Agent or session id in a signal alert",
  );
  ok(signalAlert(client(["ua.other"]), null, pats, 0) === null, "no matching signal → no alert");
  ok(signalAlert(client(["rea.scenarioSwPolicy"]), null, [], 0) === null, "no rules configured → no alert");
  ok(
    signalAlert(client(["rea.scenarioSwPolicy"], 0.5), null, pats, 0.8) === null,
    "below the minimum confidence → no alert",
  );
  ok(
    signalAlert(client(["rea.scenarioSwPolicy"], 0.9), null, pats, 0.8) !== null,
    "at or above the minimum confidence → alert",
  );
  ok(signalAlert(client(["rea"]), null, pats, 0) === null, "a prefix rule does not match a shorter name");
  // A client inventing names under a prefix cannot mint new cooldown keys.
  const k1 = signalAlert(client(["rea.invented1"]), null, pats, 0).key;
  const k2 = signalAlert(client(["rea.invented2"]), null, pats, 0).key;
  ok(
    k1 === k2 && k1 === "signal:my-site:rea.*",
    "cooldown key uses the configured rule, not the signal name",
  );
  // The canary keeps its own alert and is not duplicated by a broad rule.
  const broad = parseAlertSignals("honeypot:*");
  ok(
    signalAlert(
      event({ signals: [{ type: "automation", name: "honeypot:canary.sourceMap", confidence: 1 }] }),
      null,
      broad,
      0,
    ) === null,
    "the canary signal is left to the canary alert",
  );
  const hostile = signalAlert(client(["rea.x\n@channel" + "y".repeat(200)]), null, pats, 0);
  // eslint-disable-next-line no-control-regex
  ok(
    hostile.extra.signals[0].length <= 48 && !/[\u0000-\u001f]/.test(hostile.text),
    "signal names are capped and stripped of control characters",
  );
}

console.log(`\ncollector/alerts: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
