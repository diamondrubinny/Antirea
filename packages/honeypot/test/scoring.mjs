/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * Tests for request scoring, including the REA source-map fetch signature.
 * Build first (tsc), then: node packages/honeypot/test/scoring.mjs
 */
import { scoreRequest } from "../dist/index.js";

let pass = 0;
let fail = 0;
const ok = (c, m) => { if (c) pass++; else { fail++; console.log("FAIL:", m); } };

// REA source-map Accept token — near-certain marker.
{
  const r = scoreRequest({
    userAgent: "node",
    path: "/assets/app.js.map",
    headers: { accept: "application/json, application/source-map+json;q=0.9" },
  });
  ok(r.reasons.includes("rea.sourceMapAccept") && r.score >= 0.85, "REA source-map Accept detected");
}

// REA source-map shape: .map with no cookie/referer/sec-fetch.
{
  const r = scoreRequest({ userAgent: "node", path: "/app.js.map", headers: { accept: "*/*" } });
  ok(r.reasons.includes("rea.sourceMapShape"), "REA source-map shape detected");
}

// Real browser loading a page is NOT flagged as REA.
{
  const r = scoreRequest({
    userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    path: "/",
    headers: {
      accept: "text/html,application/xhtml+xml",
      "accept-language": "en-US,en;q=0.9",
      "sec-ch-ua": '"Chromium";v="130"',
      "sec-fetch-site": "none",
      "sec-fetch-dest": "document",
      cookie: "sid=abc",
    },
  });
  ok(!r.reasons.some((x) => x.startsWith("rea.")) && r.score < 0.5, `clean browser not flagged (score ${r.score})`);
}

// Headless UA still flagged by the generic rule.
{
  const r = scoreRequest({ userAgent: "HeadlessChrome/130", path: "/app.js", headers: {} });
  ok(r.reasons.includes("ua.headless"), "headless UA flagged");
}

console.log(`\nRESULT: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
