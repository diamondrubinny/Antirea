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
import { scoreRequest, sourceMapCanaryComment } from "../dist/index.js";

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

// --- REA 6.8.0 / Node built-in fetch (measured headers of REA's source-map fetcher on Node 22) ---
const nodeFetch = { "user-agent": "node", accept: "*/*", "accept-language": "*", "sec-fetch-mode": "cors", "accept-encoding": "gzip, deflate" };
{
  const r = scoreRequest({ userAgent: "node", headers: nodeFetch, path: "/assets/app.js" });
  ok(r.reasons.includes("ua.runtimeFetch"), "Node fetch UA flagged");
  ok(r.reasons.includes("forgery.partialSecFetch"), "Sec-Fetch-Mode without Site/Dest flagged");
  ok(r.reasons.includes("acceptLanguage.wildcard"), "Accept-Language * flagged");
  ok(r.score >= 0.6 && r.score < 0.7, `Node fetch of a script is reported, not decoyed on its own (got ${r.score}; was 0.00 before these rules)`);
}
// A legitimate server-side Node client (monitoring, SSR prefetch) fetching a
// script must not be decoyed by its runtime defaults alone.
{
  const r = scoreRequest({ userAgent: "node", headers: { ...nodeFetch, accept: "application/javascript" }, path: "/assets/app.js" });
  ok(r.score < 0.7, `legit Node service fetching a script is below threshold (got ${r.score})`);
}
// Runtime markers are one piece of evidence: three of them do not stack past the cap.
{
  const r = scoreRequest({ userAgent: "node", headers: { ...nodeFetch, accept: "application/json" }, path: "/api/status" });
  ok(r.score < 0.7, `runtime markers counted once (got ${r.score})`);
}
{
  const r = scoreRequest({ userAgent: "node", headers: nodeFetch, path: "/assets/app.js.map" });
  ok(r.score >= 0.7 && !r.reasons.includes("rea.sourceMapAccept"), "REA fork that changed Accept is still caught (runtime + .map corroboration)");
}
ok(scoreRequest({ userAgent: "Bun/1.2.3", headers: {}, path: "/a.js" }).reasons.includes("ua.runtimeFetch"), "Bun runtime UA flagged");
ok(!scoreRequest({ userAgent: "nodejs-monitor/2 (+https://x)", headers: {}, path: "/a.js" }).reasons.includes("ua.runtimeFetch"), "UA merely containing 'node' is not the runtime rule");
{
  const r = scoreRequest({
    userAgent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36",
    headers: { "sec-ch-ua": '"HeadlessChrome";v="153", "Chromium";v="153"', "sec-fetch-site": "same-origin", "sec-fetch-mode": "no-cors", "sec-fetch-dest": "script", accept: "*/*", "accept-language": "en-US" },
    path: "/assets/app.js",
  });
  ok(r.reasons.includes("ua.headlessClientHint"), "HeadlessChrome brand in Client Hints flagged despite a spoofed UA");
}
{
  const r = scoreRequest({ userAgent: "HeadlessChrome/153", headers: { "sec-ch-ua": '"HeadlessChrome";v="153"' }, path: "/a.js" });
  ok(r.reasons.includes("ua.headless") && !r.reasons.includes("ua.headlessClientHint"), "headless not double-counted when the UA already says so");
}
// --- false-positive guard: a real desktop Chrome script request gains no new reasons ---
{
  const r = scoreRequest({
    userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36",
    headers: {
      accept: "*/*", "accept-language": "he-IL,he;q=0.9,en-US;q=0.8,en;q=0.7", "sec-ch-ua": '"Chromium";v="153", "Google Chrome";v="153", "Not_A Brand";v="99"',
      "sec-fetch-site": "same-origin", "sec-fetch-mode": "no-cors", "sec-fetch-dest": "script", referer: "https://example.com/", cookie: "sid=1",
    },
    path: "/assets/app.js",
  });
  ok(r.score === 0 && r.reasons.length === 0, `real Chrome request scores 0 (got ${r.score} ${r.reasons})`);
}
// --- false-positive guard: a real Chrome behind a proxy that strips Sec-Fetch-Site/Dest and Accept-Language ---
{
  const r = scoreRequest({
    userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36",
    headers: { accept: "*/*", "sec-ch-ua": '"Chromium";v="153"', "sec-fetch-mode": "no-cors", referer: "https://example.com/", cookie: "sid=1" },
    path: "/assets/app.js",
  });
  ok(!r.reasons.includes("forgery.partialSecFetch"), "partial Sec-Fetch not counted when the UA claims Chromium");
  ok(r.score < 0.7, `proxied real Chrome stays below threshold (got ${r.score} ${r.reasons})`);
}
// --- source-map canary ---
{
  const c = sourceMapCanaryComment("/__antirea/m/", "release42abc");
  ok(c === "//# sourceMappingURL=/__antirea/m/release42abc.map", "canary comment format");
  ok(/^\/\/# sourceMappingURL=\/__antirea\/m\/[0-9a-f]{24}\.map$/.test(sourceMapCanaryComment()), "default canary is random and unguessable");
  let threw = false;
  try { sourceMapCanaryComment("/x/", "../../etc"); } catch { threw = true; }
  ok(threw, "canary token rejects path traversal / unsafe characters");
  const r = scoreRequest({ userAgent: "Mozilla/5.0 Chrome/153", headers: { cookie: "a=1" }, path: "/__antirea/m/release42abc.map", canaryPaths: ["/__antirea/m/"] });
  ok(r.reasons.includes("canary.sourceMap") && r.score === 1, "canary hit is decisive even with browser-like headers");
  ok(!scoreRequest({ userAgent: "x", headers: {}, path: "/__antirea/m/a.map" }).reasons.includes("canary.sourceMap"), "no canary configured → rule off");
  ok(!scoreRequest({ userAgent: "x", headers: {}, path: "/maps-ui/app.js", canaryPaths: ["/maps"] }).reasons.includes("canary.sourceMap"), "canary prefix matches on a directory boundary (/maps ≠ /maps-ui)");
  ok(scoreRequest({ userAgent: "x", headers: {}, path: "/maps/t0k3n.map", canaryPaths: ["/maps"] }).reasons.includes("canary.sourceMap"), "canary prefix without trailing slash still matches its directory");
  ok(!scoreRequest({ userAgent: "x", headers: {}, path: "/app.js", canaryPaths: ["/"] }).reasons.includes("canary.sourceMap"), "root prefix is refused (would flag every request)");
}

console.log(`\nRESULT: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
