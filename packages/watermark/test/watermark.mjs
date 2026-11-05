/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * Tests watermark embed/recover, canary store, scan (mock fetch), and alerts.
 * Build first (tsc), then: node test/watermark.mjs
 */
import {
  embed, recover, stripZeroWidth,
  MemoryCanaryStore, issueCanary, watermarkText,
  buildGitHubQuery, parseGitHubResults, scanGitHub,
  SpikeDetector, Alerter,
} from "../dist/index.js";

let pass = 0, fail = 0;
const ok = (c, m) => { if (c) pass++; else { fail++; console.log("FAIL:", m); } };

const CODE = `"use strict";\nexport const f = (x) => x * 2;\n`;

// 1. zero-width embed/recover round-trip; invisible (visible text unchanged).
{
  const token = "wm_abc123def456";
  const wm = embed(CODE, token, "zerowidth");
  ok(recover(wm).includes(token), "zero-width: token recovered");
  ok(wm.replace(/[​‌⁠⁣]/g, "") === CODE, "zero-width: visible text is unchanged");
}

// 2. comment embed/recover round-trip.
{
  const token = "wm_comment0001";
  const wm = embed(CODE, token, "comment");
  ok(recover(wm).includes(token), "comment: token recovered");
  ok(wm.includes("/*!wm:"), "comment: bang comment present");
}

// 3. strip zero-width removes the mark.
{
  const wm = embed(CODE, "wm_tostrip0001", "zerowidth");
  ok(recover(stripZeroWidth(wm)).length === 0, "stripZeroWidth removes the watermark");
}

// 4. canary store: unique per viewer, lookup identifies the recipient.
{
  const store = new MemoryCanaryStore();
  const a = watermarkText(store, CODE, "viewer-A");
  const b = watermarkText(store, CODE, "viewer-B");
  ok(a.token !== b.token, "each viewer gets a unique token");
  ok(store.get(a.token)?.viewer === "viewer-A", "store maps token -> viewer A");
  ok(store.get(b.token)?.viewer === "viewer-B", "store maps token -> viewer B");
  // A leaked copy of A's bundle is traced back to viewer-A:
  const leaked = a.body;
  const found = recover(leaked);
  ok(found.length === 1 && store.get(found[0])?.viewer === "viewer-A", "leaked copy traced to the leaker");
}

// 5. scan: query building + result parsing + scanGitHub with a mock fetch.
{
  const q = buildGitHubQuery("wm_xyz");
  ok(q.includes("/search/code?q=") && q.includes("wm_xyz"), "scan query built");
  const parsed = parseGitHubResults("wm_xyz", { items: [{ html_url: "https://github.com/x/y/blob/a.js", repository: { full_name: "x/y" } }] });
  ok(parsed.length === 1 && parsed[0].repository === "x/y", "scan results parsed");

  const mockFetch = async () => ({ ok: true, json: async () => ({ items: [{ html_url: "u", repository: { full_name: "evil/clone" } }] }) });
  const hits = await scanGitHub(["wm_leak"], { token: "t", fetchImpl: mockFetch });
  ok(hits.length === 1 && hits[0].repository === "evil/clone" && hits[0].token === "wm_leak", "scanGitHub returns hits (mock)");
}

// 6. spike detector fires once on crossing the threshold.
{
  const d = new SpikeDetector(60_000, 3);
  const fired = [d.hit(1000), d.hit(1100), d.hit(1200), d.hit(1300)];
  ok(fired[0] === false && fired[1] === false && fired[2] === true && fired[3] === false, "spike fires once at threshold");
}

// 7. alerter sends via webhook and respects cooldown (mock fetch).
{
  let calls = 0;
  const a = new Alerter({ webhookUrl: "https://hook", cooldownMs: 10_000, fetchImpl: async () => { calls++; return { ok: true }; } });
  const s1 = await a.send("spike", "attack spike", {}, 1000);
  const s2 = await a.send("spike", "attack spike", {}, 2000);   // within cooldown
  const s3 = await a.send("spike", "attack spike", {}, 20_000); // after cooldown
  ok(s1 === true && s2 === false && s3 === true && calls === 2, "webhook sent with cooldown honored");
}

console.log(`\nRESULT: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
