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
  SpikeDetector, Alerter, signWebhook,
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

// 8. alerter: signature, failure handling, URL rules, bounded cooldown table.
{
  const sent = [];
  const a = new Alerter({ webhookUrl: "https://hook.example/x", secret: "0123456789abcdef-secret", cooldownMs: 1000, fetchImpl: async (url, init) => { sent.push({ url, init }); return { ok: true }; } });
  const okSend = await a.send("k", "hello", { event: "canary" }, 1_700_000_000_000);
  const { init } = sent[0];
  const ts = Number(init.headers["X-Antirea-Timestamp"]);
  ok(okSend && ts === 1_700_000_000, "signed alert carries the timestamp (seconds)");
  ok(init.headers["X-Antirea-Signature"] === "sha256=" + signWebhook("0123456789abcdef-secret", ts, init.body), "signature = HMAC-SHA-256 over '<timestamp>.<body>'");
  ok(signWebhook("0123456789abcdef-secret", ts, init.body + " ") !== signWebhook("0123456789abcdef-secret", ts, init.body), "a modified body does not verify");
  ok(signWebhook("0123456789abcdef-secret", ts + 1, init.body) !== signWebhook("0123456789abcdef-secret", ts, init.body), "a replayed body with another timestamp does not verify");
  ok(JSON.parse(init.body).text === "hello" && JSON.parse(init.body).event === "canary", "body carries text and structured fields");
  ok(init.signal instanceof AbortSignal, "requests have a timeout");

  const unsigned = [];
  const b = new Alerter({ webhookUrl: "https://hook.example/x", fetchImpl: async (_u, i) => { unsigned.push(i); return { ok: true }; } });
  await b.send("k", "t");
  ok(!("X-Antirea-Signature" in unsigned[0].headers), "no signature header without a secret");

  const down = new Alerter({ webhookUrl: "https://hook.example/x", cooldownMs: 1000, fetchImpl: async () => ({ ok: false, status: 500 }) });
  ok((await down.send("k", "t", {}, 0)) === false, "a non-2xx answer is reported as not sent");
  const thrower = new Alerter({ webhookUrl: "https://hook.example/x", fetchImpl: async () => { throw new Error("network"); } });
  ok((await thrower.send("k", "t")) === false, "a network error never throws into the caller");

  let rejected = 0;
  for (const bad of [{ webhookUrl: "not a url" }, { webhookUrl: "http://hook.example/x" }, { webhookUrl: "file:///etc/passwd" }, { webhookUrl: "https://hook.example/x", secret: "short" }]) {
    try { new Alerter(bad); } catch { rejected++; }
  }
  ok(rejected === 4, "invalid URL, plain http, non-http scheme and weak secret are rejected");
  let localOk = true;
  try { new Alerter({ webhookUrl: "http://localhost:9000/hook" }); } catch { localOk = false; }
  ok(localOk, "plain http is allowed for localhost only");

  let calls = 0;
  const many = new Alerter({ webhookUrl: "https://hook.example/x", cooldownMs: 60_000, fetchImpl: async () => { calls++; return { ok: true }; } });
  for (let i = 0; i < 1500; i++) await many.send("site-" + i, "t", {}, 1000 + i);
  ok(calls === 1500 && many.last.size <= 1000, `cooldown table stays bounded (${many.last.size} keys)`);
  ok((await many.send("site-1499", "t", {}, 3000)) === false, "recent keys keep their cooldown after pruning");
}

console.log(`\nRESULT: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
