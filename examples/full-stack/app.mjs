/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * A single app wiring EVERY Antirea layer together:
 *   - harden: security headers (CSP/HSTS/…) + encrypted-bundle delivery
 *   - honeypot: behavioural detection + decoys (live)
 *   - secure-fn: proprietary logic runs server-side
 *   - challenge: proof-of-work gate on an expensive export route
 *   - watermark: per-viewer watermark on a protected module
 *   - guard: served to the page (client-side; domain-lock + CDP/REA detection)
 *
 * createApp() returns the Express app plus the handles the e2e test inspects.
 */
import express from "express";
import { honeypot } from "@antirea/honeypot";
import { createSecureFnRouter } from "@antirea/secure-fn";
import { challengeRouter, requireProof } from "@antirea/challenge";
import { watermark, MemoryCanaryStore } from "@antirea/watermark";
import { securityHeaders, generateKey, encryptBundle } from "@antirea/harden";

export async function createApp() {
  const app = express();
  const store = new MemoryCanaryStore();
  const POW_SECRET = "demo-pow-secret";
  const SECUREFN_SECRET = "demo-securefn-secret";
  const powDifficulty = 10; // low for a fast demo/test

  // 1. Security headers on every response (CSP allows blob: for gated imports).
  app.use(securityHeaders({ csp: { allowScriptBlob: true } }));

  // 2. Honeypot — serve decoys to analysis-shaped requests for the real bundle.
  app.use(
    honeypot({
      siteId: "full-demo",
      protect: [/^\/assets\/app\.js$/, /\.map$/],
      mode: "live",
      blockJa3: ["BADJA3"],
      allowlist: { verifyReverseDns: false },
    }),
  );
  app.get("/assets/app.js", (_req, res) => res.type("application/javascript").send("export const secret = () => 42;"));

  // 3. secure-fn — the proprietary formula never reaches the client.
  app.use(
    "/secure",
    createSecureFnRouter({
      secret: SECUREFN_SECRET,
      functions: { pricing: (a) => ({ result: Number(a?.x ?? 0) * 1337 + 17 }) },
    }),
  );

  // 4. Proof-of-work gate on an expensive/scrapable route.
  app.use("/__pow", challengeRouter({ secret: POW_SECRET, difficulty: powDifficulty }));
  app.get("/api/export", requireProof({ secret: POW_SECRET, difficulty: powDifficulty }), (_req, res) =>
    res.json({ data: "sensitive-export" }),
  );

  // 5. Per-viewer watermark on a protected module.
  app.use(watermark({ protect: [/^\/app\/core\.js$/], store, mode: "zerowidth", viewer: (req) => String(req.headers["x-session"] ?? "anon") }));
  app.get("/app/core.js", (_req, res) => res.type("application/javascript").send("export const f = (x) => x + 1;"));

  // 6. Encrypted-bundle delivery. The key is served here for the demo; in
  //    production, gate it behind the guard's attestation endpoint.
  const encKey = await generateKey();
  const encPayload = await encryptBundle("export const compute = (x) => x * 1337 + 17;", encKey);
  app.get("/enc/bundle", (_req, res) => res.json(encPayload));
  app.get("/enc/key", (_req, res) => res.json({ key: encKey }));

  return { app, store, encKey, encPayload, powDifficulty };
}
