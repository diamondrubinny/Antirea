/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * Express helpers for proof-of-work gating.
 *
 *   import express from "express";
 *   import { challengeRouter, requireProof } from "@antirea/challenge";
 *   const app = express();
 *   app.use("/__pow", challengeRouter({ secret: process.env.POW_SECRET }));
 *   // Require a solved proof on expensive/scrapable routes:
 *   app.use("/api/export", requireProof({ secret: process.env.POW_SECRET }));
 *
 * The browser gets a 402 with a challenge, solves it (see client.ts), and
 * retries with X-Antirea-PoW-Token / X-Antirea-PoW-Nonce headers.
 */
import express, { type Request, type Response, type Router } from "express";
import { ReplayCache } from "./guards.js";
import { issueChallenge, verifySolution, type PowConfig } from "./pow.js";

export function challengeRouter(cfg: PowConfig): Router {
  const router = express.Router();
  router.get("/", (_req: Request, res: Response) => {
    const ch = issueChallenge(cfg);
    res.setHeader("Cache-Control", "no-store");
    res.json({ token: ch.token, c: ch.c, difficulty: ch.difficulty, ttlMs: ch.ttlMs });
  });
  return router;
}

export interface RequireProofOptions extends PowConfig {
  /** Shared replay cache (optional; one is created if omitted). */
  replay?: ReplayCache;
}

export function requireProof(opts: RequireProofOptions) {
  const replay = opts.replay ?? new ReplayCache();
  return function proofMiddleware(req: Request, res: Response, next: (e?: unknown) => void): void {
    const token = (req.headers["x-antirea-pow-token"] as string) ?? "";
    const nonce = (req.headers["x-antirea-pow-nonce"] as string) ?? "";
    if (token && nonce) {
      const r = verifySolution(opts, token, nonce, replay);
      if (r.ok) return next();
    }
    // Not solved → issue a fresh challenge.
    const ch = issueChallenge(opts);
    res.status(402).json({
      error: "proof_required",
      token: ch.token,
      c: ch.c,
      difficulty: ch.difficulty,
      ttlMs: ch.ttlMs,
    });
  };
}
