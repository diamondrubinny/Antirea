/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * @antirea/secure-fn — server-side execution of proprietary functions.
 *
 * THE CDP-PROOF CORE: the function bodies live ONLY here, on the server. The
 * client sends inputs and receives outputs. A CDP/REA client attached to the
 * browser sees the network request and the result — never the algorithm.
 * There is no client code to reverse-engineer, because the logic is not in the
 * client.
 *
 * What this protects: the proprietary LOGIC. What it does not: it cannot hide
 * the input/output behaviour from someone authorized to call it — so we add
 * signed sessions, nonce anti-replay, rate limiting, and anomaly reporting to
 * make bulk behavioural harvesting expensive and visible in the dashboard.
 */
import express, { type Request, type Response, type Router } from "express";
import rateLimit from "express-rate-limit";
import {
  addressKey,
  createSecureFnCore,
  forwardedIp,
  trustHops,
  SESSIONS_PER_MIN,
  type SecureFnOptions,
} from "./core.js";

export type { InvokeContext, SecureFn, SecureFnOptions } from "./core.js";

/** Express adapter over the framework-neutral core (see core.ts, web.ts). */
export function createSecureFnRouter(opts: SecureFnOptions): Router {
  const core = createSecureFnCore(opts);
  const hops = trustHops(opts.trustProxy);
  const clientIp = (req: Request): string => {
    const xff = req.headers["x-forwarded-for"];
    return forwardedIp(Array.isArray(xff) ? xff.join(",") : xff, hops, req.socket.remoteAddress ?? "");
  };

  const router = express.Router();
  const jsonBody = express.json({ limit: "32kb" });

  const issueLimiter = rateLimit({
    windowMs: 60_000,
    limit: SESSIONS_PER_MIN,
    standardHeaders: true,
    legacyHeaders: false,
    // Same client address the core sees (trusted proxy hop), with IPv6
    // clients grouped by /56.
    keyGenerator: (req) => addressKey(clientIp(req)),
  });

  // Issue a short-lived session token.
  router.post("/session", issueLimiter, (req: Request, res: Response) => {
    const r = core.issueSession(clientIp(req));
    res.status(r.status).json(r.body);
  });

  // Invoke a registered function.
  router.post("/invoke", jsonBody, (req: Request, res: Response) => {
    core
      .invoke({ authorization: req.headers.authorization ?? "", body: req.body, ip: clientIp(req) })
      .then((r) => res.status(r.status).json(r.body))
      .catch(() => {
        if (!res.headersSent) res.status(500).json({ error: "internal" });
      });
  });

  return router;
}
