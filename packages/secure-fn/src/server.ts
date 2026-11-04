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
import { randomUUID } from "node:crypto";
import { NonceStore, RateLimiter } from "./guards.js";
import { signToken, verifyToken } from "./signing.js";

export interface InvokeContext {
  sid: string;
  ip: string;
  /** Invocations by this session in the current window (incl. this one). */
  invokeCount: number;
}

export type SecureFn<TArgs = unknown, TOut = unknown> = (
  args: TArgs,
  ctx: InvokeContext,
) => Promise<TOut> | TOut;

export interface SecureFnOptions {
  /** HMAC secret for session tokens. REQUIRED, from env, never in code. */
  secret: string;
  /** Map of function name -> implementation. Bodies stay server-side. */
  functions: Record<string, SecureFn>;
  /** Session token TTL (ms). Default 10 min. */
  sessionTtlMs?: number;
  /** Max invokes per session per minute before rejection. Default 120. */
  maxInvokesPerMin?: number;
  /** Nonce replay window (ms). Default 2 min. */
  nonceTtlMs?: number;
  /** If set, anomalies are reported here (the collector's /api/events). */
  reportUrl?: string;
  /** Site id used in anomaly reports. */
  siteId?: string;
  /** Trust X-Forwarded-For (only behind a trusted proxy). Default false. */
  trustProxy?: boolean;
}

function clientIp(req: Request, trustProxy: boolean): string {
  if (trustProxy) {
    const xff = req.headers["x-forwarded-for"];
    const v = Array.isArray(xff) ? xff[0] : xff;
    if (v) return v.split(",")[0].trim();
  }
  return req.socket.remoteAddress ?? "";
}

export function createSecureFnRouter(opts: SecureFnOptions): Router {
  if (!opts.secret) throw new Error("[secure-fn] secret is required");
  const sessionTtlMs = opts.sessionTtlMs ?? 10 * 60_000;
  const maxPerMin = opts.maxInvokesPerMin ?? 120;
  const nonceTtlMs = opts.nonceTtlMs ?? 2 * 60_000;
  const trustProxy = opts.trustProxy ?? false;

  const nonces = new NonceStore(nonceTtlMs);
  const limiter = new RateLimiter(maxPerMin, 60_000);

  async function reportAnomaly(name: string, ip: string, detail: string): Promise<void> {
    // Operational log (server-side only; not sent to the client).
    console.warn(`[secure-fn] anomaly ${detail} fn=${name} ip=${ip}`);
    if (!opts.reportUrl) return;
    try {
      await fetch(opts.reportUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          v: 1,
          ts: Date.now(),
          sessionId: "secure-fn",
          siteId: opts.siteId ?? "secure-fn",
          source: "server",
          path: `/invoke/${name}`,
          ua: "",
          lang: "",
          screen: "",
          tz: "",
          signals: [{ type: "automation", name: `securefn:${detail}`, confidence: 0.9 }],
        }),
      });
    } catch {
      /* reporting must never break the endpoint */
    }
  }

  const router = express.Router();
  const jsonBody = express.json({ limit: "32kb" });

  const issueLimiter = rateLimit({ windowMs: 60_000, limit: 30, standardHeaders: true, legacyHeaders: false });

  // Issue a short-lived session token.
  router.post("/session", issueLimiter, (_req: Request, res: Response) => {
    const sid = randomUUID();
    const token = signToken(opts.secret, { sid, exp: Date.now() + sessionTtlMs });
    res.json({ token, ttlMs: sessionTtlMs });
  });

  // Invoke a registered function.
  router.post("/invoke", jsonBody, (req: Request, res: Response) => {
    void (async () => {
      const ip = clientIp(req, trustProxy);

      // 1. Auth: verify the signed session token.
      const auth = req.headers.authorization ?? "";
      const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
      const payload = verifyToken(opts.secret, token);
      if (!payload) {
        res.status(401).json({ error: "invalid session" });
        return;
      }

      const body = req.body as { name?: unknown; args?: unknown; nonce?: unknown };
      const name = typeof body.name === "string" ? body.name : "";
      const nonce = typeof body.nonce === "string" ? body.nonce : "";

      // 2. Anti-replay.
      if (!nonces.check(nonce)) {
        res.status(409).json({ error: "replay" });
        return;
      }

      // 3. Rate limit per session; a spike is a harvesting signal.
      const rl = limiter.hit(payload.sid);
      if (!rl.ok) {
        void reportAnomaly(name || "?", ip, "rate_exceeded");
        res.status(429).json({ error: "rate limited" });
        return;
      }

      // 4. Dispatch to the server-side implementation.
      const fn = Object.prototype.hasOwnProperty.call(opts.functions, name)
        ? opts.functions[name]
        : undefined;
      if (!fn) {
        res.status(404).json({ error: "unknown function" });
        return;
      }

      try {
        const result = await fn(body.args, { sid: payload.sid, ip, invokeCount: rl.count });
        res.json({ result });
      } catch (e) {
        // Never leak internals (stack/algorithm) to the client.
        console.error("[secure-fn] invoke error", name, (e as Error).message);
        res.status(500).json({ error: "execution failed" });
      }
    })().catch(() => {
      if (!res.headersSent) res.status(500).json({ error: "internal" });
    });
  });

  return router;
}
