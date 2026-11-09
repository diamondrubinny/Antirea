/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * Framework-neutral core of secure-fn: session issuing and function invocation
 * as plain functions returning `{ status, body }`. The Express router
 * (server.ts) and the Fetch-API handler (web.ts) are thin adapters over it, so
 * every framework gets identical guards.
 *
 * The proprietary function bodies live ONLY on the server. A CDP client
 * attached to the browser sees the request and the result — never the
 * algorithm.
 */
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
  /**
   * Number of trusted reverse proxies in front of the app. `true` means 1.
   * The client IP is then the X-Forwarded-For entry that many hops from the
   * right — the leftmost entry is client-supplied and never trusted.
   * Default false (use the socket address).
   */
  trustProxy?: boolean | number;
}

export interface CoreResult {
  status: number;
  body: Record<string, unknown>;
}

/** Longest accepted nonce. The client sends 32 hex characters. */
export const MAX_NONCE_LENGTH = 128;
/** Session tokens issued per client address per minute. */
export const SESSIONS_PER_MIN = 30;
const MAX_TRUST_HOPS = 10;

/** Normalise the trustProxy option to a hop count (0 = do not trust). */
export function trustHops(value: boolean | number | undefined): number {
  if (value === true) return 1;
  if (typeof value !== "number" || !Number.isInteger(value) || value < 1) return 0;
  return Math.min(value, MAX_TRUST_HOPS);
}

/**
 * Client IP from X-Forwarded-For given `hops` trusted proxies: the entry
 * `hops` from the right. Falls back to `socketAddr` when not trusting proxies
 * or when the header is absent.
 */
export function forwardedIp(xff: string | undefined, hops: number, socketAddr: string): string {
  if (hops < 1 || !xff) return socketAddr;
  const parts = xff
    .split(",")
    .map((p) => p.trim())
    .filter(Boolean);
  if (parts.length === 0) return socketAddr;
  return parts[Math.max(parts.length - hops, 0)];
}

/**
 * Rate-limit key for an address: IPv6 clients are grouped by /56, so rotating
 * addresses inside one allocation buys no extra sessions.
 */
export function addressKey(ip: string): string {
  if (!ip.includes(":") || ip.includes(".")) return ip; // IPv4 or IPv4-mapped
  const [head, tail = ""] = ip.toLowerCase().split("::");
  const h = head ? head.split(":") : [];
  const t = tail ? tail.split(":") : [];
  const groups = [...h, ...Array(Math.max(8 - h.length - t.length, 0)).fill("0"), ...t]
    .slice(0, 8)
    .map((g) => g.padStart(4, "0"));
  if (groups.length < 4) return ip;
  return `${groups[0]}:${groups[1]}:${groups[2]}:${groups[3].slice(0, 2)}00::/56`;
}

export interface SecureFnCore {
  readonly sessionTtlMs: number;
  /** Issue a session token. Pass `limit: true` to apply the per-address limit. */
  issueSession(ip: string, limit?: boolean): CoreResult;
  invoke(input: { authorization: string; body: unknown; ip: string }): Promise<CoreResult>;
}

export function createSecureFnCore(opts: SecureFnOptions): SecureFnCore {
  if (!opts.secret) throw new Error("[secure-fn] secret is required");
  const sessionTtlMs = opts.sessionTtlMs ?? 10 * 60_000;
  const maxPerMin = opts.maxInvokesPerMin ?? 120;
  const nonceTtlMs = opts.nonceTtlMs ?? 2 * 60_000;

  const nonces = new NonceStore(nonceTtlMs);
  const invokeLimiter = new RateLimiter(maxPerMin, 60_000);
  const sessionLimiter = new RateLimiter(SESSIONS_PER_MIN, 60_000);

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

  return {
    sessionTtlMs,

    issueSession(ip, limit = false) {
      if (limit && !sessionLimiter.hit(addressKey(ip)).ok) {
        return { status: 429, body: { error: "rate limited" } };
      }
      const token = signToken(opts.secret, { sid: randomUUID(), exp: Date.now() + sessionTtlMs });
      return { status: 200, body: { token, ttlMs: sessionTtlMs } };
    },

    async invoke({ authorization, body, ip }) {
      // 1. Auth: verify the signed session token.
      const token = authorization.startsWith("Bearer ") ? authorization.slice(7) : "";
      const payload = verifyToken(opts.secret, token);
      if (!payload) return { status: 401, body: { error: "invalid session" } };

      const b = (body && typeof body === "object" ? body : {}) as {
        name?: unknown;
        args?: unknown;
        nonce?: unknown;
      };
      const name = typeof b.name === "string" ? b.name : "";
      const nonce = typeof b.nonce === "string" ? b.nonce : "";
      if (nonce === "" || nonce.length > MAX_NONCE_LENGTH) {
        return { status: 400, body: { error: "invalid nonce" } };
      }

      // 2. Anti-replay, scoped to the session so one session cannot burn or
      //    probe another session's nonces.
      if (!nonces.check(`${payload.sid}:${nonce}`)) return { status: 409, body: { error: "replay" } };

      // 3. Rate limit per session; a spike is a harvesting signal.
      const rl = invokeLimiter.hit(payload.sid);
      if (!rl.ok) {
        void reportAnomaly(name || "?", ip, "rate_exceeded");
        return { status: 429, body: { error: "rate limited" } };
      }

      // 4. Dispatch to the server-side implementation.
      const fn = Object.prototype.hasOwnProperty.call(opts.functions, name)
        ? opts.functions[name]
        : undefined;
      if (!fn) return { status: 404, body: { error: "unknown function" } };

      try {
        const result = await fn(b.args, { sid: payload.sid, ip, invokeCount: rl.count });
        return { status: 200, body: { result } };
      } catch (e) {
        // Never leak internals (stack/algorithm) to the client.
        console.error("[secure-fn] invoke error", name, (e as Error).message);
        return { status: 500, body: { error: "execution failed" } };
      }
    },
  };
}
