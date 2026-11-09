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
import { isIP } from "node:net";
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
 * `hops` from the right. Falls back to `socketAddr` when not trusting proxies,
 * when the header is absent, or when it has FEWER entries than trusted hops —
 * such a request did not pass through the whole proxy chain, so every entry in
 * it may be client-supplied.
 */
export function forwardedIp(xff: string | undefined, hops: number, socketAddr: string): string {
  if (hops < 1 || !xff) return socketAddr;
  const parts = xff
    .split(",")
    .map((p) => p.trim())
    .filter(Boolean);
  if (parts.length < hops) return socketAddr;
  return parts[parts.length - hops];
}

/** Strip a port and IPv6 brackets: "1.2.3.4:5678", "[2001:db8::1]:443". */
function bareAddress(raw: string): string {
  const s = raw.trim();
  const bracket = /^\[([^\]]+)\](?::\d+)?$/.exec(s);
  if (bracket) return bracket[1];
  const v4port = /^(\d{1,3}(?:\.\d{1,3}){3}):\d+$/.exec(s);
  return v4port ? v4port[1] : s;
}

/**
 * Rate-limit key for an address: IPv6 clients are grouped by /56, so rotating
 * addresses inside one allocation buys no extra sessions.
 */
export function addressKey(ip: string): string {
  const addr = bareAddress(ip).toLowerCase();
  const family = isIP(addr);
  // Not an address (should not happen for a socket or trusted-proxy value):
  // keep it as its own bounded key rather than guessing a prefix.
  if (family === 0) return addr.slice(0, 64);
  if (family === 4 || addr.includes(".")) return addr; // IPv4, or dotted IPv4-mapped
  const [head, tail = ""] = addr.split("::");
  const h = head ? head.split(":") : [];
  const t = tail ? tail.split(":") : [];
  const groups = [...h, ...Array(8 - h.length - t.length).fill("0"), ...t].map((g) => g.padStart(4, "0"));
  const prefix = groups.slice(0, 4).join(":");
  // Prefixes that embed a full IPv4 address or are special (loopback, hex-form
  // IPv4-mapped ::ffff:0:0/96, NAT64 64:ff9b::/96): grouping them by /56 would
  // put unrelated clients in one bucket, so key on the whole address.
  if (prefix === "0000:0000:0000:0000" || prefix === "0064:ff9b:0000:0000") return groups.join(":");
  return `${groups[0]}:${groups[1]}:${groups[2]}:${groups[3].slice(0, 2)}00::/56`;
}

/** True only for the `application/json` media type (parameters allowed). */
export function isJsonContentType(value: string | null | undefined): boolean {
  return (value ?? "").split(";")[0].trim().toLowerCase() === "application/json";
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
  let warnedNoAddress = false;

  async function reportAnomaly(rawName: string, ip: string, detail: string): Promise<void> {
    // The name comes from the client: quote and bound it so it cannot forge
    // log lines or bloat reports.
    const name = JSON.stringify(rawName.slice(0, 64)).slice(1, -1);
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
      if (limit) {
        if (ip === "") {
          // Without a client address a per-address limit would be ONE bucket
          // for the whole site: 30 requests from anyone would lock everyone
          // out. Skip it and tell the operator how to enable it.
          if (!warnedNoAddress) {
            warnedNoAddress = true;
            console.warn(
              "[secure-fn] no client address available: the per-address session limit is OFF. " +
                "Set trustProxy to your proxy count, or pass { ip } to the handler.",
            );
          }
        } else if (!sessionLimiter.hit(addressKey(ip)).ok) {
          return { status: 429, body: { error: "rate limited" } };
        }
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

      // 2. Rate limit per session; a spike is a harvesting signal. This runs
      //    BEFORE the nonce is stored, so a throttled session cannot grow the
      //    nonce table. The anomaly is reported once per window, not per
      //    rejected request.
      const rl = invokeLimiter.hit(payload.sid);
      if (!rl.ok) {
        if (rl.count === maxPerMin + 1) void reportAnomaly(name || "?", ip, "rate_exceeded");
        return { status: 429, body: { error: "rate limited" } };
      }

      // 3. Anti-replay, scoped to the session so one session cannot burn or
      //    probe another session's nonces.
      if (!nonces.check(`${payload.sid}:${nonce}`)) return { status: 409, body: { error: "replay" } };

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
