/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * Fetch-API adapter: `(Request) => Promise<Response>`.
 *
 * Works wherever a standard Request/Response handler runs on a Node.js
 * runtime (it uses node:crypto): Next.js App Router route handlers, Hono,
 * Fastify/`node:http` through a small bridge, serverless functions.
 *
 * It answers POST <anything>/session and POST <anything>/invoke, so mount it
 * on a catch-all route. Guards are identical to the Express router's.
 *
 * State (nonces, rate limits) is in memory, per process. On serverless
 * platforms each instance has its own counters, so limits are per instance —
 * see the README for what that does and does not protect.
 */
import { createSecureFnCore, forwardedIp, trustHops, type CoreResult, type SecureFnOptions } from "./core.js";

export type { InvokeContext, SecureFn, SecureFnOptions } from "./core.js";

/** Largest accepted request body, matching the Express router. */
export const MAX_BODY_BYTES = 32 * 1024;

export interface HandlerContext {
  /**
   * The connection's remote address, when the platform exposes it. With
   * `trustProxy` set, X-Forwarded-For takes precedence as configured.
   */
  ip?: string;
}

export type SecureFnHandler = (request: Request, ctx?: HandlerContext) => Promise<Response>;

function json(r: CoreResult, extra?: Record<string, string>): Response {
  return new Response(JSON.stringify(r.body), {
    status: r.status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...extra },
  });
}

/** Read at most `limit` bytes of the body; null if it is larger. */
async function readLimited(request: Request, limit: number): Promise<string | null> {
  const declared = Number(request.headers.get("content-length") ?? "0");
  if (Number.isFinite(declared) && declared > limit) return null;
  if (!request.body) return "";
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > limit) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString("utf8");
}

export function createSecureFnHandler(opts: SecureFnOptions): SecureFnHandler {
  const core = createSecureFnCore(opts);
  const hops = trustHops(opts.trustProxy);

  return async function handle(request, ctx = {}) {
    try {
      const path = new URL(request.url).pathname.replace(/\/+$/, "");
      const action = path.endsWith("/session") ? "session" : path.endsWith("/invoke") ? "invoke" : "";
      if (!action) return json({ status: 404, body: { error: "not found" } });
      if (request.method !== "POST") {
        return json({ status: 405, body: { error: "method not allowed" } }, { allow: "POST" });
      }

      const ip = forwardedIp(request.headers.get("x-forwarded-for") ?? undefined, hops, ctx.ip ?? "");
      if (action === "session") return json(core.issueSession(ip, true));

      const type = (request.headers.get("content-type") ?? "").toLowerCase();
      if (!type.startsWith("application/json")) {
        return json({ status: 415, body: { error: "unsupported media type" } });
      }
      const raw = await readLimited(request, MAX_BODY_BYTES);
      if (raw === null) return json({ status: 413, body: { error: "payload too large" } });
      let body: unknown;
      try {
        body = JSON.parse(raw);
      } catch {
        return json({ status: 400, body: { error: "invalid json" } });
      }

      return json(await core.invoke({ authorization: request.headers.get("authorization") ?? "", body, ip }));
    } catch {
      // Never leak internals to the client.
      return json({ status: 500, body: { error: "internal" } });
    }
  };
}
