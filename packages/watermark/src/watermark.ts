/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * Per-viewer watermarking: a pure helper plus an Express middleware that
 * embeds a unique canary in text/code responses for protected routes and
 * records which viewer received it.
 */
import type { IncomingMessage, ServerResponse } from "node:http";
import { issueCanary, MemoryCanaryStore, type CanaryStore } from "./canary.js";
import { embed, type WatermarkMode } from "./embed.js";

/** Watermark a string for a viewer, recording the canary. Returns {body, token}. */
export function watermarkText(
  store: CanaryStore,
  text: string,
  viewer: string,
  opts: { mode?: WatermarkMode; path?: string } = {},
): { body: string; token: string } {
  const token = issueCanary(store, viewer, opts.path);
  return { body: embed(text, token, opts.mode ?? "zerowidth"), token };
}

export interface WatermarkOptions {
  /** Paths whose text responses get a per-viewer watermark. */
  protect: Array<string | RegExp>;
  /** Canary store (defaults to in-memory). */
  store?: CanaryStore;
  /** "comment" or "zerowidth" (default). */
  mode?: WatermarkMode;
  /** Identify the viewer from the request (session id / user id / hashed IP). */
  viewer?: (req: IncomingMessage) => string;
  /** Called after a watermark is embedded (e.g. to persist the mapping). */
  onWatermark?: (info: { token: string; viewer: string; path: string }) => void;
}

type Req = IncomingMessage & { path?: string; originalUrl?: string };

function reqPath(req: Req): string {
  return req.path ?? (req.originalUrl ?? req.url ?? "").split("?")[0];
}
function matches(path: string, rules: Array<string | RegExp>): boolean {
  return rules.some((r) => (typeof r === "string" ? r === path : r.test(path)));
}

/**
 * Express middleware. Wraps `res.send` so that text/JS responses on protected
 * paths are watermarked per viewer. Binary responses pass through untouched.
 */
export function watermark(opts: WatermarkOptions) {
  const store = opts.store ?? new MemoryCanaryStore();
  const viewerOf = opts.viewer ?? ((req: Req) => req.socket?.remoteAddress ?? "anon");

  return function watermarkMiddleware(
    req: Req,
    res: ServerResponse & { send?: unknown },
    next: () => void,
  ): void {
    const path = reqPath(req);
    if (!matches(path, opts.protect)) return next();

    const r = res as ServerResponse & { send: (body: unknown) => unknown };
    const originalSend = r.send?.bind(r);
    if (typeof originalSend !== "function") return next(); // not Express

    r.send = (body: unknown) => {
      if (typeof body === "string") {
        const viewer = viewerOf(req);
        const { body: out, token } = watermarkText(store, body, viewer, { mode: opts.mode, path });
        opts.onWatermark?.({ token, viewer, path });
        return originalSend(out);
      }
      return originalSend(body);
    };
    next();
  };
}
