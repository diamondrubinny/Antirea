/**
 * @antirea/honeypot — Express/connect middleware implementing server-side
 * deception for protected static assets.
 *
 * Mount it BEFORE your static file handler for the paths you want to protect:
 *
 *   import express from "express";
 *   import { honeypot } from "@antirea/honeypot";
 *   const app = express();
 *   app.use(honeypot({
 *     siteId: "my-site",
 *     protect: [/^\/assets\/app\.[a-f0-9]+\.js$/],
 *     mode: "shadow",                       // start in shadow; go "live" after tuning
 *     reportUrl: "http://collector:8080/api/events",
 *   }));
 *   app.use(express.static("public"));
 *
 * Modes:
 *   - "shadow" (default): never alters responses; only reports who WOULD be
 *     honeypotted. Use this to tune the threshold on real traffic.
 *   - "live": serves a decoy to requests scoring >= threshold (allowlist aside).
 */
import type { IncomingMessage, ServerResponse } from "node:http";
import { Allowlist, type AllowlistOptions } from "./allowlist.js";
import { buildDecoy, buildEmptySourceMap } from "./decoy.js";
import { scoreRequest } from "./scoring.js";

export { scoreRequest } from "./scoring.js";
export { buildDecoy } from "./decoy.js";
export { Allowlist } from "./allowlist.js";

export interface HoneypotOptions {
  /** Identifies this site in the dashboard. */
  siteId: string;
  /** Paths to protect. Strings (exact) or RegExp. */
  protect: Array<string | RegExp>;
  /** "shadow" (report only) or "live" (serve decoys). Default "shadow". */
  mode?: "shadow" | "live";
  /** Score at/above which a request is treated as analysis. Default 0.7. */
  threshold?: number;
  /** Collector events endpoint for honeypot hits. If unset, no network report. */
  reportUrl?: string;
  /** Allowlist configuration (good bots, verified DNS, static IPs). */
  allowlist?: AllowlistOptions;
  /** Hook to persist canary tokens (for later leak-matching). */
  onDecoyServed?: (info: { canary: string; path: string; ip: string }) => void;
  /** Local logger. */
  onEvent?: (info: HoneypotEvent) => void;
}

export interface HoneypotEvent {
  siteId: string;
  mode: "shadow" | "live";
  action: "pass" | "would_decoy" | "decoy";
  path: string;
  score: number;
  reasons: string[];
  ua: string;
  ip: string;
  ts: number;
}

type Req = IncomingMessage & { path?: string; originalUrl?: string; ip?: string };
type Next = (err?: unknown) => void;

function clientIp(req: Req): string {
  const xff = req.headers["x-forwarded-for"];
  if (typeof xff === "string" && xff.length > 0) return xff.split(",")[0].trim();
  return req.socket?.remoteAddress ?? "";
}

function reqPath(req: Req): string {
  return req.path ?? (req.originalUrl ?? req.url ?? "").split("?")[0];
}

function matches(path: string, rules: Array<string | RegExp>): boolean {
  return rules.some((r) => (typeof r === "string" ? r === path : r.test(path)));
}

export function honeypot(opts: HoneypotOptions) {
  const mode = opts.mode ?? "shadow";
  const threshold = opts.threshold ?? 0.7;
  const allow = new Allowlist(opts.allowlist);

  async function report(ev: HoneypotEvent): Promise<void> {
    opts.onEvent?.(ev);
    if (!opts.reportUrl) return;
    try {
      await fetch(opts.reportUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          v: 1,
          ts: ev.ts,
          sessionId: "server",
          siteId: ev.siteId,
          source: "honeypot",
          path: ev.path,
          ua: ev.ua,
          lang: "",
          screen: "",
          tz: "",
          signals: ev.reasons.map((name) => ({
            type: "automation",
            name: `honeypot:${name}`,
            confidence: ev.score,
          })),
          honeypot: { action: ev.action, score: ev.score },
        }),
      });
    } catch {
      /* reporting must never break asset serving */
    }
  }

  return function honeypotMiddleware(req: Req, res: ServerResponse, next: Next): void {
    const path = reqPath(req);
    if (!matches(path, opts.protect)) return next();

    const ua = (req.headers["user-agent"] as string) ?? "";
    const ip = clientIp(req);

    void (async () => {
      // Never touch verified-legitimate clients (SEO + real users).
      if (await allow.isAllowed(ua, ip)) return next();

      const { score, reasons } = scoreRequest({ userAgent: ua, headers: req.headers, path });
      const flagged = score >= threshold;

      const base = { siteId: opts.siteId, mode, path, score, reasons, ua, ip, ts: Date.now() };

      if (!flagged) {
        void report({ ...base, action: "pass" });
        return next();
      }

      if (mode === "shadow") {
        // Report what we WOULD do, but serve the real asset.
        void report({ ...base, action: "would_decoy" });
        return next();
      }

      // Live mode: serve a decoy instead of the real asset.
      void report({ ...base, action: "decoy" });
      if (/\.map(\?|$)/i.test(path)) {
        const body = buildEmptySourceMap(path.split("/").pop() ?? "app.js");
        res.statusCode = 200;
        res.setHeader("Content-Type", "application/json");
        res.setHeader("Cache-Control", "no-store");
        res.end(body);
        return;
      }
      const decoy = buildDecoy(path);
      opts.onDecoyServed?.({ canary: decoy.canary, path, ip });
      res.statusCode = 200;
      res.setHeader("Content-Type", "application/javascript; charset=utf-8");
      res.setHeader("Cache-Control", "no-store");
      res.setHeader("X-Content-Type-Options", "nosniff");
      res.end(decoy.body);
    })().catch(() => next());
  };
}
