/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * @antirea/honeypot — Express/connect middleware implementing server-side
 * deception for protected static assets, with a behavioural detection engine
 * that does NOT trust client headers and optional live config from the admin
 * panel.
 *
 *   import express from "express";
 *   import { honeypot } from "@antirea/honeypot";
 *   const app = express();
 *   app.use(honeypot({
 *     siteId: "my-site",
 *     protect: [/^\/assets\/app\.[a-f0-9]+\.js$/],
 *     mode: "shadow",                       // tune in shadow, then "live"
 *     reportUrl: "http://collector:8080/api/events",
 *     // optional: let the admin panel control mode/threshold/lists live
 *     config: { url: "http://collector:8080/api/site-config", siteKey: "..." },
 *   }));
 *   app.use(express.static("public"));
 */
import type { IncomingMessage, ServerResponse } from "node:http";
import { Allowlist, type AllowlistOptions } from "./allowlist.js";
import { BehaviorTracker, fingerprintHeaders, type BehaviorOptions } from "./behavior.js";
import { RemoteConfigClient } from "./config.js";
import { buildDecoy, buildEmptySourceMap } from "./decoy.js";
import { scoreRequest } from "./scoring.js";

export { scoreRequest } from "./scoring.js";
export { buildDecoy } from "./decoy.js";
export { Allowlist } from "./allowlist.js";
export { BehaviorTracker, fingerprintHeaders } from "./behavior.js";
export { RemoteConfigClient } from "./config.js";
export type { RemoteConfig, RemoteConfigOptions } from "./config.js";
export type { BehaviorOptions, BehaviorVerdict } from "./behavior.js";

export interface HoneypotConfigSource {
  /** Collector site-config URL, e.g. "https://collector/api/site-config". */
  url: string;
  /** Shared site key (X-Antirea-Site-Key). Must match the panel's stored key. */
  siteKey: string;
  /** Poll interval ms. Default 30s. */
  intervalMs?: number;
}

export interface HoneypotOptions {
  siteId: string;
  protect: Array<string | RegExp>;
  mode?: "shadow" | "live";
  threshold?: number;
  reportUrl?: string;
  allowlist?: AllowlistOptions;
  /** Behavioural engine tuning. */
  behavior?: BehaviorOptions;
  /** Static IPs to always decoy (also settable live from the panel). */
  blockIps?: string[];
  /** Live config from the admin panel. */
  config?: HoneypotConfigSource;
  onDecoyServed?: (info: { canary: string; path: string; ip: string }) => void;
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

export interface HoneypotMiddleware {
  (req: IncomingMessage, res: ServerResponse, next: (err?: unknown) => void): void;
  /** Behavioural tracker, for exposing top offenders to an admin view. */
  tracker: BehaviorTracker;
  /** Stop background config polling. */
  stop(): void;
}

type Req = IncomingMessage & { path?: string; originalUrl?: string };
type Next = (err?: unknown) => void;

const ASSET_RE = /\.(js|mjs|map|css|png|jpe?g|gif|svg|webp|woff2?|ttf|otf)(\?|$)/i;

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

function isNavigation(h: Req["headers"]): boolean {
  const dest = h["sec-fetch-dest"];
  if (dest === "document") return true;
  const accept = Array.isArray(h.accept) ? h.accept.join(",") : h.accept ?? "";
  return accept.includes("text/html");
}

export function honeypot(opts: HoneypotOptions): HoneypotMiddleware {
  const staticMode = opts.mode ?? "shadow";
  const staticThreshold = opts.threshold ?? 0.7;
  const allow = new Allowlist(opts.allowlist);
  const tracker = new BehaviorTracker(opts.behavior);
  const staticBlock = new Set(opts.blockIps ?? []);

  const remote = opts.config
    ? new RemoteConfigClient({
        url: opts.config.url,
        siteId: opts.siteId,
        siteKey: opts.config.siteKey,
        intervalMs: opts.config.intervalMs,
      })
    : null;
  remote?.start();

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
          signals: ev.reasons.map((name) => ({ type: "automation", name: `honeypot:${name}`, confidence: ev.score })),
          honeypot: { action: ev.action, score: ev.score },
        }),
      });
    } catch {
      /* reporting must never break asset serving */
    }
  }

  const mw = function honeypotMiddleware(req: Req, res: ServerResponse, next: Next): void {
    const path = reqPath(req);
    if (!matches(path, opts.protect)) return next();

    const cfg = remote?.get() ?? {};
    if (cfg.enabled === false) return next(); // master switch from the panel

    const ua = (req.headers["user-agent"] as string) ?? "";
    const ip = clientIp(req);
    const mode = cfg.mode ?? staticMode;
    const threshold = typeof cfg.threshold === "number" ? cfg.threshold : staticThreshold;

    void (async () => {
      // Live + static allow/block lists.
      const allowIps = new Set(cfg.allowIps ?? []);
      const blockIps = new Set([...staticBlock, ...(cfg.blockIps ?? [])]);

      if (allowIps.has(ip) || (await allow.isAllowed(ua, ip))) return next();

      const isAsset = ASSET_RE.test(path);
      const nav = isNavigation(req.headers);
      const behavior = tracker.record({
        ip,
        path,
        fingerprint: fingerprintHeaders(req.headers),
        isAsset,
        isNavigation: nav,
      });

      const req_ = scoreRequest({ userAgent: ua, headers: req.headers, path });
      const reasons = [...new Set([...req_.reasons, ...behavior.reasons])];

      const blocked = blockIps.has(ip);
      // Server-truth behavioural score and header score are combined; the
      // client header cannot lower the behavioural score.
      const score = blocked ? 1 : Math.min(1, Math.max(req_.score, behavior.score));
      const flagged = blocked || score >= threshold;

      const base = { siteId: opts.siteId, mode, path, score, reasons: blocked ? ["blocklist", ...reasons] : reasons, ua, ip, ts: Date.now() };

      if (!flagged) {
        void report({ ...base, action: "pass" });
        return next();
      }
      if (mode === "shadow") {
        void report({ ...base, action: "would_decoy" });
        return next();
      }

      // Live mode: serve a decoy.
      void report({ ...base, action: "decoy" });
      res.setHeader("Cache-Control", "no-store");
      res.setHeader("X-Content-Type-Options", "nosniff");
      if (/\.map(\?|$)/i.test(path)) {
        res.statusCode = 200;
        res.setHeader("Content-Type", "application/json");
        res.end(buildEmptySourceMap(path.split("/").pop() ?? "app.js"));
        return;
      }
      const decoy = buildDecoy(path);
      opts.onDecoyServed?.({ canary: decoy.canary, path, ip });
      res.statusCode = 200;
      res.setHeader("Content-Type", "application/javascript; charset=utf-8");
      res.end(decoy.body);
    })().catch(() => next());
  } as HoneypotMiddleware;

  mw.tracker = tracker;
  mw.stop = () => remote?.stop();
  return mw;
}
