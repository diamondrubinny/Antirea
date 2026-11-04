/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * antirea collector — ingests telemetry, enriches, stores, and serves the
 * admin dashboard.
 *
 * Security:
 *   - Payload size cap, rate limiting, strict validation.
 *   - CORS configurable via ALLOWED_ORIGINS.
 *   - Dashboard + admin APIs behind a bearer token (ADMIN_TOKEN).
 *   - Security headers on all responses.
 */
import express, { type NextFunction, type Request, type Response } from "express";
import rateLimit from "express-rate-limit";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import {
  AnthropicAdvisor,
  clampThreshold,
  recommend,
  type KnowledgeStore,
  type KnowledgeSignature,
  type Proposal,
} from "@antirea/adaptive";
import { Store } from "./db.js";
import { countryFor, extractIp, hashIp, initGeo } from "./geo.js";
import { validateEvent } from "./validate.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

const PORT = Number(process.env.PORT ?? 8080);
const DB_FILE = process.env.DB_FILE ?? "./antirea.db";
const IP_SALT = process.env.IP_SALT ?? "";
const ADMIN_TOKEN = process.env.ADMIN_TOKEN ?? "";
const TRUST_PROXY = process.env.TRUST_PROXY === "true";
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS ?? "*").split(",").map((s) => s.trim());
const RETENTION_DAYS = Number(process.env.RETENTION_DAYS ?? 90);

// Adaptive AI layer. OFF by default. Auto-apply OFF by default (suggest-only).
const AI_ENABLED = process.env.AI_ENABLED === "true";
const AI_AUTO_APPLY = process.env.AI_AUTO_APPLY === "true";
const AI_MODEL = process.env.AI_MODEL ?? "claude-opus-5-5";
const AI_ANALYZE_INTERVAL_MIN = Number(process.env.AI_ANALYZE_INTERVAL_MIN ?? 0);

if (!IP_SALT) {
  // Fail fast: without a salt, IP hashing is weak. Required in all envs.
  console.error("[antirea] FATAL: IP_SALT env var is required (random, secret).");
  process.exit(1);
}
if (!ADMIN_TOKEN) {
  console.error("[antirea] FATAL: ADMIN_TOKEN env var is required to protect the dashboard.");
  process.exit(1);
}

const store = new Store(DB_FILE);
await initGeo();

const app = express();
if (TRUST_PROXY) app.set("trust proxy", true);
app.disable("x-powered-by");

// --- Security headers (lightweight; a CDN/proxy may add more) ---
app.use((_req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'",
  );
  next();
});

// --- CORS for the ingest endpoint ---
function corsFor(req: Request, res: Response): boolean {
  const origin = req.headers.origin;
  if (ALLOWED_ORIGINS.includes("*")) {
    res.setHeader("Access-Control-Allow-Origin", "*");
  } else if (origin && ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
  } else if (origin) {
    return false;
  }
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("Access-Control-Max-Age", "600");
  return true;
}

const ingestLimiter = rateLimit({
  windowMs: 60_000,
  limit: 120, // per IP per minute
  standardHeaders: true,
  legacyHeaders: false,
});

// --- Ingest endpoint ---
app.options("/api/events", (req, res) => {
  corsFor(req, res);
  res.status(204).end();
});

app.post(
  "/api/events",
  ingestLimiter,
  express.json({ limit: "16kb", type: ["application/json", "text/plain"] }),
  (req: Request, res: Response) => {
    if (!corsFor(req, res)) return res.status(403).json({ error: "origin not allowed" });

    const result = validateEvent(req.body);
    if (!result.ok) return res.status(400).json({ error: result.error });
    const ev = result.value;

    const ip = extractIp(req.headers, req.socket.remoteAddress, TRUST_PROXY);
    const country = countryFor(ip);
    const ipHash = hashIp(ip, IP_SALT);

    try {
      store.insertEvent(
        {
          ts: ev.ts,
          received_ts: Date.now(),
          site_id: ev.siteId,
          session_id: ev.sessionId,
          source: ev.source ?? "client",
          path: ev.path,
          ua: ev.ua,
          lang: ev.lang,
          screen: ev.screen,
          tz: ev.tz,
          country,
          ip_hash: ipHash,
          signals_json: JSON.stringify(ev.signals),
          honeypot_action: ev.honeypot?.action ?? null,
          honeypot_score: ev.honeypot?.score ?? null,
        },
        ev.signals,
      );
    } catch (e) {
      console.error("[antirea] insert failed", (e as Error).message);
      return res.status(500).json({ error: "store failed" });
    }
    // 204: no body, nothing for an attacker to learn.
    return res.status(204).end();
  },
);

// --- Admin auth ---
function requireAdmin(req: Request, res: Response, next: NextFunction): void {
  const auth = req.headers.authorization ?? "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  // Constant-time-ish compare.
  if (token.length !== ADMIN_TOKEN.length || token !== ADMIN_TOKEN) {
    res.status(401).json({ error: "unauthorized" });
    return;
  }
  next();
}

function sinceFromQuery(req: Request): number {
  const days = Math.min(365, Math.max(1, Number(req.query.days ?? 7)));
  return Date.now() - days * 864e5;
}

// --- Dashboard data APIs ---
app.get("/api/stats", requireAdmin, (req: Request, res: Response) => {
  const since = sinceFromQuery(req);
  const siteId = typeof req.query.site === "string" && req.query.site ? req.query.site : undefined;
  const days = Math.min(365, Math.max(1, Number(req.query.days ?? 7)));
  const bucketMs = days <= 2 ? 36e5 : 864e5; // hourly for <=2d, else daily
  res.json({
    totals: store.totals(since, siteId),
    byCountry: store.byCountry(since, siteId),
    bySignal: store.bySignal(since, siteId),
    honeypot: store.honeypotBreakdown(since, siteId),
    timeline: store.timeline(since, bucketMs, siteId),
    bucketMs,
  });
});

app.get("/api/offenders", requireAdmin, (req: Request, res: Response) => {
  const since = sinceFromQuery(req);
  const siteId = typeof req.query.site === "string" && req.query.site ? req.query.site : undefined;
  res.json({ offenders: store.topOffenders(since, siteId, 50) });
});

// --- Site configuration (admin reads/writes; honeypot reads via site key) ---
interface SiteConfig {
  enabled: boolean;
  mode: "shadow" | "live";
  threshold: number;
  allowIps: string[];
  blockIps: string[];
  /** Shared secret the honeypot presents to read this config. */
  siteKey: string;
}

function sanitizeConfig(input: unknown, prev: SiteConfig | null): SiteConfig {
  const o = (input ?? {}) as Record<string, unknown>;
  const arr = (v: unknown): string[] =>
    Array.isArray(v) ? v.filter((x) => typeof x === "string").slice(0, 1000) : [];
  const num = typeof o.threshold === "number" ? Math.min(1, Math.max(0, o.threshold)) : prev?.threshold ?? 0.7;
  return {
    enabled: typeof o.enabled === "boolean" ? o.enabled : prev?.enabled ?? true,
    mode: o.mode === "live" ? "live" : o.mode === "shadow" ? "shadow" : prev?.mode ?? "shadow",
    threshold: num,
    allowIps: o.allowIps !== undefined ? arr(o.allowIps) : prev?.allowIps ?? [],
    blockIps: o.blockIps !== undefined ? arr(o.blockIps) : prev?.blockIps ?? [],
    siteKey: typeof o.siteKey === "string" && o.siteKey ? o.siteKey : prev?.siteKey ?? "",
  };
}

app.get("/api/config", requireAdmin, (req: Request, res: Response) => {
  const siteId = typeof req.query.site === "string" ? req.query.site : "";
  if (!siteId) return res.status(400).json({ error: "site required" });
  const cfg = (store.getConfig(siteId) as SiteConfig | null) ?? sanitizeConfig({}, null);
  return res.json({ config: cfg });
});

app.put("/api/config", requireAdmin, express.json({ limit: "32kb" }), (req: Request, res: Response) => {
  const siteId = typeof req.query.site === "string" ? req.query.site : "";
  if (!siteId) return res.status(400).json({ error: "site required" });
  const prev = store.getConfig(siteId) as SiteConfig | null;
  const next = sanitizeConfig(req.body, prev);
  store.setConfig(siteId, next as unknown as Record<string, unknown>);
  return res.json({ config: next });
});

// Honeypot pulls live config here. Authenticated by the per-site key, so an
// attacker cannot read or change rules. Never returns the siteKey itself.
app.get("/api/site-config", (req: Request, res: Response) => {
  const siteId = typeof req.query.site === "string" ? req.query.site : "";
  const key = (req.headers["x-antirea-site-key"] as string) ?? "";
  const cfg = siteId ? (store.getConfig(siteId) as SiteConfig | null) : null;
  if (!cfg || !cfg.siteKey || key.length !== cfg.siteKey.length || key !== cfg.siteKey) {
    return res.status(403).json({ error: "forbidden" });
  }
  return res.json({ enabled: cfg.enabled, mode: cfg.mode, threshold: cfg.threshold, allowIps: cfg.allowIps, blockIps: cfg.blockIps });
});

// --- Adaptive defense (learns + proposes bounded changes) ---

/** SQLite-backed knowledge store scoped to one site. */
class SiteKnowledge implements KnowledgeStore {
  constructor(private readonly siteId: string) {}
  get(pattern: string): KnowledgeSignature | null {
    return store.knowledgeGet(this.siteId, pattern);
  }
  put(sig: KnowledgeSignature): void {
    store.knowledgePut(this.siteId, sig);
  }
  list(limit: number): KnowledgeSignature[] {
    return store.knowledgeList(this.siteId, limit);
  }
}

/** Apply a proposal to the live site config. Bounded + clamped. */
function applyProposal(siteId: string, p: { type: string; proposed?: string | number }): void {
  const prev = (store.getConfig(siteId) as SiteConfig | null) ?? sanitizeConfig({}, null);
  const next: SiteConfig = { ...prev };
  if (p.type === "threshold" && p.proposed !== undefined) {
    next.threshold = clampThreshold(Number(p.proposed));
  } else if (p.type === "mode" && (p.proposed === "shadow" || p.proposed === "live")) {
    next.mode = p.proposed;
  } else {
    return; // "watch" changes nothing live
  }
  store.setConfig(siteId, next as unknown as Record<string, unknown>);
}

/** Conservative auto-apply gate: only small threshold steps, never mode. */
function canAutoApply(p: Proposal, currentThreshold: number): boolean {
  if (p.type !== "threshold" || p.proposed === undefined) return false;
  const next = clampThreshold(Number(p.proposed));
  return Math.abs(next - currentThreshold) <= 0.15;
}

async function runAnalysis(siteId: string): Promise<{ analysis: string; count: number }> {
  const since = Date.now() - 24 * 36e5;
  const rows = store.recentRows(since, siteId, 5000);
  if (rows.length === 0) return { analysis: "No recent events.", count: 0 };
  const cfg = store.getConfig(siteId) as SiteConfig | null;
  const ctx = {
    siteId,
    currentMode: (cfg?.mode ?? "shadow") as "shadow" | "live",
    currentThreshold: typeof cfg?.threshold === "number" ? cfg.threshold : 0.7,
  };
  const advisor = AI_ENABLED ? new AnthropicAdvisor({ model: AI_MODEL }) : undefined;
  const { analysis, proposals } = await recommend({
    rows,
    windowStart: since,
    windowEnd: Date.now(),
    ctx,
    knowledge: new SiteKnowledge(siteId),
    advisor,
  });
  for (const p of proposals) {
    let status = p.status;
    if (AI_AUTO_APPLY && canAutoApply(p, ctx.currentThreshold)) {
      applyProposal(siteId, p);
      status = "applied";
    }
    store.insertProposal({ ...p, status });
  }
  return { analysis, count: proposals.length };
}

app.post("/api/analyze", requireAdmin, (req: Request, res: Response) => {
  const siteId = typeof req.query.site === "string" ? req.query.site : "";
  if (!siteId) return res.status(400).json({ error: "site required" });
  void runAnalysis(siteId)
    .then((r) => res.json(r))
    .catch((e) => res.status(500).json({ error: (e as Error).message }));
  return undefined;
});

app.get("/api/proposals", requireAdmin, (req: Request, res: Response) => {
  const siteId = typeof req.query.site === "string" && req.query.site ? req.query.site : undefined;
  const status = typeof req.query.status === "string" ? req.query.status : undefined;
  res.json({ proposals: store.listProposals(siteId, status, 100) });
});

app.get("/api/knowledge", requireAdmin, (req: Request, res: Response) => {
  const siteId = typeof req.query.site === "string" ? req.query.site : "";
  if (!siteId) return res.status(400).json({ error: "site required" });
  return res.json({ knowledge: store.knowledgeList(siteId, 50) });
});

app.post("/api/proposals/approve", requireAdmin, express.json({ limit: "4kb" }), (req: Request, res: Response) => {
  const id = (req.body as { id?: string })?.id ?? "";
  const p = store.getProposal(id);
  if (!p) return res.status(404).json({ error: "not found" });
  applyProposal(String(p.site_id), { type: String(p.type), proposed: p.proposed_val as string });
  store.setProposalStatus(id, "applied");
  return res.json({ ok: true });
});

app.post("/api/proposals/reject", requireAdmin, express.json({ limit: "4kb" }), (req: Request, res: Response) => {
  const id = (req.body as { id?: string })?.id ?? "";
  if (!store.getProposal(id)) return res.status(404).json({ error: "not found" });
  store.setProposalStatus(id, "rejected");
  return res.json({ ok: true });
});

app.get("/api/events", requireAdmin, (req: Request, res: Response) => {
  const since = sinceFromQuery(req);
  const siteId = typeof req.query.site === "string" && req.query.site ? req.query.site : undefined;
  const rows = store.recent(since, siteId, 200).map((r) => ({
    ts: r.received_ts,
    siteId: r.site_id,
    source: r.source,
    country: r.country,
    path: r.path,
    ua: r.ua,
    honeypot: r.honeypot_action,
    score: r.honeypot_score,
    signals: JSON.parse(r.signals_json) as unknown,
  }));
  res.json({ events: rows });
});

// --- Static dashboard (also behind admin token at the API layer) ---
app.use("/", express.static(join(__dirname, "..", "public")));

// --- Retention job: prune daily ---
function prune(): void {
  try {
    const removed = store.pruneOlderThan(Date.now() - RETENTION_DAYS * 864e5);
    if (removed > 0) console.log(`[antirea] pruned ${removed} events older than ${RETENTION_DAYS}d`);
  } catch (e) {
    console.error("[antirea] prune failed", (e as Error).message);
  }
}
prune();
setInterval(prune, 24 * 36e5);

// Scheduled adaptive analysis (heuristics always; AI only when AI_ENABLED).
if (AI_ANALYZE_INTERVAL_MIN > 0) {
  const analyzeAll = (): void => {
    const sites = store.knownSites(Date.now() - 24 * 36e5);
    for (const siteId of sites) {
      void runAnalysis(siteId).catch((e) => console.error("[antirea] analysis failed", siteId, (e as Error).message));
    }
  };
  setInterval(analyzeAll, AI_ANALYZE_INTERVAL_MIN * 60_000);
  console.log(`[antirea] adaptive analysis every ${AI_ANALYZE_INTERVAL_MIN}min (AI ${AI_ENABLED ? "on" : "off"}, auto-apply ${AI_AUTO_APPLY ? "on" : "off"})`);
}

const server = app.listen(PORT, () => {
  console.log(`[antirea] collector listening on :${PORT} (retention ${RETENTION_DAYS}d)`);
});

function shutdown(): void {
  server.close(() => {
    store.close();
    process.exit(0);
  });
}
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
