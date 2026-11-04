/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * Strict server-side validation of inbound telemetry.
 * Never trust the client. Bound every field; reject anything malformed.
 */
export interface IncomingSignal {
  type: string;
  name: string;
  confidence: number;
}

export interface IncomingEvent {
  v: 1;
  ts: number;
  sessionId: string;
  siteId: string;
  source?: string;
  signals: IncomingSignal[];
  path: string;
  ua: string;
  lang: string;
  screen: string;
  tz: string;
  honeypot?: { action?: string; score?: number };
}

const MAX_STR = 512;
const MAX_UA = 1024;
const MAX_SIGNALS = 50;
const ALLOWED_SIGNAL_TYPES = new Set(["devtools", "automation", "integrity", "console"]);
const ALLOWED_SOURCES = new Set(["client", "honeypot", "server"]);

function str(v: unknown, max = MAX_STR): string | null {
  if (typeof v !== "string") return null;
  if (v.length > max) return v.slice(0, max);
  return v;
}

function num(v: unknown): number | null {
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}

export function validateEvent(input: unknown): { ok: true; value: IncomingEvent } | { ok: false; error: string } {
  if (typeof input !== "object" || input === null) return { ok: false, error: "not an object" };
  const o = input as Record<string, unknown>;

  if (o.v !== 1) return { ok: false, error: "bad version" };

  const siteId = str(o.siteId, 128);
  if (!siteId) return { ok: false, error: "siteId required" };

  const sessionId = str(o.sessionId, 64) ?? "";
  const path = str(o.path, 1024) ?? "";
  const ua = str(o.ua, MAX_UA) ?? "";
  const lang = str(o.lang, 64) ?? "";
  const screen = str(o.screen, 32) ?? "";
  const tz = str(o.tz, 64) ?? "";

  let ts = num(o.ts) ?? Date.now();
  // Reject absurd timestamps; clamp to a sane window.
  const now = Date.now();
  if (ts < now - 7 * 864e5 || ts > now + 864e5) ts = now;

  const source = str(o.source, 16) ?? "client";
  const safeSource = ALLOWED_SOURCES.has(source) ? source : "client";

  if (!Array.isArray(o.signals)) return { ok: false, error: "signals must be array" };
  const rawSignals = o.signals.slice(0, MAX_SIGNALS);
  const signals: IncomingSignal[] = [];
  for (const rs of rawSignals) {
    if (typeof rs !== "object" || rs === null) continue;
    const s = rs as Record<string, unknown>;
    const type = str(s.type, 32) ?? "";
    const name = str(s.name, 128) ?? "";
    let confidence = num(s.confidence) ?? 0;
    if (confidence < 0) confidence = 0;
    if (confidence > 1) confidence = 1;
    if (!ALLOWED_SIGNAL_TYPES.has(type) || name === "") continue;
    signals.push({ type, name, confidence });
  }
  if (signals.length === 0) return { ok: false, error: "no valid signals" };

  let honeypot: IncomingEvent["honeypot"];
  if (o.honeypot && typeof o.honeypot === "object") {
    const hp = o.honeypot as Record<string, unknown>;
    honeypot = { action: str(hp.action, 16) ?? undefined, score: num(hp.score) ?? undefined };
  }

  return {
    ok: true,
    value: { v: 1, ts, sessionId, siteId, source: safeSource, signals, path, ua, lang, screen, tz, honeypot },
  };
}
