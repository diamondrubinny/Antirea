/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * Secret comparison, bearer parsing, proxy-hop parsing and audit logging for
 * the collector. Kept free of Express so it can be unit-tested directly.
 */
import { createHash, timingSafeEqual } from "node:crypto";

/**
 * Constant-time secret comparison. Both sides are hashed first, so neither the
 * secret's length nor the position of the first mismatch leaks through timing.
 * An empty expected secret never matches.
 */
export function safeEqual(provided: string, expected: string): boolean {
  if (!expected) return false;
  const a = createHash("sha256").update(provided, "utf8").digest();
  const b = createHash("sha256").update(expected, "utf8").digest();
  return timingSafeEqual(a, b);
}

/** Extract the token from an `Authorization: Bearer <token>` header. */
export function bearerToken(header: string | undefined): string {
  if (!header) return "";
  const m = /^Bearer\s+(.+)$/i.exec(header.trim());
  return m ? m[1].trim() : "";
}

/** Minimum length below which the admin token is treated as weak. */
export const MIN_STRONG_TOKEN = 32;

/** Returns a warning message when the token is weak, otherwise null. */
export function tokenStrengthWarning(token: string): string | null {
  if (token.length < MIN_STRONG_TOKEN) {
    return `ADMIN_TOKEN is ${token.length} chars; use at least ${MIN_STRONG_TOKEN} random characters (e.g. \`openssl rand -hex 32\`).`;
  }
  if (/^(.)\1+$/.test(token)) return "ADMIN_TOKEN is a single repeated character; use a random value.";
  return null;
}

/**
 * Parse TRUST_PROXY into a number of trusted proxy hops.
 * "true" means one hop (a single reverse proxy such as nginx or a load
 * balancer). Trusting every hop would let clients forge their IP through
 * X-Forwarded-For and bypass rate limits, so that is never the default.
 */
export function parseTrustProxy(value: string | undefined): number {
  if (!value || value === "false" || value === "0") return 0;
  if (value === "true") return 1;
  const n = Number(value);
  return Number.isInteger(n) && n > 0 && n <= 10 ? n : 0;
}

export type AuditOutcome = "ok" | "denied" | "error";

export interface AuditEntry {
  action: string;
  outcome: AuditOutcome;
  siteId?: string;
  /** Salted IP hash — never the raw address. */
  ipHash?: string;
  detail?: Record<string, string | number | boolean>;
}

/**
 * Structured, append-only audit line (JSON on stdout) for security-relevant
 * actions: admin changes, proposal decisions and failed authentication.
 * Never pass secrets, tokens or raw IPs here.
 */
export function audit(entry: AuditEntry, write: (line: string) => void = (l) => console.log(l)): void {
  write(JSON.stringify({ audit: true, ts: new Date().toISOString(), ...entry }));
}
