/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * Server-side proof-of-work. The server issues a signed challenge; the client
 * must find a nonce whose SHA-256(challenge:nonce) has `difficulty` leading
 * zero bits. Verification is stateless (HMAC-signed challenge) apart from a
 * small replay cache, so mass scraping pays CPU for every request.
 *
 * SCOPE (honest): PoW raises the cost of HIGH-VOLUME automated access. It does
 * not stop a single determined client, and difficulty must be tuned so real
 * users (and low-power devices) are not punished. Use it for flagged/suspicious
 * traffic, not every visitor.
 */
import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { leadingZeroBits } from "./sha256.js";

export interface PowConfig {
  /** HMAC secret for signing challenges. Required, from env. */
  secret: string;
  /** Required leading zero bits. Default 18 (~0.5-3s on a laptop). */
  difficulty?: number;
  /** Challenge lifetime (ms). Default 120000. */
  ttlMs?: number;
}

export interface Challenge {
  /** Opaque signed token (carries c, difficulty, expiry). */
  token: string;
  /** Random challenge string the client hashes. */
  c: string;
  difficulty: number;
  ttlMs: number;
}

interface Payload {
  c: string;
  d: number;
  exp: number;
}

function b64url(buf: Buffer): string {
  return buf.toString("base64url");
}

function sign(secret: string, body: string): string {
  return b64url(createHmac("sha256", secret).update(body).digest());
}

export function issueChallenge(cfg: PowConfig): Challenge {
  const difficulty = cfg.difficulty ?? 18;
  const ttlMs = cfg.ttlMs ?? 120_000;
  const c = randomBytes(16).toString("hex");
  const payload: Payload = { c, d: difficulty, exp: Date.now() + ttlMs };
  const body = b64url(Buffer.from(JSON.stringify(payload)));
  const token = `${body}.${sign(cfg.secret, body)}`;
  return { token, c, difficulty, ttlMs };
}

export interface VerifyResult {
  ok: boolean;
  reason?: string;
}

/** Stateless verify (plus caller-supplied replay guard). */
export function verifySolution(
  cfg: PowConfig,
  token: string,
  nonce: string,
  seen?: { has: (k: string) => boolean; add: (k: string) => void },
): VerifyResult {
  const dot = token.indexOf(".");
  if (dot < 0) return { ok: false, reason: "malformed" };
  const body = token.slice(0, dot);
  const mac = token.slice(dot + 1);
  const expected = sign(cfg.secret, body);
  const a = Buffer.from(mac);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !timingSafeEqual(a, b)) return { ok: false, reason: "bad_signature" };

  let payload: Payload;
  try {
    payload = JSON.parse(Buffer.from(body, "base64url").toString("utf8")) as Payload;
  } catch {
    return { ok: false, reason: "bad_payload" };
  }
  if (Date.now() > payload.exp) return { ok: false, reason: "expired" };
  if (typeof nonce !== "string" || nonce.length === 0 || nonce.length > 64)
    return { ok: false, reason: "bad_nonce" };

  if (seen) {
    const key = `${body}:${nonce}`;
    if (seen.has(key)) return { ok: false, reason: "replay" };
  }

  const digest = createHash("sha256").update(`${payload.c}:${nonce}`).digest("hex");
  if (leadingZeroBits(digest) < payload.d) return { ok: false, reason: "insufficient_work" };

  if (seen) seen.add(`${body}:${nonce}`);
  return { ok: true };
}
