/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * HMAC signing for short-lived session tokens. Server-only (uses node:crypto).
 *
 * The token binds a session id + expiry so the /invoke endpoint can be
 * stateless about auth while still rejecting forged or expired sessions.
 * The secret NEVER leaves the server, so a CDP/client attacker cannot mint
 * tokens or learn how results are produced.
 */
import { createHmac, timingSafeEqual } from "node:crypto";

export interface TokenPayload {
  /** Session id. */
  sid: string;
  /** Expiry, ms epoch. */
  exp: number;
}

function b64url(buf: Buffer): string {
  return buf.toString("base64url");
}

export function signToken(secret: string, payload: TokenPayload): string {
  const body = b64url(Buffer.from(JSON.stringify(payload)));
  const mac = b64url(createHmac("sha256", secret).update(body).digest());
  return `${body}.${mac}`;
}

export function verifyToken(secret: string, token: string): TokenPayload | null {
  const dot = token.indexOf(".");
  if (dot < 0) return null;
  const body = token.slice(0, dot);
  const mac = token.slice(dot + 1);
  const expected = b64url(createHmac("sha256", secret).update(body).digest());
  const a = Buffer.from(mac);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !timingSafeEqual(a, b)) return null;
  try {
    const payload = JSON.parse(Buffer.from(body, "base64url").toString("utf8")) as TokenPayload;
    if (typeof payload.sid !== "string" || typeof payload.exp !== "number") return null;
    if (Date.now() > payload.exp) return null;
    return payload;
  } catch {
    return null;
  }
}
