/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * Express/connect middleware that sets a strong set of security headers,
 * including a CSP built from csp.ts. Reduces the injection/exfiltration surface
 * around your protected app.
 */
import type { IncomingMessage, ServerResponse } from "node:http";
import { buildCsp, type CspOptions } from "./csp.js";

export interface SecurityHeaderOptions {
  csp?: CspOptions | false; // false disables the CSP header
  /** HSTS max-age in seconds. Default 1 year. 0 disables HSTS. */
  hstsMaxAge?: number;
  /** X-Frame-Options value. Default "DENY". */
  frameOptions?: "DENY" | "SAMEORIGIN";
  /** Referrer-Policy. Default "strict-origin-when-cross-origin". */
  referrerPolicy?: string;
  /** Permissions-Policy. Default disables camera/mic/geo/FLoC. */
  permissionsPolicy?: string;
}

export function securityHeaders(opts: SecurityHeaderOptions = {}) {
  const hsts = opts.hstsMaxAge ?? 31536000;
  const csp = opts.csp === false ? null : buildCsp(opts.csp ?? {});
  const frame = opts.frameOptions ?? "DENY";
  const referrer = opts.referrerPolicy ?? "strict-origin-when-cross-origin";
  const perms = opts.permissionsPolicy ?? "geolocation=(), microphone=(), camera=(), interest-cohort=()";

  return function securityHeadersMiddleware(
    _req: IncomingMessage,
    res: ServerResponse,
    next: () => void,
  ): void {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", frame);
    res.setHeader("Referrer-Policy", referrer);
    res.setHeader("Permissions-Policy", perms);
    res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
    if (hsts > 0) res.setHeader("Strict-Transport-Security", `max-age=${hsts}; includeSubDomains`);
    if (csp) res.setHeader("Content-Security-Policy", csp);
    try {
      res.removeHeader("X-Powered-By");
    } catch {
      /* ignore */
    }
    next();
  };
}
