/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * Build a strict Content-Security-Policy string. Defaults lock everything to
 * 'self'; add the few sources your app actually needs. A CSP limits injection
 * and makes it harder to exfiltrate code/data from a compromised page.
 */
export interface CspOptions {
  /** Extra script-src sources (besides 'self'). */
  scriptSrc?: string[];
  /** Extra style-src sources. */
  styleSrc?: string[];
  /** Extra connect-src sources (your API/collector origins). */
  connectSrc?: string[];
  /** Extra img-src sources (data: is included by default). */
  imgSrc?: string[];
  /** A per-response nonce to allow specific inline scripts. */
  nonce?: string;
  /** Allow 'unsafe-inline' styles (needed if you use inline style attributes). */
  allowInlineStyle?: boolean;
  /** Allow blob: in script-src (needed for importProtected / WASM blob import). */
  allowScriptBlob?: boolean;
  /** report-uri / report-to endpoint. */
  reportUri?: string;
}

export function buildCsp(o: CspOptions = {}): string {
  const script = [
    "'self'",
    ...(o.allowScriptBlob ? ["blob:"] : []),
    ...(o.nonce ? [`'nonce-${o.nonce}'`] : []),
    ...(o.scriptSrc ?? []),
  ];
  const style = ["'self'", ...(o.allowInlineStyle ? ["'unsafe-inline'"] : []), ...(o.styleSrc ?? [])];
  const connect = ["'self'", ...(o.connectSrc ?? [])];
  const img = ["'self'", "data:", ...(o.imgSrc ?? [])];
  const parts = [
    `default-src 'self'`,
    `script-src ${script.join(" ")}`,
    `style-src ${style.join(" ")}`,
    `connect-src ${connect.join(" ")}`,
    `img-src ${img.join(" ")}`,
    `object-src 'none'`,
    `base-uri 'self'`,
    `frame-ancestors 'none'`,
    `form-action 'self'`,
    `upgrade-insecure-requests`,
  ];
  if (o.reportUri) parts.push(`report-uri ${o.reportUri}`);
  return parts.join("; ");
}
