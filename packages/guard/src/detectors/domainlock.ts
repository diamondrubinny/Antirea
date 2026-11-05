/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * Domain lock: flag (and optionally degrade) when the page runs on a host that
 * is not in your allowlist — i.e. someone copied your front-end and rehosted it
 * on their own domain. Even in "silent" mode this is useful intelligence: the
 * clone's hostname shows up in your dashboard.
 *
 * LIMITATIONS: this is client-side, so an attacker who reads the code can delete
 * the check or patch the allowlist. It stops lazy copy-paste rehosting and
 * surfaces clones; it is not a hard lock. Keep real logic server-side.
 */
import type { Signal } from "../types";

/**
 * Returns a signal when `host` is not covered by `allowed`. A host matches an
 * allowlist entry exactly or as a subdomain (e.g. "app.example.com" matches
 * "example.com"). Empty allowlist = disabled.
 */
export function checkDomainLock(allowed: string[], host: string): Signal[] {
  if (!allowed || allowed.length === 0) return [];
  const h = (host || "").toLowerCase();
  const okHost = allowed.some((a) => {
    const base = a.toLowerCase().replace(/^\*\./, "");
    return h === base || h.endsWith(`.${base}`);
  });
  if (okHost) return [];
  return [{ type: "integrity", name: "domainlock.mismatch", confidence: 0.9, detail: h.slice(0, 64) }];
}

/** Read the current host safely (browser). */
export function currentHost(): string {
  try {
    return typeof location !== "undefined" ? location.host : "";
  } catch {
    return "";
  }
}
