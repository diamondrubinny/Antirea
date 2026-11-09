/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * GeoIP enrichment + privacy-preserving IP handling.
 *
 * Privacy by design:
 *   - We derive a COUNTRY (coarse) from the IP, for the "from where" view.
 *   - We store sha256(ip + salt) only, to count unique sources without
 *     retaining the raw IP (a personal identifier under GDPR / IL law).
 *   - The raw IP is never written to disk or logs.
 *
 * NOTE: geoip-lite bundles MaxMind GeoLite2 data. Its EULA/licensing for
 * COMMERCIAL use REQUIRES LEGAL VERIFICATION. The data also needs periodic
 * updates. Treated as optional: if unavailable, country resolves to "".
 */
import { createHash } from "node:crypto";

type GeoLookup = (ip: string) => { country?: string } | null;

let lookup: GeoLookup = () => null;

// Lazy, optional load so the collector runs even without the geo dataset.
export async function initGeo(): Promise<void> {
  try {
    const mod = (await import("geoip-lite")) as unknown as {
      default?: { lookup: GeoLookup };
      lookup?: GeoLookup;
    };
    const fn = mod.default?.lookup ?? mod.lookup;
    if (fn) lookup = fn;
  } catch {
    // geoip-lite not installed → country stays "". Non-fatal.
  }
}

export function countryFor(ip: string): string {
  if (!ip) return "";
  try {
    const r = lookup(ip);
    return r?.country ?? "";
  } catch {
    return "";
  }
}

/** Salted, non-reversible IP fingerprint. Salt MUST come from env, not code. */
export function hashIp(ip: string, salt: string): string {
  if (!ip) return "";
  return createHash("sha256").update(salt).update("|").update(ip).digest("hex").slice(0, 32);
}

/**
 * Extract the client IP, trusting exactly `trustHops` reverse proxies.
 *
 * Each trusted proxy appends the address it saw to X-Forwarded-For, so the
 * client is the entry `trustHops` places from the right. Entries further left
 * are client-supplied and can be forged, so they are never used. With
 * `trustHops = 0` the socket address is used and the header is ignored.
 */
export function extractIp(
  headers: Record<string, string | string[] | undefined>,
  socketAddr: string | undefined,
  trustHops: number,
): string {
  if (trustHops > 0) {
    const xff = headers["x-forwarded-for"];
    const val = Array.isArray(xff) ? xff.join(",") : xff;
    if (val) {
      const parts = val
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
      if (parts.length > 0) return parts[Math.max(parts.length - trustHops, 0)];
    }
  }
  return socketAddr ?? "";
}
