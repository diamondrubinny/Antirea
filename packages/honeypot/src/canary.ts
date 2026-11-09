/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * Source-map canaries. Append the comment to a served bundle; the URL is never
 * linked anywhere else, and browsers only fetch source maps while DevTools is
 * open. A request for it is therefore a source-map consumer analysing the
 * bundle — e.g. REA's `analyze_web_bundle` with `fetch_source_maps`, which
 * fetches every map a page declares. Pair with the honeypot's
 * `sourceMapCanary` option so the hit is scored and answered with a decoy.
 */
import { randomBytes } from "node:crypto";

/** Default path prefix for canary maps. */
export const DEFAULT_CANARY_PREFIX = "/__antirea/m/";

/**
 * Build a `//# sourceMappingURL=` comment pointing at a unique canary map.
 * @param prefix path prefix also given to the honeypot's `sourceMapCanary`
 * @param token unique, unguessable id (random by default) — log it to trace
 *   which bundle or release a hit came from
 */
export function sourceMapCanaryComment(prefix = DEFAULT_CANARY_PREFIX, token?: string): string {
  if (!prefix.startsWith("/")) throw new Error("canary prefix must start with '/'");
  const id = token ?? randomBytes(12).toString("hex");
  if (!/^[A-Za-z0-9_-]{8,128}$/.test(id)) throw new Error("canary token must be 8-128 URL-safe characters");
  const base = prefix.endsWith("/") ? prefix : `${prefix}/`;
  return `//# sourceMappingURL=${base}${id}.map`;
}
