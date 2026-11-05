/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * Subresource Integrity (SRI) hashes. Put the result in a script/link
 * `integrity="..."` attribute so the browser refuses a tampered asset.
 */
import { createHash } from "node:crypto";

export type SriAlgo = "sha256" | "sha384" | "sha512";

/** Compute an SRI hash, e.g. "sha384-<base64>". Default sha384. */
export function sriHash(content: string | Uint8Array, algo: SriAlgo = "sha384"): string {
  const digest = createHash(algo)
    .update(typeof content === "string" ? Buffer.from(content, "utf8") : Buffer.from(content))
    .digest("base64");
  return `${algo}-${digest}`;
}
