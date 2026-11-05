/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * Browser helpers to decrypt and run an encrypted bundle. Combine with the
 * guard's attestation gate: fetch the KEY through the gate so a detected
 * CDP/automation client never receives it.
 *
 *   import { importEncrypted } from "@antirea/harden/client";
 *   // key fetched from a gated endpoint (real for clean clients only):
 *   const mod = await importEncrypted(encryptedPayload, key);
 */
import { decryptBundle, type EncryptedBundle } from "./crypto.js";

export { decryptBundle } from "./crypto.js";
export type { EncryptedBundle } from "./crypto.js";

/** Decrypt an encrypted ES-module bundle and import it. Requires CSP blob: in script-src. */
export async function importEncrypted(
  payload: EncryptedBundle,
  keyB64: string,
): Promise<Record<string, unknown>> {
  const code = await decryptBundle(payload, keyB64);
  const blob = new Blob([code], { type: "text/javascript" });
  const url = URL.createObjectURL(blob);
  try {
    return (await import(/* @vite-ignore */ url)) as Record<string, unknown>;
  } finally {
    URL.revokeObjectURL(url);
  }
}
