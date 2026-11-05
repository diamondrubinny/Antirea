/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * Encrypted-bundle delivery. The real client bundle is encrypted at rest; the
 * key is handed only to clean clients (deliver it through the guard's
 * attestation gate, so a detected CDP/automation client never receives it).
 *
 * Uses WebCrypto (AES-256-GCM), isomorphic between Node ≥18 and the browser.
 *
 * LIMITATIONS (honest): any client that receives the key can decrypt and read
 * the bundle — the protection is the GATE on the key, not the encryption. This
 * raises cost and withholds code from detected clients; it is not hermetic.
 * Keep real logic server-side (@antirea/secure-fn).
 */
import { base64ToBytes, bytesToBase64 } from "./b64.js";

export interface EncryptedBundle {
  alg: "AES-GCM";
  iv: string; // base64
  ct: string; // base64 (ciphertext + tag)
}

const enc = new TextEncoder();
const dec = new TextDecoder();

function subtle(): SubtleCrypto {
  const c = (globalThis as { crypto?: Crypto }).crypto;
  if (!c?.subtle) throw new Error("WebCrypto subtle is not available in this runtime");
  return c.subtle;
}

/** Generate a fresh 256-bit key, returned as base64. */
export async function generateKey(): Promise<string> {
  const raw = new Uint8Array(32);
  (globalThis.crypto as Crypto).getRandomValues(raw);
  return bytesToBase64(raw);
}

// WebCrypto's DOM types want ArrayBuffer-backed BufferSource; our Uint8Arrays
// are fine at runtime, so present them as BufferSource.
const buf = (u8: Uint8Array): BufferSource => u8 as unknown as BufferSource;

async function importKey(keyB64: string): Promise<CryptoKey> {
  return subtle().importKey("raw", buf(base64ToBytes(keyB64)), { name: "AES-GCM" }, false, [
    "encrypt",
    "decrypt",
  ]);
}

/** Encrypt a bundle (string) with a base64 key. */
export async function encryptBundle(plaintext: string, keyB64: string): Promise<EncryptedBundle> {
  const key = await importKey(keyB64);
  const iv = new Uint8Array(12);
  (globalThis.crypto as Crypto).getRandomValues(iv);
  const ct = await subtle().encrypt({ name: "AES-GCM", iv: buf(iv) }, key, buf(enc.encode(plaintext)));
  return { alg: "AES-GCM", iv: bytesToBase64(iv), ct: bytesToBase64(new Uint8Array(ct)) };
}

/** Decrypt a bundle produced by encryptBundle. Throws on a wrong key/tamper. */
export async function decryptBundle(payload: EncryptedBundle, keyB64: string): Promise<string> {
  const key = await importKey(keyB64);
  const pt = await subtle().decrypt(
    { name: "AES-GCM", iv: buf(base64ToBytes(payload.iv)) },
    key,
    buf(base64ToBytes(payload.ct)),
  );
  return dec.decode(pt);
}
