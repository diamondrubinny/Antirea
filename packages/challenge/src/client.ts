/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * Browser-side proof-of-work solver and a fetch wrapper. No node deps.
 *
 *   import { proofFetch } from "@antirea/challenge/client";
 *   const res = await proofFetch("/api/export", {}, "/__pow");
 *
 * On a 402 proof_required, it solves the challenge and retries once with the
 * proof headers. Solving is CPU-bound; for high difficulty, run it in a Worker.
 */
import { leadingZeroBits, sha256hex } from "./sha256.js";

export interface ChallengeData {
  token: string;
  c: string;
  difficulty: number;
  ttlMs?: number;
}

/** Find a nonce such that sha256(c:nonce) has `difficulty` leading zero bits. */
export function solvePow(c: string, difficulty: number, maxIterations = 50_000_000): string {
  for (let n = 0; n < maxIterations; n++) {
    const nonce = n.toString(36);
    if (leadingZeroBits(sha256hex(`${c}:${nonce}`)) >= difficulty) return nonce;
  }
  throw new Error("proof-of-work: exceeded max iterations");
}

/** Headers carrying a solved proof, to attach to a retried request. */
export function proofHeaders(ch: ChallengeData): Record<string, string> {
  const nonce = solvePow(ch.c, ch.difficulty);
  return { "X-Antirea-PoW-Token": ch.token, "X-Antirea-PoW-Nonce": nonce };
}

/**
 * fetch() that transparently satisfies a proof-of-work gate. On a 402 with
 * `proof_required`, it solves the challenge and retries once.
 */
export async function proofFetch(
  url: string,
  init: RequestInit = {},
  _challengeEndpoint?: string,
): Promise<Response> {
  const first = await fetch(url, init);
  if (first.status !== 402) return first;
  let data: ChallengeData & { error?: string };
  try {
    data = (await first.clone().json()) as ChallengeData & { error?: string };
  } catch {
    return first;
  }
  if (data.error !== "proof_required" || !data.token || !data.c) return first;
  const headers = { ...(init.headers as Record<string, string>), ...proofHeaders(data) };
  return fetch(url, { ...init, headers });
}

export { sha256hex, leadingZeroBits } from "./sha256.js";
