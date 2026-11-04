/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * Knowledge base: learned attack signatures that grow in confidence with
 * repeated observation. Storage is injected (the collector backs it with
 * SQLite) so this package stays storage-agnostic and testable.
 */
import type { KnowledgeSignature } from "./types.js";

export interface KnowledgeStore {
  get(pattern: string): KnowledgeSignature | null;
  put(sig: KnowledgeSignature): void;
  list(limit: number): KnowledgeSignature[];
}

/** In-memory store (default; tests and single-process use). */
export class MemoryKnowledgeStore implements KnowledgeStore {
  private readonly map = new Map<string, KnowledgeSignature>();
  get(pattern: string): KnowledgeSignature | null {
    return this.map.get(pattern) ?? null;
  }
  put(sig: KnowledgeSignature): void {
    this.map.set(sig.pattern, sig);
  }
  list(limit: number): KnowledgeSignature[] {
    return [...this.map.values()].sort((a, b) => b.confidence - a.confidence).slice(0, limit);
  }
}

/**
 * Reinforce a signature from an observed combo. Confidence rises with
 * occurrences via a saturating curve (never reaches 1, never decays to panic).
 */
export function reinforce(store: KnowledgeStore, pattern: string, count: number, now = Date.now()): KnowledgeSignature {
  const existing = store.get(pattern);
  const occurrences = (existing?.occurrences ?? 0) + count;
  // Saturating confidence: 1 - 1/(1 + occurrences/20), capped at 0.97.
  const confidence = Math.min(0.97, 1 - 1 / (1 + occurrences / 20));
  const sig: KnowledgeSignature = {
    id: existing?.id ?? `kb-${Buffer.from(pattern).toString("base64url").slice(0, 16)}`,
    pattern,
    confidence,
    occurrences,
    firstSeen: existing?.firstSeen ?? now,
    lastSeen: now,
  };
  store.put(sig);
  return sig;
}
