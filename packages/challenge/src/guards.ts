/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/** Self-pruning replay cache for solved proofs (in-memory; single process). */
export class ReplayCache {
  private readonly seen = new Map<string, number>();
  constructor(private readonly ttlMs = 5 * 60_000) {}
  has(key: string): boolean {
    this.prune();
    return this.seen.has(key);
  }
  add(key: string): void {
    this.seen.set(key, Date.now() + this.ttlMs);
  }
  private prune(): void {
    const now = Date.now();
    for (const [k, exp] of this.seen) if (exp < now) this.seen.delete(k);
  }
}
