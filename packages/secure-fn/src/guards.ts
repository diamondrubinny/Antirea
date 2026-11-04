/**
 * In-memory protections for the invoke endpoint: nonce replay store and a
 * per-session rate limiter. Both self-prune.
 *
 * For a single-process deployment these are sufficient. For multi-instance,
 * back them with a shared store (e.g. Redis) — noted in the README.
 */

/** Rejects reused nonces within a TTL window (anti-replay). */
export class NonceStore {
  private readonly seen = new Map<string, number>(); // nonce -> expiry
  constructor(private readonly ttlMs: number) {}

  /** Returns true if the nonce is fresh (and records it); false if reused. */
  check(nonce: string): boolean {
    this.prune();
    if (!nonce || this.seen.has(nonce)) return false;
    this.seen.set(nonce, Date.now() + this.ttlMs);
    return true;
  }

  private prune(): void {
    const now = Date.now();
    for (const [k, exp] of this.seen) if (exp < now) this.seen.delete(k);
  }
}

/** Fixed-window per-key rate limiter. */
export class RateLimiter {
  private readonly windows = new Map<string, { count: number; resetAt: number }>();
  constructor(private readonly limit: number, private readonly windowMs: number) {}

  /** Returns { ok, count }. ok=false means the key is over its limit. */
  hit(key: string): { ok: boolean; count: number } {
    const now = Date.now();
    let w = this.windows.get(key);
    if (!w || w.resetAt < now) {
      w = { count: 0, resetAt: now + this.windowMs };
      this.windows.set(key, w);
    }
    w.count += 1;
    return { ok: w.count <= this.limit, count: w.count };
  }
}
