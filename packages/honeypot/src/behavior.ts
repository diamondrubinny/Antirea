/**
 * Server-side behavioural detection engine.
 *
 * KEY PROPERTY: this does NOT trust client-supplied headers. It scores what
 * the server itself observes — the connection IP, request cadence, timing
 * regularity, burst volume, path-harvesting shape, and header INSTABILITY
 * (an attacker rotating/forging the User-Agent from one IP raises the score,
 * not lowers it). So tampering with the header does not help an attacker and
 * often exposes them.
 *
 * SCOPE (honest): this is statistical deterrence, not a mathematical wall. A
 * slow, patient, single-identity scraper can stay under thresholds. The only
 * hermetic protection for proprietary logic is server-side execution
 * (@antirea/secure-fn). This engine raises cost and surfaces attackers.
 *
 * MEMORY: in-process, bounded LRU. For multi-instance deployments back it with
 * a shared store (e.g. Redis) — see README.
 */

export interface BehaviorInput {
  /** Connection IP (server-observed, not a header the client controls). */
  ip: string;
  /** Request path. */
  path: string;
  /** Stable hash of the client's declared identity headers. */
  fingerprint: string;
  /** Whether this request is for a static asset (js/css/map/img/font). */
  isAsset: boolean;
  /** Whether this request looks like a top-level navigation (HTML document). */
  isNavigation: boolean;
  /** Current time (ms). Injectable for tests. */
  now?: number;
}

export interface BehaviorVerdict {
  /** 0..1 — higher means more bot-like, independent of header claims. */
  score: number;
  reasons: string[];
  /** Observations recorded for this IP in the window. */
  count: number;
}

interface IpRecord {
  times: number[]; // request timestamps (bounded)
  paths: Set<string>;
  fingerprints: Map<string, number>; // fp -> last seen
  navCount: number;
  assetCount: number;
  lastSeen: number;
}

export interface BehaviorOptions {
  /** Sliding window length (ms). Default 10 min. */
  windowMs?: number;
  /** Max timestamps kept per IP. Default 60. */
  maxSamplesPerIp?: number;
  /** Max tracked IPs before LRU eviction. Default 50000. */
  maxIps?: number;
  /** Requests within 10s above this count flag high velocity. Default 25. */
  velocityPer10s?: number;
  /** Distinct asset paths with zero navigations that flag harvesting. Default 8. */
  harvestAssetPaths?: number;
  /** Distinct header fingerprints from one IP that flag rotation. Default 3. */
  fingerprintChurn?: number;
}

export class BehaviorTracker {
  private readonly rec = new Map<string, IpRecord>();
  private readonly windowMs: number;
  private readonly maxSamples: number;
  private readonly maxIps: number;
  private readonly velocityPer10s: number;
  private readonly harvestAssetPaths: number;
  private readonly fingerprintChurn: number;

  constructor(opts: BehaviorOptions = {}) {
    this.windowMs = opts.windowMs ?? 10 * 60_000;
    this.maxSamples = opts.maxSamplesPerIp ?? 60;
    this.maxIps = opts.maxIps ?? 50_000;
    this.velocityPer10s = opts.velocityPer10s ?? 25;
    this.harvestAssetPaths = opts.harvestAssetPaths ?? 8;
    this.fingerprintChurn = opts.fingerprintChurn ?? 3;
  }

  /** Record a request and return the current behavioural verdict for its IP. */
  record(input: BehaviorInput): BehaviorVerdict {
    const now = input.now ?? Date.now();
    if (!input.ip) return { score: 0, reasons: [], count: 0 };

    let r = this.rec.get(input.ip);
    if (!r) {
      r = { times: [], paths: new Set(), fingerprints: new Map(), navCount: 0, assetCount: 0, lastSeen: now };
      this.rec.set(input.ip, r);
      this.evictIfNeeded();
    }

    // Drop samples outside the window.
    const cutoff = now - this.windowMs;
    r.times = r.times.filter((t) => t >= cutoff);

    r.times.push(now);
    if (r.times.length > this.maxSamples) r.times.shift();
    r.paths.add(input.path);
    r.fingerprints.set(input.fingerprint, now);
    if (input.isNavigation) r.navCount += 1;
    if (input.isAsset) r.assetCount += 1;
    r.lastSeen = now;

    return this.evaluate(r, now);
  }

  private evaluate(r: IpRecord, now: number): BehaviorVerdict {
    const reasons: string[] = [];
    let score = 0;
    const count = r.times.length;

    // 1. Velocity: many requests in the last 10 seconds.
    const recent = r.times.filter((t) => t >= now - 10_000).length;
    if (recent >= this.velocityPer10s) {
      score += 0.5;
      reasons.push(`velocity:${recent}/10s`);
    }

    // 2. Timing regularity: scripted clients fire at suspiciously even
    //    intervals. Low coefficient of variation + enough samples = robotic.
    if (count >= 8) {
      const intervals: number[] = [];
      for (let i = 1; i < r.times.length; i++) intervals.push(r.times[i] - r.times[i - 1]);
      const mean = intervals.reduce((a, b) => a + b, 0) / intervals.length;
      if (mean > 0) {
        const variance = intervals.reduce((a, b) => a + (b - mean) ** 2, 0) / intervals.length;
        const cv = Math.sqrt(variance) / mean;
        if (cv < 0.12) {
          score += 0.45;
          reasons.push(`cadence:cv=${cv.toFixed(2)}`);
        }
        // Sustained very fast cadence is hard for a human UI to produce.
        if (mean < 60 && count >= 5) {
          score += 0.35;
          reasons.push(`fastCadence:${Math.round(mean)}ms`);
        }
      }
    }

    // 3. Harvesting shape: many distinct asset paths, never loading a page.
    if (r.navCount === 0 && r.paths.size >= this.harvestAssetPaths && r.assetCount >= this.harvestAssetPaths) {
      score += 0.4;
      reasons.push(`harvest:${r.paths.size}assets/0nav`);
    }

    // 4. Header instability: one IP presenting several distinct identities in
    //    the window strongly implies forged/rotated headers. This is exactly
    //    the "attacker changes the header" case — it RAISES the score.
    const liveFps = [...r.fingerprints.values()].filter((t) => t >= now - this.windowMs).length;
    if (liveFps >= this.fingerprintChurn) {
      score += 0.55;
      reasons.push(`headerChurn:${liveFps}`);
    }

    return { score: Math.min(1, score), reasons, count };
  }

  private evictIfNeeded(): void {
    if (this.rec.size <= this.maxIps) return;
    // Evict the least-recently-seen ~1% to amortise cost.
    const target = Math.max(1, Math.floor(this.maxIps * 0.01));
    const entries = [...this.rec.entries()].sort((a, b) => a[1].lastSeen - b[1].lastSeen);
    for (let i = 0; i < target && i < entries.length; i++) this.rec.delete(entries[i][0]);
  }

  /** Expose a snapshot for the admin panel (top offenders). */
  topOffenders(now = Date.now(), limit = 50): Array<{ ip: string; count: number; verdict: BehaviorVerdict }> {
    const out: Array<{ ip: string; count: number; verdict: BehaviorVerdict }> = [];
    for (const [ip, r] of this.rec) {
      const v = this.evaluate(r, now);
      if (v.score > 0) out.push({ ip, count: r.times.length, verdict: v });
    }
    return out.sort((a, b) => b.verdict.score - a.verdict.score).slice(0, limit);
  }
}

/** Cheap, stable fingerprint of identity headers (no crypto needed). */
export function fingerprintHeaders(h: Record<string, string | string[] | undefined>): string {
  const get = (k: string): string => {
    const v = h[k];
    return (Array.isArray(v) ? v.join(",") : v ?? "").slice(0, 256);
  };
  return [
    get("user-agent"),
    get("accept"),
    get("accept-language"),
    get("accept-encoding"),
    get("sec-ch-ua"),
    get("sec-ch-ua-platform"),
  ].join("|");
}
