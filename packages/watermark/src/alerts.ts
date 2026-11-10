/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * Alerts: fire a webhook (Slack/Discord/generic JSON) when attacks spike or a
 * canary is found. Includes a cooldown so one incident doesn't spam the channel.
 *
 * `fetchImpl` is injectable for testing.
 */
import { createHmac } from "node:crypto";

export interface AlertConfig {
  /** Webhook URL (Slack/Discord incoming webhook or any JSON endpoint). */
  webhookUrl: string;
  /** Minimum ms between alerts of the same key. Default 10 min. */
  cooldownMs?: number;
  /**
   * Shared secret (16+ characters). When set, each request carries
   * `X-Antirea-Timestamp` and `X-Antirea-Signature: sha256=<hex>` so the
   * receiver can verify the alert came from this collector.
   */
  secret?: string;
  /** Injectable fetch. */
  fetchImpl?: typeof fetch;
}

/** Rolling spike detector over a time window. */
export class SpikeDetector {
  private readonly times: number[] = [];
  constructor(
    private readonly windowMs: number,
    private readonly threshold: number,
  ) {}
  /** Record one event; returns true when the window count crosses the threshold. */
  hit(now = Date.now()): boolean {
    const cutoff = now - this.windowMs;
    while (this.times.length && this.times[0] < cutoff) this.times.shift();
    this.times.push(now);
    return this.times.length === this.threshold; // fire once on crossing
  }
  count(now = Date.now()): number {
    const cutoff = now - this.windowMs;
    return this.times.filter((t) => t >= cutoff).length;
  }
}

/** Keys remembered for cooldown; oldest are dropped beyond this. */
const MAX_COOLDOWN_KEYS = 1000;
/** Give up on a webhook that does not answer. */
const SEND_TIMEOUT_MS = 5000;

/**
 * Signature for a webhook body: HMAC-SHA-256 over `<timestamp>.<body>`, hex.
 * The receiver recomputes it with the shared secret and compares in constant
 * time, and rejects timestamps that are too old (replay).
 */
export function signWebhook(secret: string, timestamp: number, body: string): string {
  return createHmac("sha256", secret).update(`${timestamp}.${body}`).digest("hex");
}

export class Alerter {
  private readonly last = new Map<string, number>();
  constructor(private readonly cfg: AlertConfig) {
    let url: URL;
    try {
      url = new URL(cfg.webhookUrl);
    } catch {
      throw new Error("[antirea] alert webhook URL is not a valid URL");
    }
    const local = url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "[::1]";
    if (url.protocol !== "https:" && !(url.protocol === "http:" && local)) {
      throw new Error("[antirea] alert webhook URL must use https");
    }
    if (cfg.secret !== undefined && cfg.secret.length < 16) {
      throw new Error("[antirea] alert webhook secret must be at least 16 characters");
    }
  }

  /**
   * Send an alert, honoring the per-key cooldown. Returns true only if the
   * webhook answered with a success status. A failed attempt still starts the
   * cooldown, so an unreachable webhook is not retried on every event.
   */
  async send(key: string, text: string, extra?: Record<string, unknown>, now = Date.now()): Promise<boolean> {
    const cooldown = this.cfg.cooldownMs ?? 10 * 60_000;
    const prev = this.last.get(key);
    if (prev !== undefined && now - prev < cooldown) return false;
    // Keys can derive from request data: keep the table bounded.
    if (this.last.size >= MAX_COOLDOWN_KEYS) {
      for (const [k, t] of this.last) if (now - t >= cooldown) this.last.delete(k);
      while (this.last.size >= MAX_COOLDOWN_KEYS) {
        const oldest = this.last.keys().next().value;
        if (oldest === undefined) break;
        this.last.delete(oldest);
      }
    }
    this.last.delete(key);
    this.last.set(key, now);

    const doFetch = this.cfg.fetchImpl ?? fetch;
    // `text` is the Slack/Discord field; `extra` carries structured data.
    const body = JSON.stringify({ text, ...extra });
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (this.cfg.secret) {
      const ts = Math.floor(now / 1000);
      headers["X-Antirea-Timestamp"] = String(ts);
      headers["X-Antirea-Signature"] = `sha256=${signWebhook(this.cfg.secret, ts, body)}`;
    }
    try {
      const res = await doFetch(this.cfg.webhookUrl, {
        method: "POST",
        headers,
        body,
        signal: AbortSignal.timeout(SEND_TIMEOUT_MS),
      });
      return res.ok === true;
    } catch {
      return false;
    }
  }
}
