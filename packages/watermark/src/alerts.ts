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
export interface AlertConfig {
  /** Webhook URL (Slack/Discord incoming webhook or any JSON endpoint). */
  webhookUrl: string;
  /** Minimum ms between alerts of the same key. Default 10 min. */
  cooldownMs?: number;
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

export class Alerter {
  private readonly last = new Map<string, number>();
  constructor(private readonly cfg: AlertConfig) {}

  /** Send an alert, honoring the per-key cooldown. Returns true if sent. */
  async send(key: string, text: string, extra?: Record<string, unknown>, now = Date.now()): Promise<boolean> {
    const cooldown = this.cfg.cooldownMs ?? 10 * 60_000;
    const prev = this.last.get(key);
    if (prev !== undefined && now - prev < cooldown) return false;
    this.last.set(key, now);
    const doFetch = this.cfg.fetchImpl ?? fetch;
    try {
      await doFetch(this.cfg.webhookUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        // `text` is the Slack/Discord field; `extra` carries structured data.
        body: JSON.stringify({ text, ...extra }),
      });
      return true;
    } catch {
      return false;
    }
  }
}
