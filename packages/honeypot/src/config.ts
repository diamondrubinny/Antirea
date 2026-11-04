/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * Optional live configuration pulled from the collector's admin panel, so an
 * operator can change mode/threshold/allow/block lists WITHOUT redeploying the
 * protected site. Polls on an interval; on any error it keeps the last good
 * config (fail-safe, never throws into the request path).
 */
export interface RemoteConfig {
  mode?: "shadow" | "live";
  threshold?: number;
  allowIps?: string[];
  blockIps?: string[];
  /** Master switch; when false the middleware passes everything through. */
  enabled?: boolean;
}

export interface RemoteConfigOptions {
  /** e.g. "https://collector.example.com/api/site-config". */
  url: string;
  /** Site identifier (query param). */
  siteId: string;
  /** Shared site key sent as X-Antirea-Site-Key. */
  siteKey: string;
  /** Poll interval ms. Default 30s. */
  intervalMs?: number;
}

export class RemoteConfigClient {
  private current: RemoteConfig = {};
  private timer: ReturnType<typeof setInterval> | null = null;

  constructor(private readonly opts: RemoteConfigOptions) {}

  get(): RemoteConfig {
    return this.current;
  }

  start(): void {
    void this.refresh();
    this.timer = setInterval(() => void this.refresh(), this.opts.intervalMs ?? 30_000);
    // Do not keep the process alive solely for polling.
    (this.timer as { unref?: () => void }).unref?.();
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  private async refresh(): Promise<void> {
    try {
      const u = new URL(this.opts.url);
      u.searchParams.set("site", this.opts.siteId);
      const res = await fetch(u.toString(), {
        headers: { "X-Antirea-Site-Key": this.opts.siteKey },
      });
      if (!res.ok) return;
      const data = (await res.json()) as RemoteConfig;
      // Shallow validation; ignore anything unexpected.
      this.current = {
        mode: data.mode === "live" || data.mode === "shadow" ? data.mode : undefined,
        threshold: typeof data.threshold === "number" ? data.threshold : undefined,
        allowIps: Array.isArray(data.allowIps) ? data.allowIps.slice(0, 1000) : undefined,
        blockIps: Array.isArray(data.blockIps) ? data.blockIps.slice(0, 1000) : undefined,
        enabled: typeof data.enabled === "boolean" ? data.enabled : undefined,
      };
    } catch {
      /* keep last good config */
    }
  }
}
