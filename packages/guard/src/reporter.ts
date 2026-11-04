/**
 * Telemetry reporter. Batches signals and ships them to the collector.
 *
 * Privacy by design: sends only coarse, non-PII fields. Page query strings are
 * stripped by default (they may contain tokens). No cookies, no credentials.
 */
import type { GuardConfig, GuardEvent, Signal } from "./types";

/** Generate a non-persistent random session id (not stable across reloads). */
function makeSessionId(): string {
  const buf = new Uint8Array(12);
  (crypto || (window as unknown as { msCrypto: Crypto }).msCrypto).getRandomValues(buf);
  return Array.from(buf, (b) => b.toString(16).padStart(2, "0")).join("");
}

export class Reporter {
  private readonly cfg: Required<Pick<GuardConfig, "siteId" | "endpoint">> & GuardConfig;
  private readonly sessionId = makeSessionId();
  private queue: Signal[] = [];
  private flushTimer: ReturnType<typeof setTimeout> | null = null;
  private readonly seen = new Set<string>();

  constructor(cfg: GuardConfig) {
    this.cfg = { ...cfg };
  }

  /** Enqueue signals; de-duplicates by name within a session. */
  report(signals: Signal[]): void {
    const fresh = signals.filter((s) => {
      const key = `${s.type}:${s.name}`;
      if (this.seen.has(key)) return false;
      this.seen.add(key);
      return true;
    });
    if (fresh.length === 0) return;
    this.queue.push(...fresh);
    this.cfg.onDetect?.(fresh);
    this.scheduleFlush();
  }

  private scheduleFlush(): void {
    if (this.flushTimer) return;
    this.flushTimer = setTimeout(() => this.flush(), 800);
  }

  private buildEvent(signals: Signal[]): GuardEvent {
    const path = this.cfg.includeQuery
      ? location.pathname + location.search
      : location.pathname;
    return {
      v: 1,
      ts: Date.now(),
      sessionId: this.sessionId,
      siteId: this.cfg.siteId,
      signals,
      path,
      ua: navigator.userAgent || "",
      lang: navigator.language || "",
      screen: `${screen.width}x${screen.height}`,
      tz: (() => {
        try {
          return Intl.DateTimeFormat().resolvedOptions().timeZone || "";
        } catch {
          return "";
        }
      })(),
    };
  }

  flush(): void {
    if (this.flushTimer) {
      clearTimeout(this.flushTimer);
      this.flushTimer = null;
    }
    if (this.queue.length === 0) return;
    const event = this.buildEvent(this.queue.splice(0));
    const body = JSON.stringify(event);

    // Prefer sendBeacon: survives page unload, non-blocking.
    try {
      if (navigator.sendBeacon) {
        const blob = new Blob([body], { type: "application/json" });
        if (navigator.sendBeacon(this.cfg.endpoint, blob)) return;
      }
    } catch {
      /* fall through */
    }
    // Fallback: keepalive fetch. No credentials (privacy + CORS simplicity).
    try {
      void fetch(this.cfg.endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body,
        keepalive: true,
        credentials: "omit",
        mode: "cors",
      }).catch(() => void 0);
    } catch {
      /* give up silently; telemetry must never break the host app */
    }
  }
}
