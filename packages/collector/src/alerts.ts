/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * Builds the webhook alerts the collector sends. Pure functions, so the
 * payload — what leaves the server — is unit-tested.
 *
 * PRIVACY: an alert goes to a third party (Slack, Discord, your own endpoint).
 * It carries only what is needed to act: site, path, score, signal names and
 * country. It never carries an IP address, an IP hash, a User-Agent or a
 * session id.
 */
import type { IncomingEvent } from "./validate.js";

/** Signal name the honeypot reports for a source-map canary hit. */
export const CANARY_SIGNAL = "honeypot:canary.sourceMap";

export interface AlertMessage {
  /** Cooldown key: one alert per key per cooldown window. */
  key: string;
  /** Human-readable line (the Slack/Discord `text` field). */
  text: string;
  /** Structured fields merged into the JSON body. */
  extra: Record<string, unknown>;
}

/** Strip control characters and bound the length of a value shown in chat. */
function clean(value: string, max: number): string {
  // eslint-disable-next-line no-control-regex
  return value.replace(/[\u0000-\u001f\u007f]/g, " ").slice(0, max);
}

/**
 * Alert for a source-map canary hit, or null when the event is not one.
 * Only events from the honeypot source count.
 *
 * NOTE: the ingest endpoint is unauthenticated (browsers post to it), so an
 * event can be forged. Treat the alert as a prompt to look at the dashboard,
 * not as proof.
 */
export function canaryAlert(ev: IncomingEvent, country: string | null): AlertMessage | null {
  if (ev.source !== "honeypot") return null;
  if (!ev.signals.some((s) => s.name === CANARY_SIGNAL)) return null;
  const site = clean(ev.siteId, 64);
  const path = clean(ev.path, 200);
  const reasons = ev.signals
    .map((s) => clean(s.name.replace(/^honeypot:/, ""), 48))
    .filter((n) => n !== "")
    .slice(0, 12);
  return {
    // The full (validated, length-limited) site id, not the display value:
    // two sites sharing a 64-character prefix must not share a cooldown.
    key: `canary:${ev.siteId}`,
    text: `Antirea: source-map canary read on ${site} (${path}). A source-map consumer fetched the bundle's map — check the dashboard.`,
    extra: {
      event: "canary",
      site,
      path,
      action: ev.honeypot?.action ?? null,
      score: ev.honeypot?.score ?? null,
      reasons,
      country: country ? country : null,
    },
  };
}

/** Most patterns accepted in ALERT_SIGNALS. */
export const MAX_ALERT_PATTERNS = 20;

/** A signal-name rule: an exact name, or a prefix when it ends with `*`. */
export interface AlertPattern {
  /** The pattern as configured (used in the cooldown key and the payload). */
  source: string;
  prefix: boolean;
  /** Name to compare: the pattern without its trailing `*`. */
  value: string;
}

/**
 * Parse ALERT_SIGNALS: comma-separated signal names. A trailing `*` matches a
 * prefix (`rea.*`, `honeypot:rea.*`). Throws on anything else, so a typo
 * stops the collector at startup instead of silently never alerting.
 */
export function parseAlertSignals(raw: string | undefined): AlertPattern[] {
  const items = (raw ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  if (items.length > MAX_ALERT_PATTERNS) {
    throw new Error(`ALERT_SIGNALS accepts at most ${MAX_ALERT_PATTERNS} patterns`);
  }
  return items.map((source) => {
    if (!/^[A-Za-z0-9_.:-]{1,64}\*?$/.test(source) || source === "*") {
      throw new Error(
        `ALERT_SIGNALS: invalid pattern ${JSON.stringify(source.slice(0, 80))} ` +
          "(use a signal name, optionally ending with * for a prefix)",
      );
    }
    const prefix = source.endsWith("*");
    return { source, prefix, value: prefix ? source.slice(0, -1) : source };
  });
}

/** Parse ALERT_MIN_CONFIDENCE (0..1, default 0). Throws when out of range. */
export function parseMinConfidence(raw: string | undefined): number {
  if (raw === undefined || raw.trim() === "") return 0;
  const n = Number(raw);
  if (!Number.isFinite(n) || n < 0 || n > 1)
    throw new Error("ALERT_MIN_CONFIDENCE must be a number from 0 to 1");
  return n;
}

/**
 * Alerts for an event carrying signals that match configured patterns with at
 * least `minConfidence` — one alert per distinct matching rule, so a rule that
 * is in cooldown never hides another rule that matched the same event. Each
 * alert lists only the signals of its own rule. One alert per site per rule
 * per cooldown window. The source-map canary has its own alert and is skipped.
 */
export function signalAlerts(
  ev: IncomingEvent,
  country: string | null,
  patterns: AlertPattern[],
  minConfidence: number,
): AlertMessage[] {
  if (patterns.length === 0) return [];
  // Insertion order = order of first match; at most one entry per pattern.
  const byRule = new Map<string, string[]>();
  for (const s of ev.signals) {
    if (s.name === CANARY_SIGNAL || s.confidence < minConfidence) continue;
    const p = patterns.find((x) => (x.prefix ? s.name.startsWith(x.value) : s.name === x.value));
    if (!p) continue;
    const names = byRule.get(p.source) ?? [];
    if (!byRule.has(p.source)) byRule.set(p.source, names);
    const name = clean(s.name, 48);
    if (name !== "" && !names.includes(name) && names.length < 12) names.push(name);
  }
  const site = clean(ev.siteId, 64);
  const path = clean(ev.path, 200);
  const out: AlertMessage[] = [];
  for (const [rule, names] of byRule) {
    out.push({
      // The configured pattern, not the signal name from the request: a client
      // cannot mint new cooldown keys by inventing names under a prefix.
      key: `signal:${ev.siteId}:${rule}`,
      text: `Antirea: signal ${names.join(", ")} on ${site} (${path}) — check the dashboard.`,
      extra: {
        event: "signal",
        site,
        path,
        rule,
        signals: names,
        source: ev.source === "honeypot" || ev.source === "server" ? ev.source : "client",
        country: country ? country : null,
      },
    });
  }
  return out;
}

/** Alert for a spike of detection events. */
export function spikeAlert(siteId: string, threshold: number, windowMin: number): AlertMessage {
  const site = clean(siteId, 64);
  return {
    key: "spike",
    text: `Antirea: ${threshold}+ detection events in ${windowMin} min (latest site: ${site}).`,
    extra: { event: "spike", site, window_min: windowMin, threshold },
  };
}
