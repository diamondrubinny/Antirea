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
    key: `canary:${site}`,
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

/** Alert for a spike of detection events. */
export function spikeAlert(siteId: string, threshold: number, windowMin: number): AlertMessage {
  const site = clean(siteId, 64);
  return {
    key: "spike",
    text: `Antirea: ${threshold}+ detection events in ${windowMin} min (latest site: ${site}).`,
    extra: { event: "spike", site, window_min: windowMin, threshold },
  };
}
