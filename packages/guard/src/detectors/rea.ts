/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * REA-specific client fingerprint.
 *
 * Detects the DEFAULT Playwright launch profile REA uses for its scripted
 * browser scenarios, verified against morluto/rea
 * src/domain/browserScenarioValues.ts:
 *   headless: default true · locale default "en-US" · timezone default "UTC"
 *   color_scheme default "light" · reduced_motion default "reduce"
 *   viewport default 1280x720 · device_scale_factor default 1
 *   service_workers default "block"
 * plus Playwright's navigator.webdriver = true.
 *
 * No single marker is conclusive; the COMBINATION is distinctive. A real user
 * almost never has timezone UTC + reduced-motion reduce + exactly 1280x720 +
 * DPR 1 + webdriver all at once.
 *
 * HONESTY: an operator can override locale/timezone/viewport in the scenario
 * spec, which defeats those markers. This catches REA's DEFAULTS and raises
 * cost; it is not conclusive. The CDP source-read path is caught by cdp.ts, and
 * the source-map fetch by the server (honeypot). Evadability noted per marker.
 */
import type { Signal } from "../types";

/** Environment inputs, injectable for testability. */
export interface ReaEnv {
  webdriver: boolean;
  width: number;
  height: number;
  dpr: number;
  timezone: string;
  language: string;
  reducedMotion: boolean;
  colorSchemeDark: boolean;
}

export function readReaEnv(): ReaEnv {
  const mm = (q: string): boolean => {
    try {
      return typeof matchMedia === "function" && matchMedia(q).matches;
    } catch {
      return false;
    }
  };
  let tz = "";
  try {
    tz = Intl.DateTimeFormat().resolvedOptions().timeZone || "";
  } catch {
    /* ignore */
  }
  return {
    webdriver: (navigator as Navigator & { webdriver?: boolean }).webdriver === true,
    width: window.innerWidth,
    height: window.innerHeight,
    dpr: window.devicePixelRatio || 1,
    timezone: tz,
    language: navigator.language || "",
    reducedMotion: mm("(prefers-reduced-motion: reduce)"),
    colorSchemeDark: mm("(prefers-color-scheme: dark)"),
  };
}

/**
 * Score REA's default-launch markers. Returns a single aggregate signal when
 * enough markers align (keeps telemetry compact and avoids false positives
 * from any one marker).
 */
export function detectRea(env: ReaEnv = readReaEnv()): Signal[] {
  const markers: string[] = [];
  if (env.webdriver) markers.push("webdriver");
  if (env.width === 1280 && env.height === 720) markers.push("viewport1280x720");
  if (env.dpr === 1) markers.push("dpr1");
  if (env.timezone === "UTC") markers.push("tzUTC");
  if (env.language.toLowerCase().startsWith("en-us")) markers.push("localeEnUS");
  if (env.reducedMotion) markers.push("reducedMotion");
  if (!env.colorSchemeDark) markers.push("colorLight");

  // dpr1/localeEnUS/colorLight are common on their own; require a strong core.
  const strong = env.webdriver || (env.width === 1280 && env.height === 720);
  if (!strong || markers.length < 4) return [];

  // Confidence scales with how many of REA's defaults line up, and webdriver
  // (Playwright-controlled) pushes it high.
  let confidence = Math.min(0.9, 0.3 + markers.length * 0.08);
  if (env.webdriver && markers.length >= 5) confidence = Math.max(confidence, 0.85);

  return [
    {
      type: "automation",
      name: "rea.playwrightDefaults",
      confidence,
      detail: `${markers.length}/7: ${markers.join(",")}`,
    },
  ];
}
