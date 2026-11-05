/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * antirea-guard — client-side reverse-engineering detection + telemetry.
 *
 * Drop-in usage (script tag):
 *   <script src="antirea-guard.iife.js"
 *           data-site-id="my-site"
 *           data-endpoint="https://collector.example.com/api/events"></script>
 *
 * Module usage:
 *   import { initGuard } from "@antirea/guard";
 *   initGuard({ siteId: "my-site", endpoint: "https://.../api/events" });
 *
 * LIMITATIONS: this hardens and reports. It does not make client code unreadable.
 * Proprietary logic belongs on the server. See PLAN.md §2.
 */
import { detectAutomation, setAutomationAsyncSink } from "./detectors/automation";
import { probeCdp } from "./detectors/cdp";
import { detectDevtools } from "./detectors/devtools";
import { detectIntegrity } from "./detectors/integrity";
import { detectRea } from "./detectors/rea";
import { Reporter } from "./reporter";
import type { GuardConfig, Signal } from "./types";

export type { GuardConfig, GuardMode, Signal, SignalType, GuardEvent } from "./types";
export { probeCdp } from "./detectors/cdp";
export { detectRea, readReaEnv } from "./detectors/rea";
export type { ReaEnv } from "./detectors/rea";
export { fetchProtected, importProtected } from "./protected";
export type { ProtectedLoaderConfig } from "./protected";

/** Best-effort dev-environment guess, so we don't disrupt development. */
function looksLikeDev(): boolean {
  const h = location.hostname;
  return h === "localhost" || h === "127.0.0.1" || h === "::1" || h.endsWith(".local") || h.endsWith(".test");
}

let started = false;

export function initGuard(cfg: GuardConfig): { stop: () => void } {
  if (started) return { stop: () => void 0 };
  if (!cfg.siteId || !cfg.endpoint) {
    // Misconfiguration must fail loud in dev, silent in prod.
    if (looksLikeDev()) throw new Error("[antirea] siteId and endpoint are required");
    return { stop: () => void 0 };
  }
  if (looksLikeDev() && !cfg.enableInDev) {
    return { stop: () => void 0 };
  }

  started = true;
  const reporter = new Reporter(cfg);
  const mode = cfg.mode ?? "silent";
  const pollMs = Math.max(500, cfg.pollMs ?? 1500);

  setAutomationAsyncSink((s: Signal) => handle([s]));

  function handle(signals: Signal[]): void {
    if (signals.length === 0) return;
    reporter.report(signals);
    applyMode(signals);
  }

  function applyMode(signals: Signal[]): void {
    if (mode === "silent") return;

    if (mode === "obstruct" || mode === "aggressive") {
      // Degrade the console so logged objects/sources are less useful.
      try {
        const noop = (): void => void 0;
        (["log", "debug", "info", "warn", "dir", "table"] as const).forEach((k) => {
          (console as unknown as Record<string, () => void>)[k] = noop;
        });
      } catch {
        /* ignore */
      }
    }

    if (mode === "aggressive") {
      // Opt-in only. Harms legitimate users + accessibility. We require a
      // high-confidence signal before halting, to limit collateral damage.
      const confident = signals.some((s) => s.confidence >= 0.7);
      if (confident) haltApp();
    }
  }

  function haltApp(): void {
    try {
      // Replace the document with a neutral notice. Accessible, no code leak.
      const html =
        '<!doctype html><html lang="he" dir="rtl"><head><meta charset="utf-8">' +
        '<meta name="viewport" content="width=device-width,initial-scale=1">' +
        '<title>גישה מוגבלת</title></head><body style="font-family:system-ui;' +
        'padding:2rem;max-width:40rem;margin:auto">' +
        "<h1>גישה מוגבלת</h1><p>הזוהתה פעילות ניתוח אוטומטי. אם לדעתך מדובר בטעות, " +
        "פנה לתמיכה.</p></body></html>";
      document.open();
      document.write(html);
      document.close();
    } catch {
      /* ignore */
    }
  }

  const cdpProbeEnabled = cfg.cdpProbe ?? true;
  const cdpIntervalMs = Math.max(1000, cfg.cdpIntervalMs ?? 4000);

  // Run one-shot detectors immediately.
  function sweep(): void {
    const signals: Signal[] = [
      ...detectAutomation(),
      ...detectRea(),
      ...detectDevtools(),
      ...detectIntegrity(),
    ];
    if (cdpProbeEnabled) signals.push(...probeCdp().signals);
    handle(signals);
  }

  sweep();
  // Live detectors (devtools/CDP can attach after load) poll on an interval.
  const interval = setInterval(() => {
    handle([...detectDevtools()]);
  }, pollMs);
  // CDP probe runs on a slower cadence (the debugger trap is intrusive).
  const cdpInterval = cdpProbeEnabled ? setInterval(() => handle(probeCdp().signals), cdpIntervalMs) : null;

  // Final flush on unload.
  const onHide = (): void => reporter.flush();
  window.addEventListener("visibilitychange", onHide);
  window.addEventListener("pagehide", onHide);

  return {
    stop(): void {
      clearInterval(interval);
      if (cdpInterval) clearInterval(cdpInterval);
      window.removeEventListener("visibilitychange", onHide);
      window.removeEventListener("pagehide", onHide);
      started = false;
    },
  };
}

/** Auto-init from the <script> tag's data-* attributes, if present. */
function autoInit(): void {
  const el = document.currentScript as HTMLScriptElement | null;
  if (!el) return;
  const siteId = el.getAttribute("data-site-id");
  const endpoint = el.getAttribute("data-endpoint");
  if (!siteId || !endpoint) return;
  initGuard({
    siteId,
    endpoint,
    mode: (el.getAttribute("data-mode") as GuardConfig["mode"]) ?? "silent",
    enableInDev: el.getAttribute("data-enable-in-dev") === "true",
  });
}

// IIFE builds auto-init; ESM consumers call initGuard() themselves.
if (typeof document !== "undefined" && document.currentScript) {
  autoInit();
}
