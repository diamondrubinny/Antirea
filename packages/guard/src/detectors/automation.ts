/**
 * Automation / headless-browser detectors.
 *
 * Targets the Playwright/Puppeteer-style path used by analysis tools that
 * drive a scripted browser (REA's "Playwright scenarios" path).
 *
 * HONESTY: every signal here is heuristic and evadable. A determined operator
 * can spoof navigator.webdriver, patch the UA, and inject fake plugins. These
 * raise the cost of automated harvesting; they do not prevent it. The CDP
 * "attach to a user-launched browser" path is NOT caught here (see cdp.ts).
 */
import type { Signal } from "../types";

function sig(name: string, confidence: number, detail?: string): Signal {
  return { type: "automation", name, confidence, detail };
}

export function detectAutomation(): Signal[] {
  const out: Signal[] = [];
  const nav = navigator as Navigator & { webdriver?: boolean };

  // 1. The standard automation flag. Evadable: can be deleted/overridden.
  if (nav.webdriver === true) out.push(sig("navigator.webdriver", 0.8));

  // 2. Headless UA markers. Evadable: UA is trivially spoofed.
  const ua = navigator.userAgent || "";
  if (/HeadlessChrome/i.test(ua)) out.push(sig("ua.headlessChrome", 0.7));
  if (/PhantomJS|SlimerJS/i.test(ua)) out.push(sig("ua.legacyHeadless", 0.6));

  // 3. Real Chrome exposes window.chrome; many headless contexts do not.
  //    Evadable + false-positive-prone (non-Chrome browsers). Low confidence.
  const w = window as Window & { chrome?: unknown };
  const isChromeUa = /Chrome\//.test(ua) && !/Edg|OPR/.test(ua);
  if (isChromeUa && typeof w.chrome === "undefined") {
    out.push(sig("window.chrome.missing", 0.4));
  }

  // 4. Empty plugin/mimeType lists on a desktop Chrome are suspicious.
  if (isChromeUa && navigator.plugins && navigator.plugins.length === 0) {
    out.push(sig("navigator.plugins.empty", 0.3));
  }

  // 5. Language list empty/inconsistent.
  if (!navigator.languages || navigator.languages.length === 0) {
    out.push(sig("navigator.languages.empty", 0.3));
  }

  // 6. Puppeteer/Playwright injected globals (best-effort; names change).
  const globals = Object.getOwnPropertyNames(window);
  for (const marker of ["__playwright", "__puppeteer", "_phantom", "callPhantom", "__nightmare"]) {
    if (globals.includes(marker)) out.push(sig(`global.${marker}`, 0.7));
  }

  // 7. Permissions API inconsistency: headless often reports "denied"
  //    for notifications while Notification.permission is "default".
  try {
    const perm = (navigator as Navigator & {
      permissions?: { query: (d: { name: PermissionName }) => Promise<PermissionStatus> };
    }).permissions;
    if (perm && typeof Notification !== "undefined") {
      perm
        .query({ name: "notifications" as PermissionName })
        .then((status) => {
          if (Notification.permission === "default" && status.state === "denied") {
            // Reported asynchronously via the live callback registered by index.ts.
            automationAsyncSink?.(sig("permissions.inconsistent", 0.5));
          }
        })
        .catch(() => void 0);
    }
  } catch {
    /* ignore */
  }

  return out;
}

/** Sink for async-detected automation signals, wired by index.ts. */
export let automationAsyncSink: ((s: Signal) => void) | undefined;
export function setAutomationAsyncSink(fn: (s: Signal) => void): void {
  automationAsyncSink = fn;
}
