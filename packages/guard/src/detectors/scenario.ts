/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * Scripted-scenario patches left in the page.
 *
 * REA's `capture_browser_scenario` blocks service workers by default
 * (`service_workers: "block"`). Verified against morluto/rea 6.8.0:
 *
 * - Connect mode (attaching to an existing browser) injects a main-world script
 *   via `Page.addScriptToEvaluateOnNewDocument` (src/browser/
 *   PlaywrightScenarioServiceWorkers.ts) that replaces
 *   `ServiceWorkerContainer.prototype.register`, tags the replacement with
 *   `Symbol.for("rea-service-workers-<uuid>")`, and defines a hidden global
 *   `rea-restore-<uuid>`. Those names are unique to REA → near-certain.
 * - Launch mode passes `serviceWorkers: "block"` to Playwright, which sets an
 *   own, non-native `register` on the `navigator.serviceWorker` instance
 *   (measured). Generic to Playwright's option, so lower confidence.
 *
 * Evadability: low for the REA markers (fixed prefixes; a fork could rename
 * them), medium for the Playwright patch (`service_workers: "allow"` removes
 * it). Prototype-level wrappers are deliberately ignored: frameworks such as
 * zone.js patch prototypes legitimately.
 */
import type { Signal } from "../types";

export interface ScenarioPatchEnv {
  /** Own property names of the global object. */
  globalNames: string[];
  /** Descriptions of own symbol keys on `ServiceWorkerContainer.prototype.register`. */
  registerSymbols: string[];
  /** `navigator.serviceWorker` has an OWN (instance) `register` property. */
  instanceRegister: boolean;
  /** That instance property is a native function. */
  instanceRegisterNative: boolean;
}

const UUID = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";
const REA_RESTORE = new RegExp(`^rea-restore-${UUID}$`, "i");
const REA_SW_MARKER = new RegExp(`^rea-service-workers-${UUID}$`, "i");

function isNative(fn: unknown): boolean {
  try {
    return (
      typeof fn === "function" && /\{\s*\[native code\]\s*\}\s*$/.test(Function.prototype.toString.call(fn))
    );
  } catch {
    return false;
  }
}

/** Read the live page state. Never throws; unsupported pieces read as empty. */
export function readScenarioPatchEnv(): ScenarioPatchEnv {
  const env: ScenarioPatchEnv = {
    globalNames: [],
    registerSymbols: [],
    instanceRegister: false,
    instanceRegisterNative: true,
  };
  try {
    env.globalNames = Object.getOwnPropertyNames(globalThis);
  } catch {
    /* ignore */
  }
  try {
    const ctor = (globalThis as { ServiceWorkerContainer?: { prototype: { register?: unknown } } })
      .ServiceWorkerContainer;
    const reg = ctor?.prototype.register;
    if (typeof reg === "function") {
      env.registerSymbols = Object.getOwnPropertySymbols(reg).map((s) => s.description ?? "");
    }
  } catch {
    /* ignore */
  }
  try {
    const sw = (navigator as Navigator & { serviceWorker?: object }).serviceWorker;
    if (sw && Object.prototype.hasOwnProperty.call(sw, "register")) {
      env.instanceRegister = true;
      env.instanceRegisterNative = isNative((sw as { register?: unknown }).register);
    }
  } catch {
    /* ignore */
  }
  return env;
}

/** Detect REA's (and Playwright's) service-worker blocking patches. */
export function detectScenarioPatches(env: ScenarioPatchEnv = readScenarioPatchEnv()): Signal[] {
  const reaMarker =
    env.globalNames.some((n) => REA_RESTORE.test(n)) ||
    env.registerSymbols.some((d) => REA_SW_MARKER.test(d));
  if (reaMarker) {
    return [{ type: "automation", name: "rea.scenarioSwPolicy", confidence: 0.99 }];
  }
  if (env.instanceRegister && !env.instanceRegisterNative) {
    return [{ type: "automation", name: "automation.swBlockPatch", confidence: 0.7 }];
  }
  return [];
}
