/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * Anti-tamper / integrity detectors.
 *
 * Detect whether core runtime functions have been hooked/overridden — a
 * common technique when an analysis tool instruments the page.
 *
 * LIMITATIONS: an attacker who controls the runtime can also hook the very
 * checks below. This is a tripwire, not a lock.
 */
import type { Signal } from "../types";

function sig(name: string, confidence: number, detail?: string): Signal {
  return { type: "integrity", name, confidence, detail };
}

/**
 * Native functions stringify to "[native code]". If a core function has been
 * replaced with a JS wrapper (instrumentation), toString no longer matches.
 */
function isNative(fn: unknown): boolean {
  try {
    return typeof fn === "function" && /\{\s*\[native code\]\s*\}/.test(Function.prototype.toString.call(fn));
  } catch {
    return false;
  }
}

export function detectIntegrity(): Signal[] {
  const out: Signal[] = [];

  // 1. Function.prototype.toString itself must be native; if it is hooked,
  //    every other isNative() check is unreliable — so flag it first.
  if (!isNative(Function.prototype.toString)) {
    out.push(sig("hook.Function.toString", 0.7));
  }

  // 2. Common instrumentation targets.
  const targets: Array<[string, unknown]> = [
    ["JSON.parse", JSON.parse],
    ["JSON.stringify", JSON.stringify],
    ["fetch", typeof fetch !== "undefined" ? fetch : undefined],
    ["XMLHttpRequest.open", XMLHttpRequest?.prototype?.open],
    ["Function.prototype.bind", Function.prototype.bind],
    ["console.log", console.log],
  ];
  for (const [name, fn] of targets) {
    if (fn !== undefined && !isNative(fn)) {
      // console.log is often legitimately wrapped by logging libs → low conf.
      const confidence = name === "console.log" ? 0.3 : 0.5;
      out.push(sig(`hook.${name}`, confidence));
    }
  }

  return out;
}
