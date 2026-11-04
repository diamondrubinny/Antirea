/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * DevTools / inspector detectors.
 *
 * HONESTY: these are classic heuristics. A CDP client (REA's main browser
 * path) can read source and network WITHOUT a visible DevTools window and
 * can blackbox/suppress these traps. Treat as deterrence + telemetry only.
 */
import type { Signal } from "../types";

function sig(name: string, confidence: number, detail?: string): Signal {
  return { type: "devtools", name, confidence, detail };
}

/**
 * Timing trap: a `debugger` statement pauses only when an inspector is
 * attached and "pause on exceptions"/stepping is engaged. A large delta
 * across the statement suggests an attached, paused debugger.
 *
 * Disabled unless explicitly requested, because a stray `debugger` is itself
 * a code smell and can annoy. Kept here for completeness.
 */
export function detectDebuggerPause(thresholdMs = 120): Signal[] {
  const start = performance.now();
  // eslint-disable-next-line no-debugger
  debugger;
  const delta = performance.now() - start;
  return delta > thresholdMs ? [sig("debugger.pause", 0.6, `${Math.round(delta)}ms`)] : [];
}

/**
 * Docked-devtools heuristic via viewport gap. False positives with zoom,
 * browser chrome, extensions. Low confidence by design.
 */
export function detectViewportGap(): Signal[] {
  const wGap = window.outerWidth - window.innerWidth;
  const hGap = window.outerHeight - window.innerHeight;
  // Generous thresholds to reduce false positives.
  if (wGap > 220 || hGap > 220) {
    return [sig("viewport.gap", 0.25, `${wGap}x${hGap}`)];
  }
  return [];
}

/**
 * Getter-trap: when an object is logged and DevTools is OPEN, the console
 * eagerly reads accessors (e.g. toString / a defined getter) to render a
 * preview. We log such an object off-screen and watch whether the accessor
 * fires. Evadable; harmless if it misfires.
 */
export function detectConsoleGetter(): Signal[] {
  let accessed = false;
  const bait = Object.defineProperty({}, "id", {
    get() {
      accessed = true;
      return "";
    },
    enumerable: true,
  });
  // The read only happens if an inspector renders the logged value.
  // We keep it quiet: log then immediately clear.
  try {
    console.debug(bait);
    // eslint-disable-next-line no-console
    (console as Console).clear?.();
  } catch {
    /* ignore */
  }
  return accessed ? [sig("console.getterRead", 0.5)] : [];
}

export function detectDevtools(opts?: { includeDebugger?: boolean }): Signal[] {
  const out: Signal[] = [];
  out.push(...detectViewportGap());
  out.push(...detectConsoleGetter());
  if (opts?.includeDebugger) out.push(...detectDebuggerPause());
  return out;
}
