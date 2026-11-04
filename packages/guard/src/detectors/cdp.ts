/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * CDP / inspector-attach detectors.
 *
 * Targets the hardest path: an analysis tool attached to a user-launched
 * browser via the Chrome DevTools Protocol (REA's main browser capability),
 * which reads script source directly from the engine and bypasses page JS.
 *
 * WHY THIS CAN STILL FIRE: REA's passive capture ENABLES the CDP `Debugger`
 * domain and (per its own docs) does NOT suppress `debugger`-statement pauses.
 * So a `debugger`-timing probe detects the *default* passive attach.
 *
 * HONESTY — this is defeated by:
 *   - an operator who disables "pause on debugger" / blackboxes the script,
 *   - patching the page before it runs.
 * It raises cost and catches default/honest tooling. It is NOT a block.
 */
import type { Signal } from "../types";

function sig(name: string, confidence: number, detail?: string): Signal {
  return { type: "devtools", name, confidence, detail };
}

export interface CdpVerdict {
  detected: boolean;
  /** 0..1 aggregate confidence. */
  confidence: number;
  signals: Signal[];
  /** Max observed pause across the debugger probe, ms. */
  maxPauseMs: number;
}

/**
 * Debugger-timing probe. When an inspector with the Debugger domain is
 * attached and pausing, execution stops at `debugger;` and the measured delta
 * spikes. With no inspector attached this is a near-zero-cost no-op, so it is
 * safe for real users.
 */
function probeDebuggerPause(iterations: number): { maxDelta: number } {
  let maxDelta = 0;
  for (let i = 0; i < iterations; i++) {
    const t0 = performance.now();
    // eslint-disable-next-line no-debugger
    debugger;
    const d = performance.now() - t0;
    if (d > maxDelta) maxDelta = d;
  }
  return { maxDelta };
}

/**
 * Error.stack getter-trap. When an inspector/CDP console serializes a logged
 * Error for its preview, it reads `.stack`, firing our getter. No attached
 * console → getter never fires.
 */
function probeStackGetter(): boolean {
  let read = false;
  try {
    const e = new Error("");
    Object.defineProperty(e, "stack", {
      configurable: true,
      get() {
        read = true;
        return "";
      },
    });
    // Log off to the side, then clear so real users see nothing.
    console.debug(e);
    (console as Console).clear?.();
  } catch {
    /* ignore */
  }
  return read;
}

/**
 * toString-count trap on a RegExp. DevTools/CDP console calls toString when
 * rendering a logged RegExp preview. Multiple reads strongly suggest an
 * attached, rendering console.
 */
function probeRegExpToString(): boolean {
  let count = 0;
  try {
    const re = /antirea-probe/;
    (re as RegExp & { toString: () => string }).toString = function () {
      count += 1;
      return "antirea-probe";
    };
    console.debug("%o", re);
    (console as Console).clear?.();
  } catch {
    /* ignore */
  }
  return count > 0;
}

export interface CdpProbeOptions {
  /** Run the (intentionally intrusive) debugger-timing probe. Default true. */
  useDebugger?: boolean;
  /** Pause threshold in ms to count as "attached + pausing". Default 100. */
  thresholdMs?: number;
  /** Debugger probe iterations. Default 1. */
  iterations?: number;
}

export function probeCdp(opts: CdpProbeOptions = {}): CdpVerdict {
  const useDebugger = opts.useDebugger ?? true;
  const thresholdMs = opts.thresholdMs ?? 100;
  const iterations = Math.max(1, opts.iterations ?? 1);

  const signals: Signal[] = [];
  let confidence = 0;
  let maxPauseMs = 0;

  if (useDebugger) {
    const { maxDelta } = probeDebuggerPause(iterations);
    maxPauseMs = maxDelta;
    if (maxDelta > thresholdMs) {
      // Strong: a paused debugger is hard to explain otherwise.
      signals.push(sig("cdp.debuggerPause", 0.8, `${Math.round(maxDelta)}ms`));
      confidence = Math.max(confidence, 0.8);
    }
  }

  if (probeStackGetter()) {
    signals.push(sig("cdp.stackGetter", 0.6));
    confidence = Math.max(confidence, 0.6);
  }

  if (probeRegExpToString()) {
    signals.push(sig("cdp.regexpToString", 0.55));
    confidence = Math.max(confidence, 0.55);
  }

  return { detected: signals.length > 0, confidence, signals, maxPauseMs };
}
