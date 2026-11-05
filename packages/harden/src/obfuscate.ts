/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * JavaScript obfuscation preset for the UI code that must ship. Wraps
 * `javascript-obfuscator` (install it where you build:
 *   npm install -D javascript-obfuscator
 * ) with an anti-reverse-engineering configuration, including an optional
 * domain lock baked into the output.
 *
 * LIMITATIONS (honest): obfuscation is REVERSIBLE — it slows a human reader and
 * breaks naive copy-paste, but a determined attacker with time deobfuscates it.
 * It is a cost multiplier, not a lock. Heavy presets also enlarge and slow your
 * bundle; measure. Keep real logic server-side.
 */
export interface ObfuscateOptions {
  /** Bind the obfuscated code to these domains (javascript-obfuscator domainLock). */
  domainLock?: string[];
  /** 0..1 — how aggressive (affects size/speed). Default 0.75. */
  aggressiveness?: number;
  /** Deterministic output for a given seed. */
  seed?: number;
}

/** Build the javascript-obfuscator options object (pure; unit-testable). */
export function antiReObfuscatorOptions(o: ObfuscateOptions = {}): Record<string, unknown> {
  const a = Math.min(1, Math.max(0, o.aggressiveness ?? 0.75));
  return {
    compact: true,
    controlFlowFlattening: true,
    controlFlowFlatteningThreshold: a,
    deadCodeInjection: a > 0.5,
    deadCodeInjectionThreshold: 0.3,
    numbersToExpressions: true,
    simplify: true,
    stringArray: true,
    stringArrayEncoding: ["base64"],
    stringArrayThreshold: a,
    splitStrings: true,
    splitStringsChunkLength: 8,
    selfDefending: true,
    disableConsoleOutput: true,
    identifierNamesGenerator: "mangled",
    ...(o.domainLock && o.domainLock.length > 0
      ? { domainLock: o.domainLock, domainLockRedirectUrl: "about:blank" }
      : {}),
    ...(o.seed !== undefined ? { seed: o.seed } : {}),
  };
}

/** Obfuscate a string of JS. Lazy-loads javascript-obfuscator. */
export async function obfuscate(code: string, o: ObfuscateOptions = {}): Promise<string> {
  let mod: { obfuscate: (src: string, opts: unknown) => { getObfuscatedCode: () => string } };
  try {
    const name = "javascript-obfuscator";
    mod = (await import(name)) as unknown as typeof mod;
  } catch {
    throw new Error(
      "[harden] javascript-obfuscator is not installed. Run: npm install -D javascript-obfuscator",
    );
  }
  return mod.obfuscate(code, antiReObfuscatorOptions(o)).getObfuscatedCode();
}
