/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * Signature pack: the values of the request scorer that change when an
 * analysis tool changes — weights and match patterns — as plain data.
 *
 * The scoring LOGIC stays in code (scoring.ts). A pack only tunes it, so a
 * signature update is a reviewed JSON change, not a code release. A pack is
 * data, never code: it is validated strictly, and the library never fetches
 * one over the network — you load it from a file you control and pass it in.
 *
 * Patterns are regular expressions. Only load packs you trust: a hostile
 * pattern could be slow on purpose (ReDoS). Pattern and input lengths are
 * capped and the obvious nested-quantifier shape is rejected, but neither is
 * proof of safety.
 */

export interface SignatureWeights {
  "canary.sourceMap": number;
  "attest.cdp": number;
  "rea.sourceMapAccept": number;
  "rea.sourceMapShape": number;
  "ua.headless": number;
  "ua.automation": number;
  "ua.empty": number;
  "ua.headlessClientHint": number;
  "missing.secFetch": number;
  "missing.accept": number;
  "request.sourceMap": number;
  /** Combined runtime-fetch fingerprint (runtime UA, or two or more markers). */
  "runtimeFetch.combined": number;
  /** A single non-UA runtime marker. */
  "runtimeFetch.single": number;
  "missing.acceptLanguage": number;
  "forgery.noClientHints": number;
  "forgery.noSecFetch": number;
  "accept.wildcard": number;
}

export interface SignaturePatterns {
  /** Non-browser or headless clients, matched against the User-Agent. */
  headlessUa: string;
  /** Built-in fetch of a server-side runtime, matched against the trimmed User-Agent. */
  runtimeFetchUa: string;
  /** Automation library names, matched against the User-Agent. */
  automationUa: string;
  /** Media-type token of an analysis tool's source-map fetch, matched against Accept. */
  sourceMapAccept: string;
  /** Headless brand, matched against the sec-ch-ua Client Hint. */
  headlessClientHint: string;
}

export interface SignaturePack {
  /** Pack format version. */
  format: 1;
  /** Free-form pack version, e.g. a date. */
  version: string;
  /** REA release the pack was verified against. */
  reaVersion: string;
  weights: SignatureWeights;
  patterns: SignaturePatterns;
}

/** A partial pack: any subset of weights and patterns overrides the defaults. */
export interface SignaturePackInput {
  format: 1;
  version: string;
  reaVersion?: string;
  weights?: Partial<SignatureWeights>;
  patterns?: Partial<SignaturePatterns>;
}

/** Built-in pack, verified against REA 6.8.0 (see docs/REA-SIGNATURES.md). */
export const DEFAULT_SIGNATURE_PACK: SignaturePack = Object.freeze({
  format: 1,
  version: "2026-11-10",
  reaVersion: "6.8.0",
  weights: Object.freeze({
    "canary.sourceMap": 1,
    "attest.cdp": 0.7,
    "rea.sourceMapAccept": 0.85,
    "rea.sourceMapShape": 0.5,
    "ua.headless": 0.6,
    "ua.automation": 0.4,
    "ua.empty": 0.4,
    "ua.headlessClientHint": 0.6,
    "missing.secFetch": 0.3,
    "missing.accept": 0.2,
    "request.sourceMap": 0.3,
    "runtimeFetch.combined": 0.6,
    "runtimeFetch.single": 0.2,
    "missing.acceptLanguage": 0.15,
    "forgery.noClientHints": 0.4,
    "forgery.noSecFetch": 0.25,
    "accept.wildcard": 0.2,
  }),
  patterns: Object.freeze({
    headlessUa:
      "HeadlessChrome|PhantomJS|SlimerJS|Nightmare|Electron\\/|python-requests|node-fetch|axios\\/|curl\\/|wget\\/|Go-http-client|Java\\/|okhttp|Scrapy",
    runtimeFetchUa: "^(?:node|undici)(?:\\/[\\w.-]+)?$|^(?:Bun|Deno)\\/\\d",
    automationUa: "playwright|puppeteer|webdriver|selenium|headless",
    sourceMapAccept: "application\\/source-map\\+json",
    headlessClientHint: "HeadlessChrome",
  }),
}) as SignaturePack;

/** Longest accepted pattern source. */
export const MAX_PATTERN_LENGTH = 512;

/**
 * Longest header value handed to a pack pattern. Real User-Agent, Accept and
 * Client-Hint values are far shorter; the cap bounds how much work a slow
 * pattern can be made to do by an oversized, client-controlled header.
 */
export const MAX_MATCH_INPUT = 1024;

/**
 * A quantified group that itself contains a quantifier — `(a+)+`, `(\w*)*`,
 * `(?:x+){2,}` — the classic shape of catastrophic backtracking. This is a
 * heuristic: it catches the common mistake, not every slow pattern.
 */
const NESTED_QUANTIFIER = /\((?:[^()\\]|\\.)*[+*](?:[^()\\]|\\.)*\)(?:[+*]|\{\d)/;

/** A pack with its patterns compiled, ready for the scorer. */
export interface CompiledSignaturePack {
  pack: SignaturePack;
  re: Record<keyof SignaturePatterns, RegExp>;
}

function fail(message: string): never {
  throw new Error(`[antirea] invalid signature pack: ${message}`);
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return (
    typeof v === "object" && v !== null && !Array.isArray(v) && Object.getPrototypeOf(v) === Object.prototype
  );
}

/**
 * Validate a (partial) pack and merge it over the built-in defaults. Throws
 * with a specific message on anything unexpected: unknown keys, weights
 * outside 0..1, or patterns that are too long or do not compile.
 */
export function loadSignaturePack(input: unknown): CompiledSignaturePack {
  if (!isPlainObject(input)) fail("expected an object");
  const allowed = ["format", "version", "reaVersion", "weights", "patterns", "$comment"];
  for (const k of Object.keys(input)) if (!allowed.includes(k)) fail(`unknown key "${k}"`);
  if (input.format !== 1) fail(`unsupported format ${JSON.stringify(input.format)} (expected 1)`);
  if (typeof input.version !== "string" || input.version === "" || input.version.length > 64) {
    fail("version must be a non-empty string of at most 64 characters");
  }
  if (
    input.reaVersion !== undefined &&
    (typeof input.reaVersion !== "string" || input.reaVersion.length > 32)
  ) {
    fail("reaVersion must be a string of at most 32 characters");
  }

  const weights: SignatureWeights = { ...DEFAULT_SIGNATURE_PACK.weights };
  if (input.weights !== undefined) {
    if (!isPlainObject(input.weights)) fail("weights must be an object");
    for (const [k, v] of Object.entries(input.weights)) {
      if (!Object.prototype.hasOwnProperty.call(DEFAULT_SIGNATURE_PACK.weights, k))
        fail(`unknown weight "${k}"`);
      if (typeof v !== "number" || !Number.isFinite(v) || v < 0 || v > 1) {
        fail(`weight "${k}" must be a number between 0 and 1`);
      }
      weights[k as keyof SignatureWeights] = v;
    }
  }

  const patterns: SignaturePatterns = { ...DEFAULT_SIGNATURE_PACK.patterns };
  if (input.patterns !== undefined) {
    if (!isPlainObject(input.patterns)) fail("patterns must be an object");
    for (const [k, v] of Object.entries(input.patterns)) {
      if (!Object.prototype.hasOwnProperty.call(DEFAULT_SIGNATURE_PACK.patterns, k))
        fail(`unknown pattern "${k}"`);
      if (typeof v !== "string" || v === "" || v.length > MAX_PATTERN_LENGTH) {
        fail(`pattern "${k}" must be a non-empty string of at most ${MAX_PATTERN_LENGTH} characters`);
      }
      patterns[k as keyof SignaturePatterns] = v;
    }
  }

  const re = {} as Record<keyof SignaturePatterns, RegExp>;
  for (const k of Object.keys(patterns) as Array<keyof SignaturePatterns>) {
    try {
      re[k] = new RegExp(patterns[k], "i");
    } catch {
      fail(`pattern "${k}" is not a valid regular expression`);
    }
    if (NESTED_QUANTIFIER.test(patterns[k])) {
      fail(`pattern "${k}" nests a quantifier inside a quantified group (catastrophic backtracking risk)`);
    }
    // A pattern that matches the empty string would flag every request.
    if (re[k].test("")) fail(`pattern "${k}" matches the empty string`);
  }

  return {
    pack: {
      format: 1,
      version: input.version,
      reaVersion: (input.reaVersion as string | undefined) ?? DEFAULT_SIGNATURE_PACK.reaVersion,
      weights,
      patterns,
    },
    re,
  };
}

/** Test a pack pattern against a client-controlled value, length-capped. */
export function matches(re: RegExp, value: string): boolean {
  return re.test(value.length > MAX_MATCH_INPUT ? value.slice(0, MAX_MATCH_INPUT) : value);
}

/** The built-in pack, compiled once. */
export const DEFAULT_COMPILED_PACK: CompiledSignaturePack = loadSignaturePack(DEFAULT_SIGNATURE_PACK);
