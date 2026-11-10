/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * Request scoring for the server-side honeypot.
 *
 * Scores an incoming HTTP request for how much it looks like automated code
 * harvesting (headless browsers, scripted fetchers) rather than a real user's
 * browser loading a page.
 *
 * LIMITATIONS: this inspects only what the client sends (UA + headers). A CDP
 * client attached to a real, user-launched browser sends real-browser headers
 * and will NOT score high here — that path cannot be caught at the asset layer.
 * This catches bundle-harvesting fetchers, not in-browser CDP source reads.
 */

import { DEFAULT_COMPILED_PACK, matches, type CompiledSignaturePack } from "./signatures.js";

export interface ScoreInput {
  userAgent: string;
  /** Lower-cased header map. */
  headers: Record<string, string | string[] | undefined>;
  /** Request path. */
  path: string;
  /**
   * Path prefixes of source-map canaries: URLs that are only ever referenced
   * from a `sourceMappingURL` comment, never linked. Browsers do not fetch
   * source maps unless DevTools is open, so any hit is analysis.
   */
  canaryPaths?: string[];
}

export interface ScoreResult {
  /** 0..1 — higher means more likely automated analysis. */
  score: number;
  /** Human/machine-readable reasons that contributed. */
  reasons: string[];
}

function header(h: ScoreInput["headers"], name: string): string {
  const v = h[name.toLowerCase()];
  return Array.isArray(v) ? v.join(",") : (v ?? "");
}

/**
 * Parse the client attestation header (X-Antirea-Attest). FORGEABLE — treated
 * only as one input, never as the sole decision. An honest client that
 * detected CDP reports it here; an attacker can lie, which is why independent
 * server-side signals below still run.
 */
function parseAttestation(raw: string): { cdp?: boolean; confidence?: number } {
  try {
    const o = JSON.parse(raw) as { cdp?: unknown; c?: unknown };
    return {
      cdp: typeof o.cdp === "boolean" ? o.cdp : undefined,
      confidence: typeof o.c === "number" ? o.c : undefined,
    };
  } catch {
    return {};
  }
}

/**
 * True when `path` lies under the directory `prefix`. The prefix is treated as
 * a directory ("/maps" means "/maps/…"), so "/maps-ui/app.js" does not match.
 */
export function isUnderPrefix(path: string, prefix: string): boolean {
  if (prefix === "" || prefix === "/") return false;
  const dir = prefix.endsWith("/") ? prefix : `${prefix}/`;
  return path.startsWith(dir);
}

/**
 * Score one request. `signatures` is a compiled signature pack (see
 * signatures.ts); the built-in pack is used when omitted.
 */
export function scoreRequest(
  input: ScoreInput,
  signatures: CompiledSignaturePack = DEFAULT_COMPILED_PACK,
): ScoreResult {
  const w = signatures.pack.weights;
  const re = signatures.re;
  const reasons: string[] = [];
  let score = 0;
  const ua = input.userAgent || "";
  const h = input.headers;

  // Source-map canary: an unlinked map URL that only a source-map consumer
  // (REA's fetcher, an open DevTools, a harvesting script) would request.
  if (input.canaryPaths?.some((p) => isUnderPrefix(input.path, p))) {
    score += w["canary.sourceMap"];
    reasons.push("canary.sourceMap");
  }

  // 0. Client attestation: if an honest client reported a CDP/inspector
  //    attach, that is a strong signal to serve a decoy. (Forgeable; see note.)
  const attestRaw = header(h, "x-antirea-attest");
  if (attestRaw) {
    const att = parseAttestation(attestRaw);
    if (att.cdp === true) {
      score += w["attest.cdp"];
      reasons.push("attest.cdp");
    }
  }

  // REA source-map fetch signature (verified against morluto/rea
  // src/browser/WebSourceMapFetcher.ts). REA's source-map fetcher sends a
  // distinctive Accept, no cookie, and no referer. No browser emits
  // "application/source-map+json" — this token alone is a near-certain marker.
  const acceptHdr = header(h, "accept");
  if (matches(re.sourceMapAccept, acceptHdr)) {
    score += w["rea.sourceMapAccept"];
    reasons.push("rea.sourceMapAccept");
  } else if (
    /\.map(\?|$)/i.test(input.path) &&
    !header(h, "cookie") &&
    !header(h, "referer") &&
    !header(h, "sec-fetch-dest")
  ) {
    // A .map fetched with no cookie, no referer, and no Sec-Fetch metadata
    // matches REA's fetcher shape (credentials:"omit", referrerPolicy:
    // "no-referrer"). Lower confidence: a few CLIs look similar.
    score += w["rea.sourceMapShape"];
    reasons.push("rea.sourceMapShape");
  }

  // 1. Headless / non-browser clients in the UA.
  const headlessUa = matches(re.headlessUa, ua);
  if (headlessUa) {
    score += w["ua.headless"];
    reasons.push("ua.headless");
  }
  if (matches(re.automationUa, ua)) {
    score += w["ua.automation"];
    reasons.push("ua.automation");
  }
  if (ua.trim() === "") {
    score += w["ua.empty"];
    reasons.push("ua.empty");
  }
  // Headless Chromium also brands itself in Client Hints; count it only when
  // the UA did not already say so (e.g. a UA override left the hint intact).
  if (!headlessUa && matches(re.headlessClientHint, header(h, "sec-ch-ua"))) {
    score += w["ua.headlessClientHint"];
    reasons.push("ua.headlessClientHint");
  }

  // 2. Real browsers send Sec-Fetch-* and Accept for script requests.
  //    Their absence on a .js request is a strong harvesting signal.
  const isScript = /\.(js|mjs|map)(\?|$)/i.test(input.path);
  if (isScript) {
    if (!header(h, "sec-fetch-dest") && !header(h, "sec-fetch-mode")) {
      score += w["missing.secFetch"];
      reasons.push("missing.secFetch");
    }
    if (!header(h, "accept")) {
      score += w["missing.accept"];
      reasons.push("missing.accept");
    }
    // Harvesters often request a .map directly — a real app rarely does.
    if (/\.map(\?|$)/i.test(input.path)) {
      score += w["request.sourceMap"];
      reasons.push("request.sourceMap");
    }
  }

  // Built-in fetch of a server-side runtime (Node/undici): UA "node", only
  // Sec-Fetch-Mode (browsers send Site, Mode and Dest together, or none), and
  // Accept-Language "*". These markers all come from the same source — the
  // runtime's defaults — so they count as ONE piece of evidence, capped below
  // the default threshold: a legitimate server-side client fetching a script
  // is reported, not decoyed, unless an independent signal (a source-map
  // request, REA's Accept token, behaviour) corroborates it. A partial
  // Sec-Fetch set on a request whose UA claims Chromium is left to
  // forgery.noSecFetch below, so a proxy that strips headers from a real
  // browser is not penalised twice.
  const claimsChromium = /Chrome\/(\d+)/.test(ua) && !/Edge\//.test(ua);
  const runtimeUa = matches(re.runtimeFetchUa, ua.trim());
  const partialSecFetch =
    !claimsChromium &&
    header(h, "sec-fetch-mode") !== "" &&
    !header(h, "sec-fetch-site") &&
    !header(h, "sec-fetch-dest");
  const languageWildcard = header(h, "accept-language").trim() === "*";
  if (runtimeUa) reasons.push("ua.runtimeFetch");
  if (partialSecFetch) reasons.push("forgery.partialSecFetch");
  if (languageWildcard) reasons.push("acceptLanguage.wildcard");
  const runtimeMarkers = [runtimeUa, partialSecFetch, languageWildcard].filter(Boolean).length;
  if (runtimeMarkers > 0) {
    score += runtimeUa || runtimeMarkers >= 2 ? w["runtimeFetch.combined"] : w["runtimeFetch.single"];
  }

  // 3. No Accept-Language is uncommon for real browsers.
  if (!header(h, "accept-language")) {
    score += w["missing.acceptLanguage"];
    reasons.push("missing.acceptLanguage");
  }

  // 4. Header FORGERY via internal inconsistency. A spoofed User-Agent that
  //    claims a modern Chromium browser should also send Client Hints
  //    (sec-ch-ua) and Sec-Fetch metadata. Their absence means the UA is
  //    likely forged — detecting the lie without trusting the UA.
  const claimsModernChromium = /Chrome\/(\d+)/.test(ua) && !/Edge\//.test(ua);
  if (claimsModernChromium) {
    const major = Number((/Chrome\/(\d+)/.exec(ua) ?? [])[1] ?? 0);
    if (major >= 90 && !header(h, "sec-ch-ua")) {
      score += w["forgery.noClientHints"];
      reasons.push("forgery.noClientHints");
    }
    if (major >= 90 && !header(h, "sec-fetch-site")) {
      score += w["forgery.noSecFetch"];
      reasons.push("forgery.noSecFetch");
    }
  }
  // A real browser's Accept for a navigation includes text/html; tools send */*.
  // Browser subresource requests (fetch/XHR, images, styles) legitimately send
  // */* and declare a non-document Sec-Fetch-Dest, so they are not navigations
  // (measured: Chromium fetch() sends "accept: */*", "sec-fetch-dest: empty").
  const accept = header(h, "accept");
  const fetchDest = header(h, "sec-fetch-dest");
  const maybeNavigation = fetchDest === "" || fetchDest === "document";
  if (accept === "*/*" && !isScript && maybeNavigation) {
    score += w["accept.wildcard"];
    reasons.push("accept.wildcard");
  }

  // Clamp.
  score = Math.min(1, score);
  return { score, reasons };
}
