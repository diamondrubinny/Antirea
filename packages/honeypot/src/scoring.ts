/**
 * Request scoring for the server-side honeypot.
 *
 * Scores an incoming HTTP request for how much it looks like automated code
 * harvesting (headless browsers, scripted fetchers) rather than a real user's
 * browser loading a page.
 *
 * HONESTY: this inspects only what the client sends (UA + headers). A CDP
 * client attached to a real, user-launched browser sends real-browser headers
 * and will NOT score high here — that path cannot be caught at the asset layer.
 * This catches bundle-harvesting fetchers, not in-browser CDP source reads.
 */

export interface ScoreInput {
  userAgent: string;
  /** Lower-cased header map. */
  headers: Record<string, string | string[] | undefined>;
  /** Request path. */
  path: string;
}

export interface ScoreResult {
  /** 0..1 — higher means more likely automated analysis. */
  score: number;
  /** Human/machine-readable reasons that contributed. */
  reasons: string[];
}

const HEADLESS_UA = /HeadlessChrome|PhantomJS|SlimerJS|Nightmare|Electron\/|python-requests|node-fetch|axios\/|curl\/|wget\/|Go-http-client|Java\/|okhttp|Scrapy/i;

/** Known analysis/automation libraries sometimes present in UA or headers. */
const AUTOMATION_HINTS = /playwright|puppeteer|webdriver|selenium|headless/i;

function header(h: ScoreInput["headers"], name: string): string {
  const v = h[name.toLowerCase()];
  return Array.isArray(v) ? v.join(",") : v ?? "";
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

export function scoreRequest(input: ScoreInput): ScoreResult {
  const reasons: string[] = [];
  let score = 0;
  const ua = input.userAgent || "";
  const h = input.headers;

  // 0. Client attestation: if an honest client reported a CDP/inspector
  //    attach, that is a strong signal to serve a decoy. (Forgeable; see note.)
  const attestRaw = header(h, "x-antirea-attest");
  if (attestRaw) {
    const att = parseAttestation(attestRaw);
    if (att.cdp === true) {
      score += 0.7;
      reasons.push("attest.cdp");
    }
  }

  // REA source-map fetch signature (verified against morluto/rea
  // src/browser/WebSourceMapFetcher.ts). REA's source-map fetcher sends a
  // distinctive Accept, no cookie, and no referer. No browser emits
  // "application/source-map+json" — this token alone is a near-certain marker.
  const acceptHdr = header(h, "accept");
  if (/application\/source-map\+json/i.test(acceptHdr)) {
    score += 0.85;
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
    score += 0.5;
    reasons.push("rea.sourceMapShape");
  }

  // 1. Headless / non-browser clients in the UA.
  if (HEADLESS_UA.test(ua)) {
    score += 0.6;
    reasons.push("ua.headless");
  }
  if (AUTOMATION_HINTS.test(ua)) {
    score += 0.4;
    reasons.push("ua.automation");
  }
  if (ua.trim() === "") {
    score += 0.4;
    reasons.push("ua.empty");
  }

  // 2. Real browsers send Sec-Fetch-* and Accept for script requests.
  //    Their absence on a .js request is a strong harvesting signal.
  const isScript = /\.(js|mjs|map)(\?|$)/i.test(input.path);
  if (isScript) {
    if (!header(h, "sec-fetch-dest") && !header(h, "sec-fetch-mode")) {
      score += 0.3;
      reasons.push("missing.secFetch");
    }
    if (!header(h, "accept")) {
      score += 0.2;
      reasons.push("missing.accept");
    }
    // Harvesters often request a .map directly — a real app rarely does.
    if (/\.map(\?|$)/i.test(input.path)) {
      score += 0.3;
      reasons.push("request.sourceMap");
    }
  }

  // 3. No Accept-Language is uncommon for real browsers.
  if (!header(h, "accept-language")) {
    score += 0.15;
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
      score += 0.4;
      reasons.push("forgery.noClientHints");
    }
    if (major >= 90 && !header(h, "sec-fetch-site")) {
      score += 0.25;
      reasons.push("forgery.noSecFetch");
    }
  }
  // A real browser's Accept for a navigation includes text/html; tools send */*.
  const accept = header(h, "accept");
  if (accept === "*/*" && !isScript) {
    score += 0.2;
    reasons.push("accept.wildcard");
  }

  // Clamp.
  score = Math.min(1, score);
  return { score, reasons };
}
