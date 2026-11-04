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

export function scoreRequest(input: ScoreInput): ScoreResult {
  const reasons: string[] = [];
  let score = 0;
  const ua = input.userAgent || "";
  const h = input.headers;

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

  // Clamp.
  score = Math.min(1, score);
  return { score, reasons };
}
