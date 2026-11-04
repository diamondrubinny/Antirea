/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * Allowlist for legitimate bots and crawlers.
 *
 * CRITICAL for SEO: never honeypot Googlebot/Bingbot etc., or indexing breaks.
 *
 * HONESTY: UA strings are spoofable. For real protection of the allowlist,
 * verify via reverse+forward DNS (Google/Bing publish this method). The
 * `verifyReverseDns` hook is provided but OFF by default (adds latency/DNS
 * dependency). Enabling it is recommended before Live mode.
 */
import { promises as dns } from "node:dns";

/** Default UA substrings treated as legitimate crawlers. */
export const DEFAULT_GOOD_BOTS = [
  "Googlebot",
  "Google-InspectionTool",
  "Bingbot",
  "DuckDuckBot",
  "Slurp", // Yahoo
  "Applebot",
  "YandexBot",
  "facebookexternalhit",
  "LinkedInBot",
  "Twitterbot",
];

/** Hostnames that verify a genuine crawler (forward-confirmed reverse DNS). */
const VERIFIED_HOST_SUFFIXES = [
  ".googlebot.com",
  ".google.com",
  ".search.msn.com", // Bing
  ".crawl.yahoo.net",
  ".yandex.com",
  ".yandex.net",
  ".yandex.ru",
];

export interface AllowlistOptions {
  goodBots?: string[];
  /** Verify crawler IPs via reverse+forward DNS. Default false. */
  verifyReverseDns?: boolean;
  /** Static IP allowlist (e.g. your QA/monitoring). */
  allowIps?: string[];
}

export class Allowlist {
  private readonly goodBots: string[];
  private readonly verify: boolean;
  private readonly allowIps: Set<string>;

  constructor(opts: AllowlistOptions = {}) {
    this.goodBots = opts.goodBots ?? DEFAULT_GOOD_BOTS;
    this.verify = opts.verifyReverseDns ?? false;
    this.allowIps = new Set(opts.allowIps ?? []);
  }

  /** Fast UA/IP check (no DNS). */
  isAllowedSync(ua: string, ip: string): boolean {
    if (this.allowIps.has(ip)) return true;
    return this.goodBots.some((b) => ua.includes(b));
  }

  /**
   * Full check. When verifyReverseDns is on and the UA claims to be a crawler,
   * confirm the IP actually resolves to a verified host. Spoofed crawler UAs
   * from random IPs then fail and get honeypotted/scored normally.
   */
  async isAllowed(ua: string, ip: string): Promise<boolean> {
    if (this.allowIps.has(ip)) return true;
    const claimsBot = this.goodBots.some((b) => ua.includes(b));
    if (!claimsBot) return false;
    if (!this.verify) return true;
    return this.confirmCrawlerIp(ip);
  }

  private async confirmCrawlerIp(ip: string): Promise<boolean> {
    try {
      const hosts = await dns.reverse(ip);
      const match = hosts.find((host) =>
        VERIFIED_HOST_SUFFIXES.some((suffix) => host.toLowerCase().endsWith(suffix)),
      );
      if (!match) return false;
      // Forward-confirm to defeat reverse-DNS spoofing.
      const forward = await dns.resolve(match);
      return forward.includes(ip);
    } catch {
      return false;
    }
  }
}
