/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * Canary scanning: search public code hosts for your canary tokens so a leaked
 * copy surfaces. GitHub code search is the default source.
 *
 * `fetchImpl` is injectable so this is testable offline. In production, pass a
 * GitHub token (code search requires auth).
 *
 * LIMITATIONS: only finds tokens that were pushed to *indexed, public* code.
 * Private leaks, pastebins, or minified copies that dropped the token won't
 * show up. Respect each host's API terms and rate limits.
 */
export interface ScanHit {
  token: string;
  url: string;
  repository?: string;
  source: "github";
}

export interface GitHubScanOptions {
  /** GitHub token (needs public_repo / code search access). */
  token: string;
  /** Injectable fetch (defaults to global fetch). */
  fetchImpl?: typeof fetch;
  /** API base (for GitHub Enterprise). Default https://api.github.com. */
  apiBase?: string;
}

/** Build the GitHub code-search request for one canary token. */
export function buildGitHubQuery(token: string, apiBase = "https://api.github.com"): string {
  // Exact-string search; the token charset has no qualifiers to escape.
  const q = encodeURIComponent(`"${token}"`);
  return `${apiBase.replace(/\/$/, "")}/search/code?q=${q}&per_page=10`;
}

/** Parse a GitHub code-search response body into hits for `token`. */
export function parseGitHubResults(token: string, body: unknown): ScanHit[] {
  const items = (body as { items?: Array<{ html_url?: string; repository?: { full_name?: string } }> })
    ?.items;
  if (!Array.isArray(items)) return [];
  return items.map((it) => ({
    token,
    url: typeof it.html_url === "string" ? it.html_url : "",
    repository: it.repository?.full_name,
    source: "github" as const,
  }));
}

/** Scan GitHub for a list of canary tokens. Returns all hits found. */
export async function scanGitHub(tokens: string[], opts: GitHubScanOptions): Promise<ScanHit[]> {
  const doFetch = opts.fetchImpl ?? fetch;
  const apiBase = opts.apiBase ?? "https://api.github.com";
  const hits: ScanHit[] = [];
  for (const token of tokens) {
    try {
      const res = await doFetch(buildGitHubQuery(token, apiBase), {
        headers: {
          Authorization: `Bearer ${opts.token}`,
          Accept: "application/vnd.github+json",
          "X-GitHub-Api-Version": "2022-11-28",
        },
      });
      if (!res.ok) continue;
      const body = (await res.json()) as unknown;
      hits.push(...parseGitHubResults(token, body));
    } catch {
      // Network/rate-limit errors are non-fatal; continue scanning.
    }
  }
  return hits;
}
