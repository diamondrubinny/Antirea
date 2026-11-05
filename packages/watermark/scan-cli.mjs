/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * Scan GitHub for leaked canary tokens.
 *
 *   GITHUB_TOKEN=ghp_xxx node scan-cli.mjs wm_token1 wm_token2 ...
 *   GITHUB_TOKEN=ghp_xxx node scan-cli.mjs --file tokens.txt
 *
 * Exits non-zero if any token is found in public code (useful in a cron job).
 */
import { readFileSync } from "node:fs";
import { scanGitHub } from "./dist/index.js";

const token = process.env.GITHUB_TOKEN;
if (!token) {
  console.error("Set GITHUB_TOKEN (a PAT with code-search access).");
  process.exit(2);
}

const args = process.argv.slice(2);
let tokens = [];
const fileIdx = args.indexOf("--file");
if (fileIdx >= 0) {
  tokens = readFileSync(args[fileIdx + 1], "utf8").split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
} else {
  tokens = args.filter(Boolean);
}
if (tokens.length === 0) {
  console.error("No tokens provided.");
  process.exit(2);
}

const hits = await scanGitHub(tokens, { token });
if (hits.length === 0) {
  console.log(`No leaks found for ${tokens.length} token(s).`);
  process.exit(0);
}
console.log(`LEAK(S) FOUND (${hits.length}):`);
for (const h of hits) console.log(`  ${h.token}  ->  ${h.repository ?? "?"}  ${h.url}`);
process.exit(1);
