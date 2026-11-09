/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * Compares the REA release our signatures were verified against (recorded in
 * the honeypot fixtures) with the latest release on the npm registry.
 *
 * Prints `verified=<v>`, `latest=<v>` and `stale=true|false` (also appended to
 * $GITHUB_OUTPUT when set). Exits 0 either way — a new upstream release is a
 * to-do, not a build failure. Exits 2 only if the registry cannot be read.
 * Reads public registry metadata only; it never downloads or runs REA.
 */
import { readFileSync, appendFileSync } from "node:fs";

const PACKAGE = "rea-agents";
const fixtures = JSON.parse(
  readFileSync(new URL("../packages/honeypot/test/fixtures/captured.json", import.meta.url), "utf8"),
);
const verified = String(fixtures.reaVersion);

let latest;
try {
  const res = await fetch(`https://registry.npmjs.org/${PACKAGE}/latest`, {
    headers: { accept: "application/json" },
    signal: AbortSignal.timeout(20_000),
  });
  if (!res.ok) throw new Error(`registry responded ${res.status}`);
  latest = String((await res.json()).version ?? "");
  if (!/^\d+\.\d+\.\d+/.test(latest)) throw new Error("unexpected version format");
} catch (err) {
  console.error(`could not read the latest ${PACKAGE} version: ${err.message}`);
  process.exit(2);
}

const lines = [`verified=${verified}`, `latest=${latest}`, `stale=${latest !== verified}`];
console.log(lines.join("\n"));
if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, lines.join("\n") + "\n");
