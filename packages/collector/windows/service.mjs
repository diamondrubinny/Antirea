/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * Shared Windows Service definition for the Antirea collector.
 *
 * Runs the collector (dist/server.js) as a background Windows Service that
 * starts on boot. Uses `node-windows` (install it on the Windows box first:
 *   npm install node-windows
 * ). Environment comes from packages/collector/.env (same keys as .env.example).
 *
 * This is NOT a Microsoft Store app — a server service belongs in a Windows
 * Service, not a sandboxed per-user Store package. See README.md here.
 */
import { createRequire } from "node:module";
import { readFileSync, existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const here = dirname(fileURLToPath(import.meta.url));
const collectorDir = resolve(here, "..");

/** Parse a simple KEY=VALUE .env file into node-windows env entries. */
function readEnv() {
  const file = join(collectorDir, ".env");
  if (!existsSync(file)) return [];
  const out = [];
  for (const raw of readFileSync(file, "utf8").split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const eq = line.indexOf("=");
    if (eq < 0) continue;
    const name = line.slice(0, eq).trim();
    let value = line.slice(eq + 1).trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    if (name) out.push({ name, value });
  }
  return out;
}

export function buildService() {
  let nw;
  try {
    nw = require("node-windows");
  } catch {
    console.error("[antirea] node-windows is not installed. Run: npm install node-windows");
    process.exit(1);
  }
  const { Service } = nw;
  const script = join(collectorDir, "dist", "server.js");
  if (!existsSync(script)) {
    console.error(`[antirea] built server not found at ${script}. Run \"npm run build\" in packages/collector first.`);
    process.exit(1);
  }
  return new Service({
    name: "Antirea Collector",
    description: "Antirea collector: telemetry ingest API + control panel (anti reverse-engineering).",
    script,
    nodeOptions: ["--max_old_space_size=512"],
    env: readEnv(),
    // Restart on crash.
    wait: 2,
    grow: 0.5,
    maxRestarts: 10,
  });
}
