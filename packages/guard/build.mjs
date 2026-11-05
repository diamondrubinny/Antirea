/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * Builds the guard library with esbuild (no dev-server dependency):
 *   - dist/antirea-guard.js      (ESM, for npm consumers)
 *   - dist/antirea-guard.iife.js (self-executing, for a plain <script> tag)
 * Type declarations are emitted separately by `tsc` (see package.json build).
 */
import { build } from "esbuild";

const BANNER =
  "/*! Antirea | @author Diamond Rubinny | @license Apache-2.0 | " +
  "(c) 2026 Diamond Rubinny — credit required, keep this notice. */";

const common = {
  entryPoints: ["src/index.ts"],
  bundle: true,
  minify: true,
  target: "es2020",
  legalComments: "none", // strip source comments; the credit banner is re-added below
  banner: { js: BANNER },
  logLevel: "info",
};

await build({ ...common, format: "esm", outfile: "dist/antirea-guard.js" });
await build({ ...common, format: "iife", globalName: "Antirea", outfile: "dist/antirea-guard.iife.js" });
console.log("guard built (esbuild)");
