/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
import { defineConfig } from "vite";
import { resolve } from "node:path";

// Credit banner kept in the minified output (terser preserves it below).
const BANNER =
  "/*! Antirea | @author Diamond Rubinny | @license Apache-2.0 | " +
  "(c) 2026 Diamond Rubinny — credit required, keep this notice. */";

/**
 * Builds two artifacts:
 *   - antirea-guard.js      (ESM, for npm consumers)
 *   - antirea-guard.iife.js (self-executing, for a plain <script> tag)
 */
export default defineConfig({
  build: {
    lib: {
      entry: resolve(__dirname, "src/index.ts"),
      name: "Antirea",
      formats: ["es", "iife"],
      fileName: (format) =>
        format === "iife" ? "antirea-guard.iife.js" : "antirea-guard.js",
    },
    minify: "terser",
    sourcemap: false, // never ship source maps for the guard itself
    terserOptions: {
      // Strip comments EXCEPT the credit banner (Apache-2.0 attribution).
      format: { comments: /Diamond Rubinny/ },
    },
    rollupOptions: {
      output: { banner: BANNER },
    },
  },
});
