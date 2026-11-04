import { defineConfig } from "vite";
import { resolve } from "node:path";

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
      // Strip comments and mangle to raise the cost of reading the guard.
      format: { comments: false },
    },
  },
});
