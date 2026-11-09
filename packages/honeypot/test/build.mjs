/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * Tests for the build-time source-map canary plugin.
 * Build first, then: node packages/honeypot/test/build.mjs
 */
import { sourceMapCanaryPlugin, canaryToken } from "../dist/build.js";
import { scoreRequest } from "../dist/index.js";

let pass = 0;
let fail = 0;
const ok = (c, m) => {
  if (c) pass++;
  else {
    fail++;
    console.log("FAIL:", m);
  }
};
const SEED = "a-fixed-test-seed-0123456789";
// Mimic the bundler: one chunk in a bundle; returns the edited chunk, or null if untouched.
const run = (plugin, code, chunk, options = {}, ctx) => {
  const file = { type: "chunk", code, ...chunk };
  plugin.generateBundle.call(ctx, options, { [chunk.fileName]: file });
  return file.code === code ? null : { code: file.code };
};

{
  const seen = [];
  const p = sourceMapCanaryPlugin({ seed: SEED, onCanary: (i) => seen.push(i) });
  const out = run(p, "console.log(1);\n\n", { fileName: "assets/app-abc123.js", name: "app" });
  const lines = out.code.trimEnd().split("\n");
  const last = lines[lines.length - 1];
  ok(/^\/\/# sourceMappingURL=\/__antirea\/m\/[0-9a-f]{24}\.map$/.test(last), `canary is the last line (${last})`);
  ok(out.code.startsWith("console.log(1);\n//# "), "original code kept, trailing blank lines collapsed");
  ok(seen.length === 1 && seen[0].chunk === "assets/app-abc123.js" && last.endsWith(seen[0].url), "onCanary reports chunk, token and URL");
  // The emitted URL is exactly what the honeypot scores as a canary hit.
  const r = scoreRequest({ userAgent: "node", headers: {}, path: seen[0].url, canaryPaths: ["/__antirea/m/"] });
  ok(r.reasons.includes("canary.sourceMap") && r.score === 1, "emitted URL is recognised by the honeypot scorer");
  // Stable for a fixed seed, different per chunk, different per seed.
  const again = run(sourceMapCanaryPlugin({ seed: SEED }), "x", { fileName: "assets/app-zzz999.js", name: "app" });
  ok(again.code.includes(seen[0].token), "same seed + chunk name → same token across builds (hash in file name ignored)");
  ok(canaryToken(SEED, "app") !== canaryToken(SEED, "vendor"), "different chunks get different tokens");
  ok(canaryToken(SEED, "app") !== canaryToken(SEED + "x", "app"), "token depends on the secret seed");
}
{
  const a = run(sourceMapCanaryPlugin(), "x", { fileName: "a.js", name: "a" }).code;
  const b = run(sourceMapCanaryPlugin(), "x", { fileName: "a.js", name: "a" }).code;
  ok(a !== b, "default seed is random per build");
}
{
  const warns = [];
  const p = sourceMapCanaryPlugin({ seed: SEED });
  const ctx = { warn: (m) => warns.push(m) };
  ok(run(p, "x", { fileName: "a.js" }, { sourcemap: true }, ctx) === null, "linked source maps → chunk left untouched");
  ok(run(p, "x", { fileName: "b.js" }, { sourcemap: "inline" }, ctx) === null, "inline source maps → untouched");
  ok(warns.length === 1 && /skipped/.test(warns[0]), "warns once through the bundler's warn()");
  ok(run(p, "x", { fileName: "c.js" }, { sourcemap: "hidden" }, ctx) !== null, "hidden source maps → canary added");
}
{
  const p = sourceMapCanaryPlugin({ seed: SEED });
  ok(run(p, "body{}", { fileName: "style.css" }) === null, "non-JS output is ignored");
  ok(run(p, "x", { fileName: "worker.mjs" }) !== null, ".mjs chunks are handled");
  ok(run(p, "x\n//# sourceMappingURL=real.js.map", { fileName: "a.js" }) === null, "a chunk that already declares a map is not given a second comment");
  ok(run(p, "x", { fileName: "noname.js" }).code.includes(canaryToken(SEED, "noname.js")), "falls back to the file name when the chunk has no name");
}
{
  // Assets and non-chunk entries in the bundle are left alone.
  const p = sourceMapCanaryPlugin({ seed: SEED });
  const bundle = {
    "a.js": { type: "chunk", fileName: "a.js", name: "a", code: "x" },
    "logo.js": { type: "asset", fileName: "logo.js", source: "y" },
  };
  p.generateBundle({}, bundle);
  ok(bundle["a.js"].code.includes("sourceMappingURL") && bundle["logo.js"].source === "y", "only JS chunks are edited; assets untouched");
}
{
  let threw = 0;
  for (const bad of [{ seed: "short" }, { prefix: "no-leading-slash" }]) {
    try {
      sourceMapCanaryPlugin(bad);
    } catch {
      threw++;
    }
  }
  ok(threw === 2, "weak seed and invalid prefix are rejected at configuration time");
  const custom = run(sourceMapCanaryPlugin({ seed: SEED, prefix: "/maps" }), "x", { fileName: "a.js" }).code;
  ok(/sourceMappingURL=\/maps\/[0-9a-f]{24}\.map/.test(custom), "custom prefix without trailing slash");
}

console.log(`\nRESULT: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
