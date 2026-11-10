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
import { sourceMapCanaryPlugin, SourceMapCanaryWebpackPlugin, canaryToken, sriFor } from "../dist/build.js";
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
  plugin.generateBundle.handler.call(ctx, options, { [chunk.fileName]: file });
  return file.code === code ? null : { code: file.code };
};

{
  const seen = [];
  const p = sourceMapCanaryPlugin({ seed: SEED, onCanary: (i) => seen.push(i) });
  const out = run(p, "console.log(1);\n\n", { fileName: "assets/app-abc123.js", name: "app" });
  const lines = out.code.trimEnd().split("\n");
  const last = lines[lines.length - 1];
  ok(
    /^\/\/# sourceMappingURL=\/__antirea\/m\/[0-9a-f]{24}\.map$/.test(last),
    `canary is the last line (${last})`,
  );
  ok(out.code.startsWith("console.log(1);\n//# "), "original code kept, trailing blank lines collapsed");
  ok(
    seen.length === 1 && seen[0].chunk === "assets/app-abc123.js" && last.endsWith(seen[0].url),
    "onCanary reports chunk, token and URL",
  );
  // The emitted URL is exactly what the honeypot scores as a canary hit.
  const r = scoreRequest({
    userAgent: "node",
    headers: {},
    path: seen[0].url,
    canaryPaths: ["/__antirea/m/"],
  });
  ok(
    r.reasons.includes("canary.sourceMap") && r.score === 1,
    "emitted URL is recognised by the honeypot scorer",
  );
  // Stable for a fixed seed, different per chunk, different per seed.
  const again = run(sourceMapCanaryPlugin({ seed: SEED }), "x", {
    fileName: "assets/app-zzz999.js",
    name: "app",
  });
  ok(
    again.code.includes(seen[0].token),
    "same seed + chunk name → same token across builds (hash in file name ignored)",
  );
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
  ok(
    run(p, "x", { fileName: "a.js" }, { sourcemap: true }, ctx) === null,
    "linked source maps → chunk left untouched",
  );
  ok(
    run(p, "x", { fileName: "b.js" }, { sourcemap: "inline" }, ctx) === null,
    "inline source maps → untouched",
  );
  ok(warns.length === 1 && /skipped/.test(warns[0]), "warns once through the bundler's warn()");
  ok(
    run(p, "x", { fileName: "c.js" }, { sourcemap: "hidden" }, ctx) !== null,
    "hidden source maps → canary added",
  );
}
{
  const p = sourceMapCanaryPlugin({ seed: SEED });
  ok(run(p, "body{}", { fileName: "style.css" }) === null, "non-JS output is ignored");
  ok(run(p, "x", { fileName: "worker.mjs" }) !== null, ".mjs chunks are handled");
  ok(
    run(p, "x\n//# sourceMappingURL=real.js.map", { fileName: "a.js" }) === null,
    "a chunk that already declares a map is not given a second comment",
  );
  ok(
    run(p, "x", { fileName: "noname.js" }).code.includes(canaryToken(SEED, "noname.js")),
    "falls back to the file name when the chunk has no name",
  );
}
{
  // Assets and non-chunk entries in the bundle are left alone.
  const p = sourceMapCanaryPlugin({ seed: SEED });
  const bundle = {
    "a.js": { type: "chunk", fileName: "a.js", name: "a", code: "x" },
    "logo.js": { type: "asset", fileName: "logo.js", source: "y" },
  };
  p.generateBundle.handler.call(undefined, {}, bundle);
  ok(
    bundle["a.js"].code.includes("sourceMappingURL") && bundle["logo.js"].source === "y",
    "only JS chunks are edited; assets untouched",
  );
}
{
  // SRI manifest: emitted through the bundler, hashes computed after the canary.
  const emitted = [];
  const p = sourceMapCanaryPlugin({ seed: SEED, sriManifest: "sri-manifest.json" });
  const bundle = {
    "a.js": { type: "chunk", fileName: "a.js", name: "a", code: "console.log(1)" },
    "b.css": { type: "asset", fileName: "b.css", source: "body{}" },
  };
  p.generateBundle.handler.call({ emitFile: (f) => emitted.push(f) }, {}, bundle);
  const manifest = JSON.parse(emitted[0].source);
  ok(
    emitted.length === 1 && emitted[0].fileName === "sri-manifest.json" && emitted[0].type === "asset",
    "SRI manifest is emitted as an asset",
  );
  ok(
    manifest["a.js"] === sriFor(bundle["a.js"].code) && bundle["a.js"].code.includes("sourceMappingURL"),
    "manifest hash covers the chunk including its canary line",
  );
  ok(
    Object.keys(manifest).length === 1 && /^sha384-[A-Za-z0-9+/]{64}$/.test(manifest["a.js"]),
    "only JS chunks are listed, as sha384 values",
  );
  ok(
    sriFor("abc") === "sha384-ywB1P0WjXou1oD1pmsZQBycsMqsO3tFjGotgWkP/W+2AhgcroefMI1i67KE0yCWn",
    "sriFor matches the known SHA-384 of 'abc'",
  );
  ok(
    p.generateBundle.order === "post" && p.enforce === "post",
    "the plugin asks to run after the bundler's own plugins",
  );
  let rejected = 0;
  for (const bad of ["../x.json", "/abs.json", "manifest.txt"]) {
    try {
      sourceMapCanaryPlugin({ sriManifest: bad });
    } catch {
      rejected++;
    }
  }
  ok(rejected === 3, "unsafe or non-JSON manifest names are rejected");
}
{
  // webpack plugin, against a minimal stand-in for the compiler API.
  class RawSource {
    constructor(c) {
      this.c = c;
    }
    source() {
      return this.c;
    }
  }
  const build = (devtool, opts = {}) => {
    const taps = [];
    const warnings = [];
    const assets = { "main.abc.js": new RawSource("console.log(1)"), "logo.svg": new RawSource("<svg/>") };
    const compilation = {
      hooks: { processAssets: { tap: (o, fn) => taps.push({ o, fn }) } },
      chunks: [{ name: "main", files: ["main.abc.js"] }],
      warnings,
      updateAsset: (f, s) => {
        assets[f] = s;
      },
      emitAsset: (f, s) => {
        assets[f] = s;
      },
    };
    const compiler = {
      options: { devtool },
      webpack: {
        Compilation: { PROCESS_ASSETS_STAGE_SUMMARIZE: 1000, PROCESS_ASSETS_STAGE_REPORT: 5000 },
        sources: { RawSource },
        WebpackError: Error,
      },
      hooks: { thisCompilation: { tap: (_n, fn) => fn(compilation) } },
    };
    new SourceMapCanaryWebpackPlugin({ seed: SEED, ...opts }).apply(compiler);
    taps.sort((a, b) => a.o.stage - b.o.stage).forEach((t) => t.fn(assets));
    return { assets, warnings, stages: taps.map((t) => t.o.stage) };
  };
  const r = build(false, { sriManifest: "sri-manifest.json" });
  const code = r.assets["main.abc.js"].source();
  ok(
    code.includes(canaryToken(SEED, "main")) &&
      code.trimEnd().split("\n").pop().startsWith("//# sourceMappingURL=/__antirea/m/"),
    "webpack: canary appended, keyed on the chunk name",
  );
  ok(r.assets["logo.svg"].source() === "<svg/>", "webpack: non-JS assets untouched");
  ok(
    JSON.parse(r.assets["sri-manifest.json"].source())["main.abc.js"] === sriFor(code),
    "webpack: manifest hash covers the final asset",
  );
  ok(r.stages.join() === "1000,5000", "webpack: canary before content hashing, manifest at the report stage");
  const linked = build("source-map");
  ok(
    linked.assets["main.abc.js"].source() === "console.log(1)" && linked.warnings.length === 1,
    "webpack: linked source maps → untouched, one warning",
  );
  ok(
    build("hidden-source-map").assets["main.abc.js"].source().includes("__antirea"),
    "webpack: hidden source maps → canary added",
  );
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
