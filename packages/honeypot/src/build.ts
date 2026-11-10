/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * Build-time source-map canary for Rollup and Vite (`@antirea/honeypot/build`).
 *
 * Appends a `//# sourceMappingURL=` comment to every emitted JavaScript chunk,
 * pointing at a unique URL under the canary prefix. Pair it with the
 * honeypot's `sourceMapCanary` option on the server: a request for one of
 * these URLs means a source-map consumer read the bundle (an analysis tool, a
 * harvesting script — or a developer with DevTools open).
 *
 * The plugin has no dependency on Rollup or Vite; it is a plain object with
 * the standard `generateBundle` hook, which both tools call. A webpack 5
 * plugin with the same behaviour is exported as `SourceMapCanaryWebpackPlugin`.
 */
import { createHash, createHmac, randomBytes } from "node:crypto";
import { DEFAULT_CANARY_PREFIX, sourceMapCanaryComment } from "./canary.js";

export interface CanaryPluginOptions {
  /** Path prefix; must equal the honeypot's `sourceMapCanary`. */
  prefix?: string;
  /**
   * Secret seed for the per-chunk tokens. Random per build by default. Set a
   * fixed secret (from an environment variable, never committed) for
   * reproducible builds — the same chunk then keeps the same canary URL. With
   * the random default, a file whose name (content hash) did not change still
   * gets a different last line on every build; use a fixed seed if you serve
   * hashed files as immutable.
   */
  seed?: string;
  /** Called once per chunk, e.g. to log which token belongs to which file. */
  onCanary?: (info: { chunk: string; token: string; url: string }) => void;
  /**
   * File name for a Subresource Integrity manifest, e.g. "sri-manifest.json".
   * When set, the build also emits `{ "<file>": "sha384-…" }` for every JS
   * chunk, computed AFTER the canary line is added. Use the values for the
   * `integrity` attribute of your script tags. Put this plugin last: a plugin
   * that edits a chunk afterwards makes its hash stale.
   */
  sriManifest?: string;
}

/** The subset of Rollup's output options the plugin reads. */
interface OutputOptionsLike {
  sourcemap?: boolean | "inline" | "hidden";
}
/** The subset of a Rollup output bundle entry the plugin reads and edits. */
interface OutputFileLike {
  type: "chunk" | "asset";
  fileName: string;
  name?: string;
  code?: string;
}

export interface CanaryPlugin {
  name: string;
  /** Vite: run after its own plugins, which still rewrite chunks (Rollup ignores this). */
  enforce: "post";
  /**
   * Object-form hook with `order: "post"`: Vite's own plugins still rewrite
   * the entry chunk in generateBundle, so the canary and the SRI hash must be
   * computed after them (measured on Vite 8).
   */
  generateBundle: {
    order: "post";
    handler(
      this: {
        warn?: (message: string) => void;
        emitFile?: (file: { type: "asset"; fileName: string; source: string }) => unknown;
      } | void,
      options: OutputOptionsLike,
      bundle: Record<string, OutputFileLike>,
    ): void;
  };
}

/** Token for one chunk: unguessable without the seed, stable for a fixed seed. */
export function canaryToken(seed: string, chunkName: string): string {
  return createHmac("sha256", seed).update(chunkName).digest("hex").slice(0, 24);
}

/** Subresource Integrity value (`sha384-<base64>`) for a file's content. */
export function sriFor(content: string | Uint8Array): string {
  return `sha384-${createHash("sha384").update(content).digest("base64")}`;
}

const JS_FILE = /\.(?:m?js|cjs)$/;
const HAS_MAP_COMMENT = /\/\/[#@]\s*sourceMappingURL=/;
const SKIP_MESSAGE =
  "[antirea] source-map canary skipped: the build emits linked source maps. " +
  "Use hidden source maps or none (and do not publish the .map files).";

/** Validated options shared by the Rollup/Vite and webpack plugins. */
function resolveOptions(opts: CanaryPluginOptions): { prefix: string; seed: string; sriManifest?: string } {
  const prefix = opts.prefix ?? DEFAULT_CANARY_PREFIX;
  if (opts.seed !== undefined && opts.seed.length < 16) {
    throw new Error("[antirea] canary seed must be at least 16 characters");
  }
  // Validate the prefix once, at configuration time.
  sourceMapCanaryComment(prefix, "validation0");
  if (
    opts.sriManifest !== undefined &&
    (!/^[\w.-]+(?:\/[\w.-]+)*\.json$/.test(opts.sriManifest) ||
      opts.sriManifest.split("/").some((segment) => segment === "." || segment === ".."))
  ) {
    throw new Error("[antirea] sriManifest must be a relative .json file name");
  }
  return { prefix, seed: opts.seed ?? randomBytes(32).toString("hex"), sriManifest: opts.sriManifest };
}

/**
 * Code with the canary line appended, or null when the chunk must be left
 * alone (it already declares a map: never stack two comments).
 */
function withCanary(
  code: string,
  chunkName: string,
  fileName: string,
  cfg: { prefix: string; seed: string },
  onCanary: CanaryPluginOptions["onCanary"],
): string | null {
  if (HAS_MAP_COMMENT.test(code)) return null;
  // Key on the stable chunk name, so a fixed seed gives the same URL across
  // builds even when the content hash in the file name changes.
  const token = canaryToken(cfg.seed, chunkName);
  const comment = sourceMapCanaryComment(cfg.prefix, token);
  onCanary?.({ chunk: fileName, token, url: comment.split("=")[1] });
  return `${code.replace(/\s+$/, "")}\n${comment}\n`;
}

/** Rollup/Vite plugin that appends a source-map canary to each JS chunk. */
export function sourceMapCanaryPlugin(opts: CanaryPluginOptions = {}): CanaryPlugin {
  const cfg = resolveOptions(opts);
  let warned = false;

  return {
    name: "antirea-source-map-canary",
    enforce: "post",
    // generateBundle, not renderChunk: it runs after minification (a minifier
    // drops a comment added earlier — observed with Vite 8) and sees the final
    // file names.
    generateBundle: {
      order: "post",
      handler(options, bundle) {
        // With real linked source maps the bundler writes its own
        // sourceMappingURL; a canary would be ignored (the last comment wins)
        // and the real map would be public anyway.
        if (options.sourcemap === true || options.sourcemap === "inline") {
          if (!warned) {
            warned = true;
            if (this && typeof this.warn === "function") this.warn(SKIP_MESSAGE);
            else console.warn(SKIP_MESSAGE);
          }
        } else {
          for (const file of Object.values(bundle)) {
            if (file.type !== "chunk" || typeof file.code !== "string" || !JS_FILE.test(file.fileName))
              continue;
            const next = withCanary(file.code, file.name ?? file.fileName, file.fileName, cfg, opts.onCanary);
            if (next !== null) file.code = next;
          }
        }
        // The SRI manifest covers every JS chunk, with or without a canary.
        if (cfg.sriManifest && this && typeof this.emitFile === "function") {
          const manifest: Record<string, string> = {};
          for (const file of Object.values(bundle)) {
            if (file.type === "chunk" && typeof file.code === "string" && JS_FILE.test(file.fileName)) {
              manifest[file.fileName] = sriFor(file.code);
            }
          }
          this.emitFile({
            type: "asset",
            fileName: cfg.sriManifest,
            source: JSON.stringify(manifest, null, 2) + "\n",
          });
        }
      },
    },
  };
}

// ---------------------------------------------------------------------------
// webpack 5
// ---------------------------------------------------------------------------

/** The parts of webpack's compiler the plugin uses (no dependency on webpack). */
interface WebpackSourceLike {
  source(): string | Buffer;
}
interface WebpackCompilationLike {
  hooks: {
    processAssets: {
      tap(
        options: { name: string; stage: number },
        fn: (assets: Record<string, WebpackSourceLike>) => void,
      ): void;
    };
  };
  chunks: Iterable<{ name?: string | null; id?: string | number | null; files: Iterable<string> }>;
  warnings: unknown[];
  updateAsset(file: string, source: WebpackSourceLike): void;
  emitAsset(file: string, source: WebpackSourceLike): void;
}
interface WebpackCompilerLike {
  options: { devtool?: string | false };
  webpack: {
    Compilation: { PROCESS_ASSETS_STAGE_SUMMARIZE: number; PROCESS_ASSETS_STAGE_REPORT: number };
    sources: { RawSource: new (code: string) => WebpackSourceLike };
    WebpackError: new (message: string) => unknown;
  };
  hooks: { thisCompilation: { tap(name: string, fn: (compilation: WebpackCompilationLike) => void): void } };
}

const PLUGIN_NAME = "AntireaSourceMapCanaryPlugin";

/**
 * webpack 5 plugin with the same behaviour as `sourceMapCanaryPlugin`.
 *
 *   plugins: [new SourceMapCanaryWebpackPlugin({ seed: process.env.CANARY_SEED })]
 *
 * The canary is added after minification and before content hashes are
 * finalised, so `[contenthash]` file names include it.
 */
export class SourceMapCanaryWebpackPlugin {
  private readonly cfg: ReturnType<typeof resolveOptions>;
  constructor(private readonly opts: CanaryPluginOptions = {}) {
    this.cfg = resolveOptions(opts);
  }

  apply(compiler: WebpackCompilerLike): void {
    const { Compilation, sources, WebpackError } = compiler.webpack;
    compiler.hooks.thisCompilation.tap(PLUGIN_NAME, (compilation) => {
      compilation.hooks.processAssets.tap(
        { name: PLUGIN_NAME, stage: Compilation.PROCESS_ASSETS_STAGE_SUMMARIZE },
        (assets) => {
          // Any devtool except "hidden-*" (or none) links or inlines a real map.
          const devtool = compiler.options.devtool;
          if (typeof devtool === "string" && devtool !== "" && !devtool.includes("hidden")) {
            compilation.warnings.push(new WebpackError(SKIP_MESSAGE));
            return;
          }
          const chunkOf = new Map<string, string>();
          for (const chunk of compilation.chunks) {
            for (const file of chunk.files) chunkOf.set(file, String(chunk.name ?? chunk.id ?? file));
          }
          for (const file of Object.keys(assets)) {
            if (!JS_FILE.test(file)) continue;
            const code = assets[file].source();
            if (typeof code !== "string" && !Buffer.isBuffer(code)) continue;
            const next = withCanary(
              code.toString(),
              chunkOf.get(file) ?? file,
              file,
              this.cfg,
              this.opts.onCanary,
            );
            if (next !== null) compilation.updateAsset(file, new sources.RawSource(next));
          }
        },
      );
      const manifestName = this.cfg.sriManifest;
      if (manifestName) {
        compilation.hooks.processAssets.tap(
          { name: PLUGIN_NAME, stage: Compilation.PROCESS_ASSETS_STAGE_REPORT },
          (assets) => {
            const manifest: Record<string, string> = {};
            for (const file of Object.keys(assets)) {
              if (JS_FILE.test(file)) manifest[file] = sriFor(assets[file].source());
            }
            compilation.emitAsset(
              manifestName,
              new sources.RawSource(JSON.stringify(manifest, null, 2) + "\n"),
            );
          },
        );
      }
    });
  }
}
