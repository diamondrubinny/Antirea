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
 * the standard `generateBundle` hook, which both tools call.
 */
import { createHmac, randomBytes } from "node:crypto";
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
  generateBundle(
    this: { warn?: (message: string) => void } | void,
    options: OutputOptionsLike,
    bundle: Record<string, OutputFileLike>,
  ): void;
}

/** Token for one chunk: unguessable without the seed, stable for a fixed seed. */
export function canaryToken(seed: string, chunkName: string): string {
  return createHmac("sha256", seed).update(chunkName).digest("hex").slice(0, 24);
}

/** Rollup/Vite plugin that appends a source-map canary to each JS chunk. */
export function sourceMapCanaryPlugin(opts: CanaryPluginOptions = {}): CanaryPlugin {
  const prefix = opts.prefix ?? DEFAULT_CANARY_PREFIX;
  if (opts.seed !== undefined && opts.seed.length < 16) {
    throw new Error("[antirea] canary seed must be at least 16 characters");
  }
  const seed = opts.seed ?? randomBytes(32).toString("hex");
  // Validate the prefix once, at configuration time.
  sourceMapCanaryComment(prefix, "validation0");
  let warned = false;

  return {
    name: "antirea-source-map-canary",
    // generateBundle, not renderChunk: it runs after minification (a minifier
    // drops a comment added earlier — observed with Vite 8) and sees the final
    // file names.
    generateBundle(options, bundle) {
      // With real linked source maps the bundler writes its own
      // sourceMappingURL; a canary would be ignored (the last comment wins)
      // and the real map would be public anyway.
      if (options.sourcemap === true || options.sourcemap === "inline") {
        if (!warned) {
          warned = true;
          const message =
            "[antirea] source-map canary skipped: the build emits linked source maps. " +
            'Use sourcemap: false or "hidden" (and do not publish the .map files).';
          if (this && typeof this.warn === "function") this.warn(message);
          else console.warn(message);
        }
        return;
      }
      for (const file of Object.values(bundle)) {
        if (file.type !== "chunk" || typeof file.code !== "string") continue;
        if (!/\.(?:m?js|cjs)$/.test(file.fileName)) continue;
        // A chunk that already declares a map keeps it: never stack two comments.
        if (/\/\/[#@]\s*sourceMappingURL=/.test(file.code)) continue;

        // Key on the stable chunk name when there is one, so a fixed seed
        // gives the same URL across builds even when the content hash changes.
        const token = canaryToken(seed, file.name ?? file.fileName);
        const comment = sourceMapCanaryComment(prefix, token);
        file.code = `${file.code.replace(/\s+$/, "")}\n${comment}\n`;
        opts.onCanary?.({ chunk: file.fileName, token, url: comment.split("=")[1] });
      }
    },
  };
}
