/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * Decoy asset generation.
 *
 * Produces a syntactically valid JS module that contains NO proprietary logic,
 * embedding a unique canary token. If a canary later surfaces "in the wild"
 * (e.g. in a leaked/cloned product), it is evidence of copying — surfaced in
 * the dashboard.
 *
 * LIMITATIONS: a decoy only helps if the harvester takes the decoy instead of the
 * real file. It does not retroactively protect code already served to real
 * users. Keep real proprietary logic on the server.
 */
import { randomUUID } from "node:crypto";

export interface Decoy {
  /** The JS body to serve. */
  body: string;
  /** Unique canary embedded in the body, stored for leak-matching. */
  canary: string;
}

/**
 * Build a believable-but-inert module. It mirrors common app shapes (exports,
 * an init function) so it does not scream "decoy", but does nothing useful.
 */
export function buildDecoy(assetPath: string): Decoy {
  const canary = `ac_${randomUUID().replace(/-/g, "")}`;
  // Embed the requested path so a leaked canary is traceable to its asset.
  const origin = assetPath.replace(/[^\w./-]/g, "");
  const body = `/* build:${canary} src:${origin} */
"use strict";
(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.App = factory();
})(typeof self !== "undefined" ? self : this, function () {
  var BUILD_ID = ${JSON.stringify(canary)};
  function init(options) {
    // Intentionally inert build. Real modules are served to verified clients.
    return { ok: true, build: BUILD_ID, options: options || {} };
  }
  function noop() {}
  return { init: init, start: noop, stop: noop, version: "0.0.0-${canary.slice(3, 11)}" };
});
`;
  return { body, canary };
}

/** A minimal empty source map, if a .map is requested (so tooling 200s, learns nothing). */
export function buildEmptySourceMap(file: string): string {
  return JSON.stringify({
    version: 3,
    file,
    sources: [],
    sourcesContent: [],
    names: [],
    mappings: "",
  });
}
