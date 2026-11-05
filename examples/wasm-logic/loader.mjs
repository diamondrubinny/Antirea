/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * Minimal loader for the proprietary WASM logic. Works in Node and the browser.
 * In the browser, fetch the .wasm through Antirea's attestation-gated endpoint
 * (see @antirea/guard `fetchProtectedBytes`) so a detected CDP/automation client
 * receives a decoy binary instead of the real one.
 */
export async function loadLogic(source) {
  let bytes;
  if (source instanceof ArrayBuffer || ArrayBuffer.isView(source)) {
    bytes = source;
  } else if (typeof source === "string" || source instanceof URL) {
    bytes = await (await fetch(source)).arrayBuffer();
  } else if (source && typeof source.arrayBuffer === "function") {
    bytes = await source.arrayBuffer();
  } else {
    throw new Error("loadLogic: unsupported source");
  }
  const { instance } = await WebAssembly.instantiate(bytes, {});
  return instance.exports; // { priceQuote, riskScore }
}
