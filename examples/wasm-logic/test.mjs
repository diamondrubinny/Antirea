/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * Proves the WASM logic loads and runs, and that the readable algorithm is NOT
 * present in the shipped binary (a CDP dump yields the opaque module, not JS).
 * Build first (npm run build), then: node test.mjs
 */
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { loadLogic } from "./loader.mjs";

const here = dirname(fileURLToPath(import.meta.url));
let pass = 0,
  fail = 0;
const ok = (c, m) => {
  if (c) pass++;
  else {
    fail++;
    console.log("FAIL:", m);
  }
};

const wasm = await readFile(join(here, "dist", "logic.wasm"));
const logic = await loadLogic(wasm.buffer.slice(wasm.byteOffset, wasm.byteOffset + wasm.byteLength));

ok(logic.priceQuote(2) === 2691, "priceQuote(2) === 2691 (runs from wasm)");
ok(typeof logic.riskScore(500, 3) === "number", "riskScore returns a number");
ok(logic.riskScore(500, 3) >= 0 && logic.riskScore(500, 3) <= 999, "riskScore is bounded 0..999");

// The readable algorithm must not appear as text in the binary.
const asText = Buffer.from(wasm).toString("latin1");
ok(!asText.includes("1337") && !asText.includes("priceQuote =") && !asText.includes("* 1337"), "the JS-readable formula is not present in the wasm binary");

console.log(`\nRESULT: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
