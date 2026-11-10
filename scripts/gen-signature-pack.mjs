/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * Regenerates packages/honeypot/signatures/default.json from the built-in pack
 * (packages/honeypot/src/signatures.ts). Build the honeypot first.
 *   npm run build -w packages/honeypot && node scripts/gen-signature-pack.mjs
 */
import { writeFileSync } from "node:fs";
import { DEFAULT_SIGNATURE_PACK } from "../packages/honeypot/dist/index.js";

const out = new URL("../packages/honeypot/signatures/default.json", import.meta.url);
const doc = {
  $comment:
    "Built-in signature pack. Copy, edit and pass to honeypot({ signaturePack }). Weights are 0..1; patterns are case-insensitive regular expressions. Any subset of weights/patterns may be given; the rest keep these defaults.",
  ...DEFAULT_SIGNATURE_PACK,
};
writeFileSync(out, JSON.stringify(doc, null, 2) + "\n");
console.log("wrote", out.pathname);
