/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/** Build first (tsc), then: node test/harden.mjs */
import { createHash } from "node:crypto";
import {
  sriHash, buildCsp, antiReObfuscatorOptions,
  generateKey, encryptBundle, decryptBundle,
} from "../dist/index.js";

let pass = 0, fail = 0;
const ok = (c, m) => { if (c) pass++; else { fail++; console.log("FAIL:", m); } };

// 1. SRI hash matches a reference sha384-base64.
{
  const content = 'console.log("hello");';
  const ref = "sha384-" + createHash("sha384").update(content).digest("base64");
  ok(sriHash(content) === ref, "sriHash sha384 matches reference");
  ok(sriHash(content, "sha512").startsWith("sha512-"), "sriHash sha512 prefix");
}

// 2. CSP builder: strict defaults + options.
{
  const csp = buildCsp();
  ok(csp.includes("default-src 'self'") && csp.includes("object-src 'none'") && csp.includes("frame-ancestors 'none'"), "CSP strict defaults");
  const csp2 = buildCsp({ allowScriptBlob: true, connectSrc: ["https://api.example.com"], nonce: "abc" });
  ok(csp2.includes("blob:") && csp2.includes("'nonce-abc'") && csp2.includes("https://api.example.com"), "CSP options applied");
}

// 3. Obfuscator preset: aggressive options + domain lock.
{
  const o = antiReObfuscatorOptions({ domainLock: ["example.com"], aggressiveness: 0.9, seed: 7 });
  ok(o.controlFlowFlattening === true && o.selfDefending === true && o.stringArray === true, "obfuscator anti-RE flags set");
  ok(Array.isArray(o.domainLock) && o.domainLock[0] === "example.com", "domain lock passed through");
  ok(o.seed === 7, "seed passed through");
}

// 4. Encrypted bundle round-trip; wrong key fails.
{
  const key = await generateKey();
  const plaintext = 'export const compute = (x) => x * 1337 + 17;';
  const payload = await encryptBundle(plaintext, key);
  ok(payload.alg === "AES-GCM" && payload.iv && payload.ct, "encryptBundle produces iv+ct");
  ok(!payload.ct.includes("1337") && !JSON.stringify(payload).includes("compute"), "ciphertext hides the plaintext");
  const back = await decryptBundle(payload, key);
  ok(back === plaintext, "decrypt with the right key recovers the bundle");
  const otherKey = await generateKey();
  let failed = false;
  try { await decryptBundle(payload, otherKey); } catch { failed = true; }
  ok(failed, "decrypt with a wrong key throws");
}

console.log(`\nRESULT: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
