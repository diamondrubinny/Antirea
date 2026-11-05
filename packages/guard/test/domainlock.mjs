/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/** Build the guard first, then: node test/domainlock.mjs */
import { checkDomainLock } from "../dist/antirea-guard.js";

let pass = 0,
  fail = 0;
const ok = (c, m) => {
  if (c) pass++;
  else {
    fail++;
    console.log("FAIL:", m);
  }
};

ok(checkDomainLock(["example.com"], "example.com").length === 0, "exact host allowed");
ok(checkDomainLock(["example.com"], "app.example.com").length === 0, "subdomain allowed");
ok(checkDomainLock(["*.example.com"], "app.example.com").length === 0, "wildcard entry allowed");
{
  const sig = checkDomainLock(["example.com"], "clone.evil.net");
  ok(sig.length === 1 && sig[0].name === "domainlock.mismatch" && sig[0].confidence >= 0.8, "foreign host flagged");
}
ok(checkDomainLock([], "anything.com").length === 0, "empty allowlist disables the check");
ok(checkDomainLock(["example.com"], "notexample.com").length === 1, "lookalike host flagged (not a subdomain)");

console.log(`\nRESULT: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
