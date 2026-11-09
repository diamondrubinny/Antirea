/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * Scripted-scenario patch detector (REA service-worker policy, Playwright
 * serviceWorkers:"block") with injected environments.
 * Build the guard first, then: node test/scenario.mjs
 */
import { detectScenarioPatches } from "../dist/antirea-guard.js";

let pass = 0,
  fail = 0;
const ok = (c, m) => {
  if (c) pass++;
  else {
    fail++;
    console.log("FAIL:", m);
  }
};
const uuid = "3f2c1a9e-7b4d-4c2e-9a1f-0e5d6c7b8a90";
const base = { globalNames: ["window", "document", "fetch"], registerSymbols: [], instanceRegister: false, instanceRegisterNative: true };
const names = (env) => detectScenarioPatches(env).map((s) => s.name);

ok(names(base).length === 0, "clean page → no signal");
{
  const s = detectScenarioPatches({ ...base, globalNames: [...base.globalNames, `rea-restore-${uuid}`] });
  ok(s.length === 1 && s[0].name === "rea.scenarioSwPolicy" && s[0].confidence >= 0.99, "REA restore global → near-certain");
}
ok(names({ ...base, registerSymbols: [`rea-service-workers-${uuid}`] })[0] === "rea.scenarioSwPolicy", "REA marker symbol on register → flagged");
ok(
  names({ ...base, globalNames: [`rea-restore-${uuid}`], instanceRegister: true, instanceRegisterNative: false }).join() === "rea.scenarioSwPolicy",
  "REA marker wins; the generic patch is not double-reported",
);
{
  const s = detectScenarioPatches({ ...base, instanceRegister: true, instanceRegisterNative: false });
  ok(s.length === 1 && s[0].name === "automation.swBlockPatch", "Playwright instance-level register patch → reported");
  ok(s[0].confidence < 0.7, "instance wrapper alone stays below the aggressive-mode halt threshold (0.7)");
}
ok(names({ ...base, instanceRegister: true, instanceRegisterNative: true }).length === 0, "own but native register → not flagged");
ok(names({ ...base, globalNames: ["rea-restore-notauuid", "my-rea-restore-" + uuid] }).length === 0, "lookalike names without the exact shape → not flagged");
ok(names({ ...base, registerSymbols: ["zone.js:register", "rea-service-workers-x"] }).length === 0, "other symbols (e.g. zone.js) → not flagged");

console.log(`\nRESULT: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
