/**
 * Test the REA default-launch fingerprint detector with injected environments.
 * Build the guard first (vite), then: node packages/guard/test/rea.mjs
 */
import { detectRea } from "../dist/antirea-guard.js";

let pass = 0;
let fail = 0;
const ok = (c, m) => { if (c) pass++; else { fail++; console.log("FAIL:", m); } };

// REA default Playwright launch profile → flagged with high confidence.
{
  const env = {
    webdriver: true, width: 1280, height: 720, dpr: 1,
    timezone: "UTC", language: "en-US", reducedMotion: true, colorSchemeDark: false,
  };
  const sig = detectRea(env);
  ok(sig.length === 1 && sig[0].name === "rea.playwrightDefaults" && sig[0].confidence >= 0.85,
     "REA default profile flagged (high confidence)");
}

// Ordinary user → not flagged.
{
  const env = {
    webdriver: false, width: 1920, height: 1080, dpr: 2,
    timezone: "America/New_York", language: "en-US", reducedMotion: false, colorSchemeDark: true,
  };
  ok(detectRea(env).length === 0, "ordinary user not flagged");
}

// webdriver alone (no other defaults) → not a REA signal (handled elsewhere).
{
  const env = {
    webdriver: true, width: 1920, height: 1080, dpr: 2,
    timezone: "Europe/Paris", language: "fr-FR", reducedMotion: false, colorSchemeDark: true,
  };
  ok(detectRea(env).length === 0, "bare webdriver is not a REA fingerprint");
}

console.log(`\nRESULT: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
