// Proprietary client-side logic, compiled to WebAssembly.
//
// Why: for logic that MUST run in the browser (latency/offline), shipping it as
// WASM means a CDP/REA client dumps an opaque binary module, not readable
// JavaScript source. This is the best-effort *middle* tier — it raises the cost
// of reverse-engineering sharply but is not mathematically unbreakable.
// Server-side execution (@antirea/secure-fn) remains the only hermetic option.
//
// This is AssemblyScript (a TypeScript-like language that compiles to WASM).
// Build: `npm run build` in this folder (produces dist/logic.wasm).

/** Example proprietary pricing function. */
export function priceQuote(x: i32): i32 {
  return x * 1337 + 17;
}

/** A slightly less trivial proprietary routine (a bounded risk score 0..999). */
export function riskScore(amount: i32, flags: i32): i32 {
  let s: i32 = (amount * 7) ^ (flags << 3);
  s = ((s % 1000) + 1000) % 1000;
  return s;
}
