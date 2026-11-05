# The WASM tier — hiding client-side logic

Some logic must run in the browser (latency, offline, UX). You can't make
delivered JavaScript unreadable, but you **can** ship the sensitive parts as
**WebAssembly**: a CDP/REA client that dumps the page gets an opaque `.wasm`
binary, not readable source. This raises the cost of reverse-engineering
sharply — it is **not** mathematically unbreakable (WASM can still be
disassembled), so it sits *below* server-side execution.

## The tiers, honestly

| Tier | What the attacker sees | Guarantee |
|---|---|---|
| **`@antirea/secure-fn` (server)** | network request + output only | **Hermetic** — the algorithm never reaches the client |
| **WASM (this tier)** | an opaque compiled binary | **Strong deterrence** — much harder than JS, still disassemblable |
| **Obfuscated JS** | mangled but readable JS | Weak — slows a human down only |

## Example (`examples/wasm-logic/`)

Proprietary logic in AssemblyScript (TypeScript-like → WASM):

```ts
// assembly/index.ts
export function priceQuote(x: i32): i32 { return x * 1337 + 17; }
```

Build and test:

```bash
cd examples/wasm-logic
npm install          # assemblyscript
npm run build        # -> dist/logic.wasm (the formula is NOT readable in it)
npm test             # loads the wasm and verifies output
```

Load it at runtime (Node or browser):

```js
import { loadLogic } from "./loader.mjs";
const logic = await loadLogic("/logic.wasm");   // or an ArrayBuffer
logic.priceQuote(2); // 2691 — computed inside wasm
```

## Combine with attestation-gated delivery

Serve the `.wasm` through Antirea's gated endpoint so a detected CDP/automation
client gets a **decoy** binary instead of the real one:

```ts
import { instantiateProtectedWasm } from "@antirea/guard";

// Fetches /__p/logic through the honeypot gate (real for clean clients,
// decoy under CDP/automation), then instantiates it.
const logic = await instantiateProtectedWasm("logic", { endpoint: "/__p/" });
logic.priceQuote(2);
```

Point the honeypot's `protect` list at that route (e.g. `/^\/__p\//`) and serve
the real `.wasm` from a non-public directory after the middleware.

## Bottom line

WASM is the best option for logic that *must* be client-side. For anything you
can keep off the client, use `@antirea/secure-fn` — that is the only hermetic
protection.
