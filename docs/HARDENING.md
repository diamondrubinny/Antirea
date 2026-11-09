# Client-code hardening — `@antirea/harden` (+ guard domain lock)

For the UI code that *must* ship to the browser. None of this is hermetic — it
raises the cost of reverse-engineering and rehosting. The only hermetic layer is
server-side execution (`@antirea/secure-fn`).

## Domain lock (guard)

Flag (and optionally degrade) when your front-end runs on a host you didn't
authorize — i.e. a copied, rehosted clone. Even in `silent` mode you get the
clone's hostname in your dashboard.

```ts
import { initGuard } from "@antirea/guard";
initGuard({
  siteId: "my-site",
  endpoint: "https://collector/api/events",
  mode: "obstruct",                 // degrade on a foreign host
  allowedHosts: ["example.com", "app.example.com"],
});
```

Subdomains of an entry match. **Limit:** client-side, so an attacker who reads
the code can delete the check. It stops lazy copy-paste rehosting and surfaces
clones.

## Security headers + CSP + SRI

```ts
import express from "express";
import { securityHeaders, buildCsp, sriHash } from "@antirea/harden";

const app = express();
app.use(securityHeaders({
  csp: { connectSrc: ["https://collector.example.com"], allowScriptBlob: true },
}));

// Pin a script so the browser rejects a tampered copy:
const integrity = sriHash(fileContents);        // "sha384-…"
// <script src="/app.js" integrity="<integrity>" crossorigin="anonymous"></script>
```

`buildCsp()` defaults to a strict policy (`default-src 'self'`, `object-src
'none'`, `frame-ancestors 'none'`, …); add only the sources you need.

## Obfuscation

Wrap `javascript-obfuscator` (install where you build) with an anti-RE preset,
including an optional domain lock baked into the output:

```ts
import { obfuscate } from "@antirea/harden";
const hardened = await obfuscate(uiCode, { domainLock: ["example.com"], aggressiveness: 0.8 });
```

**Limit:** obfuscation is *reversible* — it slows a human and breaks naive
copy-paste, and heavy presets enlarge/slow the bundle. Measure, and don't rely
on it alone.

## Encrypted-bundle delivery

Ship the real bundle encrypted (AES-256-GCM) and deliver the KEY only to clean
clients — fetch it through the guard's attestation gate so a detected
CDP/automation client never gets it.

```ts
// build/server
import { generateKey, encryptBundle } from "@antirea/harden";
const key = await generateKey();
const payload = await encryptBundle(realBundleSource, key);   // {alg, iv, ct}
// serve `payload` publicly; serve `key` ONLY via the attestation-gated endpoint.
```

```ts
// browser
import { importEncrypted } from "@antirea/harden/client";
// key obtained from the gated endpoint (real for clean clients, withheld/decoy otherwise):
const mod = await importEncrypted(payload, key);
```

**Limit:** any client that receives the key can decrypt — the protection is the
GATE on the key, not the encryption. Requires CSP `blob:` in `script-src`.

**Fetch the key with the guard's gated loader** (`fetchProtected` /
`fetchProtectedBytes`), not a plain `fetch`: it runs a `debugger`-timing probe
*before* the request and sends the result as attestation. Against REA 6.8.0
this matters twice over — REA's live tools enable the `Debugger` domain and
never suppress pauses, so with REA attached the page freezes at that probe and
the key is never requested while REA observes.

**Honest limit against CDP tools (verified against REA 6.8.0):** once the bundle
has been decrypted and evaluated in the page, a CDP tool that attaches **later**
can read it — REA's `observe_web_execution` captures every main-frame script via
`Debugger.getScriptSource` regardless of URL, eval'd and `blob:` code included.
The guard's periodic probe will *detect* that attach, but cannot undo the read.
Keep anything that must stay secret server-side (`@antirea/secure-fn`). See
[`REA-SIGNATURES.md`](./REA-SIGNATURES.md#what-rea-can-and-cannot-defeat-honest).
