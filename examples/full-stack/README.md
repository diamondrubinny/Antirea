# Full-stack demo — every layer together

Wires all seven Antirea packages into one Express app and proves the chain with
an end-to-end test.

| Route | Layer |
|---|---|
| any response | `@antirea/harden` — security headers (CSP/HSTS/X-Frame-Options) |
| `/assets/app.js`, `*.map` | `@antirea/honeypot` — decoy to analysis, real bundle to browsers |
| `/secure/*` | `@antirea/secure-fn` — proprietary logic runs server-side |
| `/api/export` | `@antirea/challenge` — proof-of-work gate |
| `/app/core.js` | `@antirea/watermark` — per-viewer watermark (traceable) |
| `/enc/bundle` + `/enc/key` | `@antirea/harden` — encrypted-bundle delivery |
| the page | `@antirea/guard` — domain lock + DevTools/CDP/REA detection (client) |

## Run

```bash
npm install
npm run build --workspaces
node examples/full-stack/server.mjs      # http://localhost:3000
```

## Test

```bash
node examples/full-stack/test.mjs        # 11 checks across all layers
```

It boots the real app and asserts: security headers are set; headless requests
get a decoy while browsers get the real bundle; `secure-fn` returns the computed
output server-side; the export route needs a solved proof-of-work; the protected
module carries a per-viewer watermark traced back to its viewer; and the
encrypted bundle hides the code until decrypted with the gated key.
