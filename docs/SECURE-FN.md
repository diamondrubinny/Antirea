# Server-side execution — `@antirea/secure-fn`

The only hermetic layer in Antirea: the function body never reaches the
browser, so there is nothing for a CDP tool (REA included) to read. The client
sends inputs and receives outputs.

What it does **not** hide: the input/output behaviour. Anyone allowed to call a
function can sample it. Sessions, replay protection and rate limits make bulk
sampling slow and visible — they do not make it impossible.

## Adapters

All adapters share one core (`core.ts`), so the guards are identical.

| Framework | Import | Status |
|---|---|---|
| Express 4 | `createSecureFnRouter` from `@antirea/secure-fn` | Tested in CI |
| Next.js App Router (Node.js runtime) | `createSecureFnHandler` from `@antirea/secure-fn/web` | Verified by hand on Next.js 15.5 (build + run); not in CI |
| Any `(Request) => Response` framework on Node.js | `createSecureFnHandler` from `@antirea/secure-fn/web` | Handler tested in CI with standard `Request` objects; individual frameworks not verified |
| Edge runtimes (no `node:crypto`) | — | Not supported |

`@antirea/secure-fn/web` does not import Express; `express` and
`express-rate-limit` are optional peer dependencies needed only for the router.
**Without Express installed, import from `@antirea/secure-fn/web`** — the root
entry (`@antirea/secure-fn`) loads the Express router and fails to import.

### Express

```ts
import { createSecureFnRouter } from "@antirea/secure-fn";

app.use(
  "/secure",
  createSecureFnRouter({
    secret: process.env.SECUREFN_SECRET!,
    trustProxy: 1, // number of reverse proxies in front of the app
    functions: { pricing: (args: { x: number }) => args.x * 1337 + 17 },
  }),
);
```

### Next.js (App Router)

```ts
// app/api/secure/[action]/route.ts
import { createSecureFnHandler } from "@antirea/secure-fn/web";

export const runtime = "nodejs"; // required: uses node:crypto
export const dynamic = "force-dynamic";

const handler = createSecureFnHandler({
  secret: process.env.SECUREFN_SECRET!,
  trustProxy: 1,
  functions: { pricing: (args: { x: number }) => args.x * 1337 + 17 },
});

export const POST = (request: Request) => handler(request);
```

Keep the functions in a module that only this route imports. A function
imported by a Client Component is shipped to the browser — check the build
output if unsure.

### Browser

```ts
import { createSecureClient } from "@antirea/secure-fn/client";

const api = createSecureClient({ endpoint: "/api/secure" });
const price = await api.invoke<number>("pricing", { x: 2 });
```

### Typed calls

Share the *type* of your function map with the browser and `call` checks the
function name, its argument and its result at compile time. It is a type-only
import, so no server code reaches the bundle:

```ts
// server/functions.ts
export const functions = {
  pricing: (args: { x: number }) => args.x * 1337 + 17,
};
export type Api = typeof functions;
```

```ts
// browser
import { createSecureClient } from "@antirea/secure-fn/client";
import type { Api } from "../server/functions";

const api = createSecureClient<Api>({ endpoint: "/api/secure" });
const price = await api.call("pricing", { x: 2 }); // number
await api.call("pricng", { x: 2 });                // compile error: unknown name
await api.call("pricing", { x: "2" });             // compile error: wrong argument
```

Use `import type` (not `import`) — a value import would pull the function
bodies into the browser bundle. Types are erased at build time and validate
nothing at run time: **the server must still validate its arguments.** The
untyped `invoke(name, args)` keeps working.

## Guards

| Guard | Behaviour |
|---|---|
| Session token | HMAC-SHA-256, 10 min by default; `401` when missing, forged or expired |
| Session issuing | 30 per client address per minute (IPv6 grouped by /56); `429`. **Off when the client address is unknown** — see below |
| Replay | each nonce is accepted once per session within 2 min; `409` |
| Nonce | required, at most 128 characters; `400` |
| Per-session rate | `maxInvokesPerMin` (default 120); `429`, and one anomaly report per window. Checked before the nonce is stored, so a throttled session cannot grow memory |
| Body | JSON only (`415`), at most 32 KB (`413`) |
| Errors | function errors return `500 execution failed`; details are logged server-side only |

**Client IP.** `trustProxy` is the number of trusted reverse proxies (`true` =
1). The address is the `X-Forwarded-For` entry that many hops from the right.
If the header has fewer entries than trusted hops, the request did not pass
through your whole proxy chain and the socket address is used instead. Set the
number to match your deployment exactly. **Too low** keys every client on a
proxy's address (one shared bucket). **Too high**, or set on a directly exposed
app, can select an entry that the client supplied.

- **Express:** if the app sets Express's own `trust proxy`, `req.ip` is used and
  the option is ignored — configure one or the other.
- **Fetch-API handler:** without `trustProxy`, pass the socket address as
  `handler(request, { ip })` where the platform exposes it.
- **No address at all** (no option, no `{ ip }`, or no `X-Forwarded-For`): the
  per-address session limit is switched **off** and a warning is logged once. A
  single shared bucket would let anyone lock out every user with 30 requests.
  The per-session invoke limit still applies.

**State is in memory, per process.** With several instances or on serverless,
each instance keeps its own nonce and rate-limit tables: limits are per
instance and a replayed request can succeed once on each instance. A shared
store is not implemented yet — if replay protection must hold across
instances, run a single instance or make the functions idempotent.

## Choosing what to move

Move a function when **knowing how it works** is the asset:

| Move server-side | Leave on the client |
|---|---|
| Pricing, scoring, ranking and recommendation rules | Rendering, layout, animation |
| Licence and entitlement checks | Form UX and input masks (re-validate on the server) |
| Anything using a secret, key or private dataset | Code that must work offline |
| Fraud and abuse heuristics | Hot paths that cannot afford a network round-trip |

Migration, one function at a time:

1. Make it a pure function of its arguments (no DOM, no globals).
2. Register it under `functions`; validate its arguments there — they come
   from an untrusted client.
3. Replace the client call with `api.invoke("name", args)` and handle the
   rejected promise (offline, `429`).
4. Delete the old client implementation and confirm it is gone from the
   built bundle (search the output for a constant unique to the function).
5. Check authorisation inside the function when the result depends on who is
   asking — a session token proves a session, not an identity.

Costs: one network round-trip per call, server capacity, and no offline use.
Batch calls or return coarser results where latency matters.
