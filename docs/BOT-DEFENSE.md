# Bot / scraper defense (server side)

Stronger, header-independent defenses against high-volume automated access.
These complement the honeypot's behavioural engine; none is a silver bullet, and
each notes its honest limits.

## 1. Proof-of-work gate — `@antirea/challenge`

Make mass scraping pay CPU. The server issues a signed challenge; the client
must find a nonce whose `SHA-256(challenge:nonce)` has N leading zero bits
before it can access a protected route. One request is cheap; a million are not.

```ts
// server
import express from "express";
import { challengeRouter, requireProof } from "@antirea/challenge";
const app = express();
app.use("/__pow", challengeRouter({ secret: process.env.POW_SECRET }));
app.use("/api/export", requireProof({ secret: process.env.POW_SECRET, difficulty: 18 }));
```

```ts
// browser — transparently solves a 402 and retries
import { proofFetch } from "@antirea/challenge/client";
const res = await proofFetch("/api/export");
```

- Verification is **stateless** (HMAC-signed challenge) plus a small replay
  cache, so no shared state is needed for a single instance.
- **Tune `difficulty`.** 18 bits ≈ ~1–3s on a laptop. Too high punishes real
  users and low-power devices — apply PoW to *flagged/expensive* routes, not
  every visitor. For high difficulty, run `solvePow` in a Web Worker.
- **Limit:** PoW slows volume; it does not stop one determined client, and a
  botnet spreads the cost across many machines.

## 2. Tarpit — `@antirea/honeypot`

Instead of (or before) a decoy, delay flagged responses to waste a scraper's
time and tie up its connections:

```ts
app.use(honeypot({ siteId: "my-site", protect: [/\.js$/], mode: "live", tarpitMs: 3000 }));
```

Flagged requests wait `tarpitMs` before the response. Real users are unaffected
(they are not flagged). Keep it modest so a false positive isn't painful.

## 3. TLS fingerprint (JA3 / JA4) — `@antirea/honeypot`

`curl`, `python-requests`, Go, and scraping frameworks each have a distinctive
**TLS handshake** fingerprint that a spoofed `User-Agent` cannot hide. Node
can't compute it, so a reverse proxy / CDN must set it as a header; the honeypot
then scores it:

```ts
app.use(honeypot({
  siteId: "my-site",
  protect: [/\.js$/],
  ja3Header: "x-ja3",                 // header your proxy sets
  blockJa3: ["<known-bot-ja3-hash>", "..."],
}));
```

Populate the header at the edge, for example:

- **Cloudflare:** add `ja3_hash` (Bot Management / managed transform) as a
  request header to your origin.
- **nginx:** with a JA3 module (e.g. `ssl_preread` + a JA3 lua/module) set
  `proxy_set_header X-JA3 $ja3_hash;`.
- **HAProxy:** compute JA3 from the ClientHello and pass it on.

Maintain `blockJa3` from your own observed bot traffic (the dashboard shows the
fingerprints that hit you). **Limit:** sophisticated tools can mimic a browser's
TLS stack (uTLS), and JA3 can collide across clients — treat it as a strong
signal, not proof.

## What's next (not yet built)

- **Redis adapter** for the behavioural tracker + rate limiter, to share state
  across instances / at the edge.
- **Request-signing SDK** to protect arbitrary JSON APIs from direct replay.
- **Per-viewer watermarking + canary scanning** for traitor tracing.
