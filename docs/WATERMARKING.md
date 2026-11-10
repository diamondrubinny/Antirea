# Watermarking & traitor tracing — `@antirea/watermark`

Identify *who* leaked a copy of your code or content, spot leaks in the wild,
and get alerted when attacks spike.

> **Honest scope:** a watermark identifies a leaked copy — it does not prevent
> copying. An attacker who knows the scheme can strip it (normalise whitespace,
> strip comments). Keep the scheme private, use several carriers, and combine
> with the hermetic layer (`@antirea/secure-fn`).

## 1. Per-viewer watermarking

Embed a unique, recoverable canary per recipient, and record who got it.

```ts
import express from "express";
import { watermark, MemoryCanaryStore } from "@antirea/watermark";

const store = new MemoryCanaryStore(); // back with a DB in production
const app = express();

// Every text/JS response on these routes is watermarked per viewer.
app.use(watermark({
  protect: [/^\/app\/.*\.js$/],
  store,
  mode: "zerowidth",                   // invisible; survives copy-paste & minifiers
  viewer: (req) => req.headers["x-session"] ?? req.socket.remoteAddress,
  onWatermark: ({ token, viewer }) => { /* persist token -> viewer */ },
}));
```

Later, given a leaked file, trace the leaker:

```ts
import { recover } from "@antirea/watermark";
const tokens = recover(leakedFileContents);     // ["wm_…"]
store.get(tokens[0]);                            // { viewer, path, createdTs }
```

Modes:
- **`zerowidth`** (default) — the token is hidden in invisible zero-width
  characters. Stealthy; survives copy-paste and most minifiers.
- **`comment`** — a `/*!wm:<token>*/` bang comment. Robust in code, but a
  minifier set to strip *all* comments removes it.

## 2. Canary scanning

Search public code for your tokens so a leak surfaces:

```bash
GITHUB_TOKEN=ghp_xxx node packages/watermark/scan-cli.mjs --file tokens.txt
# exits non-zero (and lists repos/URLs) if any token is found — good for cron
```

Programmatically (injectable fetch for tests / other hosts):

```ts
import { scanGitHub } from "@antirea/watermark";
const hits = await scanGitHub(["wm_abc…"], { token: process.env.GITHUB_TOKEN });
```

Limit: finds only tokens pushed to *indexed, public* code — not private leaks or
pastebins.

## 3. Alerts (spike and canary)

The collector can POST to a webhook when detections spike or a canary is read. In
`packages/collector/.env`:

```
ALERT_WEBHOOK_URL=https://hooks.slack.com/services/…
ALERT_WINDOW_MIN=5
ALERT_THRESHOLD=50
ALERT_WEBHOOK_SECRET=        # optional, 16+ characters: sign every alert
ALERT_ON_CANARY=true         # alert when a source-map canary is read
```

Two alerts are sent:

| `event` | When | Fields |
|---|---|---|
| `spike` | `ALERT_THRESHOLD` events inside `ALERT_WINDOW_MIN` | `site`, `window_min`, `threshold` |
| `canary` | the honeypot reports a source-map canary read (see [`REA-SIGNATURES.md`](./REA-SIGNATURES.md)) | `site`, `path`, `action`, `score`, `reasons`, `country` |

Every body also has a `text` line, which Slack and Discord display.

**What leaves your server.** The webhook receiver is a third party. Alerts
carry no IP address, no IP hash, no User-Agent and no session id — only the
fields above. If you point the webhook at a service outside your organisation,
list it as a recipient in your privacy documentation.

**Verifying an alert.** With `ALERT_WEBHOOK_SECRET` set, each request carries
`X-Antirea-Timestamp` (Unix seconds) and `X-Antirea-Signature`:

```ts
import { createHmac, timingSafeEqual } from "node:crypto";

function verify(secret: string, timestamp: string, rawBody: string, header: string): boolean {
  if (Math.abs(Date.now() / 1000 - Number(timestamp)) > 300) return false; // replay window
  const expected = "sha256=" + createHmac("sha256", secret).update(`${timestamp}.${rawBody}`).digest("hex");
  const a = Buffer.from(header);
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}
```

Slack and Discord incoming webhooks ignore these headers; the signature is for
your own endpoint.

**Limits.** The ingest endpoint is unauthenticated (browsers post to it), so an
alert can be triggered by a forged event: treat it as a prompt to open the
dashboard, not as proof. One alert per site per 10 minutes, which also means a
forged event can delay a real alert for that window. The webhook URL must be
`https` (plain `http` is accepted for `localhost` only) and the collector
refuses to start otherwise.

A built-in cooldown stops one incident from spamming the channel. You can also
use the `SpikeDetector` + `Alerter` directly in your own services (both accept
an injectable `fetch`).
