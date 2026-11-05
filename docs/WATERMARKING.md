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

## 3. Attack-spike alerts

The collector can POST to a webhook when detections spike. In
`packages/collector/.env`:

```
ALERT_WEBHOOK_URL=https://hooks.slack.com/services/…
ALERT_WINDOW_MIN=5
ALERT_THRESHOLD=50
```

A built-in cooldown stops one incident from spamming the channel. You can also
use the `SpikeDetector` + `Alerter` directly in your own services (both accept
an injectable `fetch`).
