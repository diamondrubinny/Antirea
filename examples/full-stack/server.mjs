/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * Run the full-stack demo:  node examples/full-stack/server.mjs
 * Open http://localhost:3000 — the page loads the guard (with domain lock),
 * and all the server layers are wired in app.mjs.
 */
import express from "express";
import { createApp } from "./app.mjs";

const { app } = await createApp();

// Serve the built guard and a demo page.
app.use("/guard", express.static(new URL("../../packages/guard/dist", import.meta.url).pathname));
app.get("/", (_req, res) => {
  res.type("html").send(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Antirea full-stack demo</title>
<meta name="antirea-nonce" content="demo"></head>
<body style="font-family:system-ui;max-width:40rem;margin:3rem auto">
  <h1>Antirea — all layers</h1>
  <p>Open DevTools and watch the console / your collector for detection events.</p>
  <script src="/guard/antirea-guard.iife.js"
          data-site-id="full-demo"
          data-endpoint="/api/events"
          data-mode="silent"></script>
  <script type="module">
    // domain-lock + CDP detection run via the guard above (data-* init).
    // Server-side logic stays off the client:
    const s = await (await fetch("/secure/session", { method:"POST" })).json();
    const r = await fetch("/secure/invoke", { method:"POST",
      headers:{ "content-type":"application/json", authorization:"Bearer "+s.token },
      body: JSON.stringify({ name:"pricing", args:{x:2}, nonce: String(Math.random()) }) });
    console.log("pricing(2) =", (await r.json()).result?.result, "(computed on the server)");
  </script>
</body></html>`);
});

app.listen(3000, () => console.log("Antirea full-stack demo on http://localhost:3000"));
