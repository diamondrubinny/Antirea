/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * Install the Antirea collector as a Windows Service (run as Administrator):
 *   node windows/install.mjs
 */
import { buildService } from "./service.mjs";

const svc = buildService();
svc.on("install", () => {
  console.log("[antirea] service installed. Starting…");
  svc.start();
});
svc.on("alreadyinstalled", () => console.log("[antirea] service already installed."));
svc.on("start", () => console.log("[antirea] Antirea Collector is running (http://localhost:8080/)."));
svc.on("error", (e) => console.error("[antirea] service error:", e));
svc.install();
