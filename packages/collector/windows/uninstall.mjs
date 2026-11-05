/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * Uninstall the Antirea collector Windows Service (run as Administrator):
 *   node windows/uninstall.mjs
 */
import { buildService } from "./service.mjs";

const svc = buildService();
svc.on("uninstall", () => console.log("[antirea] service uninstalled."));
svc.on("error", (e) => console.error("[antirea] service error:", e));
svc.uninstall();
