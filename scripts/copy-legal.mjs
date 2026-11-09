/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * prepack hook: copy the repo-root LICENSE and NOTICE into the package being
 * packed, so every published tarball carries them (Apache-2.0 §4(a) and §4(d),
 * including the author credit in NOTICE). Runs with cwd = the package dir.
 */
import { copyFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";

const root = resolve(process.cwd(), "..", "..");
for (const name of ["LICENSE", "NOTICE"]) {
  const src = resolve(root, name);
  if (!existsSync(src)) {
    console.error(`[copy-legal] missing ${src}`);
    process.exit(1);
  }
  copyFileSync(src, resolve(process.cwd(), name));
}
