/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/** Server entry (node). Browser code imports from "@antirea/challenge/client". */
export { issueChallenge, verifySolution } from "./pow.js";
export type { PowConfig, Challenge, VerifyResult } from "./pow.js";
export { challengeRouter, requireProof } from "./middleware.js";
export type { RequireProofOptions } from "./middleware.js";
export { ReplayCache } from "./guards.js";
export { leadingZeroBits } from "./sha256.js";
