/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/** Server entry (node). Browser code must import from "./client" directly. */
export { createSecureFnRouter } from "./server.js";
export type { SecureFn, SecureFnOptions, InvokeContext } from "./server.js";
export { signToken, verifyToken } from "./signing.js";
export type { TokenPayload } from "./signing.js";
