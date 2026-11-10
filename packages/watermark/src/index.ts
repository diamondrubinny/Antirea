/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
export { embed, recover, stripZeroWidth } from "./embed.js";
export type { WatermarkMode } from "./embed.js";
export { mintToken, issueCanary, MemoryCanaryStore } from "./canary.js";
export type { CanaryStore, CanaryRecord } from "./canary.js";
export { watermark, watermarkText } from "./watermark.js";
export type { WatermarkOptions } from "./watermark.js";
export { buildGitHubQuery, parseGitHubResults, scanGitHub } from "./scan.js";
export type { ScanHit, GitHubScanOptions } from "./scan.js";
export { SpikeDetector, Alerter, signWebhook } from "./alerts.js";
export type { AlertConfig } from "./alerts.js";
