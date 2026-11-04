/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * Attestation-gated loader for proprietary client modules.
 *
 * The idea (defense in depth against CDP):
 *   - The proprietary module is NOT in the initial bundle.
 *   - Before fetching it, we run the CDP probe and send the verdict in a
 *     header. We also send a server-issued nonce (from a <meta> tag) to limit
 *     replay.
 *   - The server (see @antirea/honeypot) decides: clean probe -> real module;
 *     CDP/debugger detected OR request scores as automation -> decoy.
 *
 * LIMITATIONS:
 *   - The header verdict is attacker-FORGEABLE (an attacker can claim clean).
 *     Its value is catching default/passive REA and honest automation, and it
 *     is combined with INDEPENDENT server-side scoring, which does not trust
 *     the client. The durable protection is server-side logic + WASM.
 *   - Requires CSP to allow `blob:` in script-src for dynamic import.
 */
import { probeCdp, type CdpProbeOptions } from "./detectors/cdp";

export interface ProtectedLoaderConfig {
  /** Base endpoint that serves protected modules, e.g. "/__p/". */
  endpoint: string;
  /** Name of a <meta> tag holding a per-page server nonce. Default "antirea-nonce". */
  nonceMeta?: string;
  /** CDP probe tuning. */
  probe?: CdpProbeOptions;
}

function readNonce(metaName: string): string {
  try {
    const el = document.querySelector(`meta[name="${metaName}"]`);
    return el?.getAttribute("content") ?? "";
  } catch {
    return "";
  }
}

/** Fetch the raw source of a protected module, attaching the attestation header. */
export async function fetchProtected(name: string, cfg: ProtectedLoaderConfig): Promise<string> {
  const verdict = probeCdp(cfg.probe);
  const nonce = readNonce(cfg.nonceMeta ?? "antirea-nonce");
  const attest = JSON.stringify({
    cdp: verdict.detected,
    c: Number(verdict.confidence.toFixed(2)),
    pause: Math.round(verdict.maxPauseMs),
    nonce,
  });
  const url = cfg.endpoint.replace(/\/?$/, "/") + encodeURIComponent(name);
  const res = await fetch(url, {
    method: "GET",
    headers: { "X-Antirea-Attest": attest },
    credentials: "same-origin",
    cache: "no-store",
  });
  if (!res.ok) throw new Error(`protected fetch failed: ${res.status}`);
  return res.text();
}

/**
 * Fetch + dynamically import a protected ES module. Returns its namespace.
 * Note: whatever the server returns (real or decoy) is a valid module, so the
 * caller's code path is identical — the attacker gets inert behaviour, not an
 * error that reveals the gate.
 */
export async function importProtected(
  name: string,
  cfg: ProtectedLoaderConfig,
): Promise<Record<string, unknown>> {
  const code = await fetchProtected(name, cfg);
  const blob = new Blob([code], { type: "text/javascript" });
  const url = URL.createObjectURL(blob);
  try {
    return (await import(/* @vite-ignore */ url)) as Record<string, unknown>;
  } finally {
    URL.revokeObjectURL(url);
  }
}
