/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * Browser client for @antirea/secure-fn. No node deps — safe to bundle.
 *
 * It obtains a session token, then invokes server-side functions. The client
 * holds NO secret and NO function logic: it only ships inputs and receives
 * outputs. There is nothing proprietary here for CDP/REA to read.
 */
export interface SecureClientConfig {
  /** Base path where the router is mounted, e.g. "/secure". */
  endpoint: string;
  /** Called when the server rejects (e.g. rate limited) — optional. */
  onReject?: (status: number) => void;
}

interface Session {
  token: string;
  /** Local expiry estimate, ms epoch. */
  exp: number;
}

function randomNonce(): string {
  const buf = new Uint8Array(16);
  crypto.getRandomValues(buf);
  return Array.from(buf, (b) => b.toString(16).padStart(2, "0")).join("");
}

export class SecureClient {
  private session: Session | null = null;
  private pending: Promise<Session> | null = null;

  constructor(private readonly cfg: SecureClientConfig) {}

  private base(): string {
    return this.cfg.endpoint.replace(/\/?$/, "");
  }

  private async getSession(): Promise<Session> {
    if (this.session && Date.now() < this.session.exp - 5_000) return this.session;
    if (this.pending) return this.pending;
    this.pending = (async () => {
      const res = await fetch(`${this.base()}/session`, { method: "POST", credentials: "same-origin" });
      if (!res.ok) throw new Error(`session failed: ${res.status}`);
      const data = (await res.json()) as { token: string; ttlMs: number };
      const session: Session = { token: data.token, exp: Date.now() + data.ttlMs };
      this.session = session;
      this.pending = null;
      return session;
    })();
    try {
      return await this.pending;
    } finally {
      this.pending = null;
    }
  }

  /** Invoke a server-side function. Returns its result. */
  async invoke<TOut = unknown>(name: string, args?: unknown): Promise<TOut> {
    const session = await this.getSession();
    const res = await fetch(`${this.base()}/invoke`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${session.token}` },
      credentials: "same-origin",
      body: JSON.stringify({ name, args, nonce: randomNonce() }),
    });
    if (res.status === 401) {
      // Session expired/invalid — drop it and retry once.
      this.session = null;
      const retrySession = await this.getSession();
      const retry = await fetch(`${this.base()}/invoke`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${retrySession.token}` },
        credentials: "same-origin",
        body: JSON.stringify({ name, args, nonce: randomNonce() }),
      });
      if (!retry.ok) {
        this.cfg.onReject?.(retry.status);
        throw new Error(`invoke failed: ${retry.status}`);
      }
      return ((await retry.json()) as { result: TOut }).result;
    }
    if (!res.ok) {
      this.cfg.onReject?.(res.status);
      throw new Error(`invoke failed: ${res.status}`);
    }
    return ((await res.json()) as { result: TOut }).result;
  }
}

export function createSecureClient(cfg: SecureClientConfig): SecureClient {
  return new SecureClient(cfg);
}
