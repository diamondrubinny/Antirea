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

/**
 * Shape of a server function map, for typing the client. Use it with a
 * type-only import so no server code reaches the browser bundle:
 *
 *   // server/functions.ts
 *   export const functions = { pricing: (a: { x: number }) => a.x * 2 };
 *   export type Api = typeof functions;
 *
 *   // browser
 *   import type { Api } from "../server/functions";
 *   const api = createSecureClient<Api>({ endpoint: "/secure" });
 *   const price = await api.call("pricing", { x: 2 }); // number
 *
 * Types describe the contract; they do not validate anything at run time.
 * The server must still validate its arguments — they come from the network.
 */
export type SecureApi = Record<string, (args: any, ctx: any) => unknown>;

/** Argument type of a server function (`never` when it takes none). */
export type ArgsOf<F> = F extends (...args: infer P) => unknown ? (P extends [] ? never : P[0]) : never;
/** Resolved result type of a server function. */
export type ResultOf<F> = F extends (...args: any[]) => infer R ? Awaited<R> : never;

/** `call` takes no argument, an optional one, or a required one, as the function declares. */
type CallArgs<F> = [ArgsOf<F>] extends [never]
  ? []
  : undefined extends ArgsOf<F>
    ? [args?: ArgsOf<F>]
    : [args: ArgsOf<F>];

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

export class SecureClient<T extends SecureApi = SecureApi> {
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

  /**
   * Typed invoke: the function name, its argument and its result are checked
   * against the server's function map `T`. Same request as `invoke`.
   */
  call<K extends keyof T & string>(name: K, ...args: CallArgs<T[K]>): Promise<ResultOf<T[K]>> {
    return this.invoke<ResultOf<T[K]>>(name, args[0]);
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

export function createSecureClient<T extends SecureApi = SecureApi>(
  cfg: SecureClientConfig,
): SecureClient<T> {
  return new SecureClient<T>(cfg);
}
