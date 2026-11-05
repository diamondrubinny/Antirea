/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * Canary tokens: unique, recoverable identifiers minted per recipient and
 * recorded so a token found "in the wild" names who received the leaked copy.
 */
import { randomBytes } from "node:crypto";

export interface CanaryRecord {
  token: string;
  /** Who/what received it (session id, user id, hashed IP, …). Non-PII preferred. */
  viewer: string;
  /** Optional asset/path the token was embedded in. */
  path?: string;
  createdTs: number;
}

export interface CanaryStore {
  put(rec: CanaryRecord): void;
  get(token: string): CanaryRecord | null;
  all(): CanaryRecord[];
}

/** In-memory store (default; back it with SQLite/DB for production). */
export class MemoryCanaryStore implements CanaryStore {
  private readonly map = new Map<string, CanaryRecord>();
  put(rec: CanaryRecord): void {
    this.map.set(rec.token, rec);
  }
  get(token: string): CanaryRecord | null {
    return this.map.get(token) ?? null;
  }
  all(): CanaryRecord[] {
    return [...this.map.values()];
  }
}

/** Mint a new canary token (prefix `wm_` + random). */
export function mintToken(): string {
  return `wm_${randomBytes(9).toString("hex")}`;
}

/** Mint + record a canary for a viewer, returning the token. */
export function issueCanary(store: CanaryStore, viewer: string, path?: string): string {
  const token = mintToken();
  store.put({ token, viewer, path, createdTs: Date.now() });
  return token;
}
