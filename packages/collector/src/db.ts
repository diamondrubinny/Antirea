/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * SQLite storage for antirea telemetry.
 *
 * Privacy: we store derived country + a salted IP hash (for unique counts),
 * NEVER the raw IP. See geo.ts.
 */
import Database from "better-sqlite3";

export interface StoredEvent {
  id?: number;
  ts: number;
  received_ts: number;
  site_id: string;
  session_id: string;
  source: string; // "client" | "honeypot"
  path: string;
  ua: string;
  lang: string;
  screen: string;
  tz: string;
  country: string;
  ip_hash: string;
  signals_json: string;
  honeypot_action: string | null;
  honeypot_score: number | null;
}

export interface StatsRow {
  label: string;
  count: number;
}

export class Store {
  private readonly db: Database.Database;

  constructor(file: string) {
    this.db = new Database(file);
    this.db.pragma("journal_mode = WAL");
    this.migrate();
  }

  private migrate(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts INTEGER NOT NULL,
        received_ts INTEGER NOT NULL,
        site_id TEXT NOT NULL,
        session_id TEXT NOT NULL,
        source TEXT NOT NULL DEFAULT 'client',
        path TEXT NOT NULL,
        ua TEXT NOT NULL,
        lang TEXT NOT NULL,
        screen TEXT NOT NULL,
        tz TEXT NOT NULL,
        country TEXT NOT NULL,
        ip_hash TEXT NOT NULL,
        signals_json TEXT NOT NULL,
        honeypot_action TEXT,
        honeypot_score REAL
      );
      CREATE INDEX IF NOT EXISTS idx_events_site_ts ON events(site_id, received_ts);
      CREATE INDEX IF NOT EXISTS idx_events_country ON events(country);

      CREATE TABLE IF NOT EXISTS signals (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
        type TEXT NOT NULL,
        name TEXT NOT NULL,
        confidence REAL NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_signals_name ON signals(name);

      CREATE TABLE IF NOT EXISTS canaries (
        canary TEXT PRIMARY KEY,
        site_id TEXT NOT NULL,
        path TEXT NOT NULL,
        ip_hash TEXT NOT NULL,
        created_ts INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS site_config (
        site_id TEXT PRIMARY KEY,
        data TEXT NOT NULL,
        updated_ts INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS proposals (
        id TEXT PRIMARY KEY,
        site_id TEXT NOT NULL,
        created_ts INTEGER NOT NULL,
        type TEXT NOT NULL,
        source TEXT NOT NULL,
        rationale TEXT NOT NULL,
        confidence REAL NOT NULL,
        current_val TEXT,
        proposed_val TEXT,
        status TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_proposals_site ON proposals(site_id, status, created_ts);

      CREATE TABLE IF NOT EXISTS knowledge (
        site_id TEXT NOT NULL,
        pattern TEXT NOT NULL,
        id TEXT NOT NULL,
        confidence REAL NOT NULL,
        occurrences INTEGER NOT NULL,
        first_seen INTEGER NOT NULL,
        last_seen INTEGER NOT NULL,
        PRIMARY KEY (site_id, pattern)
      );
    `);
  }

  insertEvent(e: StoredEvent, signals: Array<{ type: string; name: string; confidence: number }>): number {
    const insert = this.db.prepare(`
      INSERT INTO events (ts, received_ts, site_id, session_id, source, path, ua, lang,
        screen, tz, country, ip_hash, signals_json, honeypot_action, honeypot_score)
      VALUES (@ts, @received_ts, @site_id, @session_id, @source, @path, @ua, @lang,
        @screen, @tz, @country, @ip_hash, @signals_json, @honeypot_action, @honeypot_score)
    `);
    const insertSig = this.db.prepare(`
      INSERT INTO signals (event_id, type, name, confidence) VALUES (?, ?, ?, ?)
    `);
    const tx = this.db.transaction(() => {
      const info = insert.run(e);
      const eventId = Number(info.lastInsertRowid);
      for (const s of signals) insertSig.run(eventId, s.type, s.name, s.confidence);
      return eventId;
    });
    return tx();
  }

  recordCanary(c: { canary: string; siteId: string; path: string; ipHash: string }): void {
    this.db
      .prepare(
        `INSERT OR IGNORE INTO canaries (canary, site_id, path, ip_hash, created_ts)
         VALUES (?, ?, ?, ?, ?)`,
      )
      .run(c.canary, c.siteId, c.path, c.ipHash, Date.now());
  }

  // --- Dashboard queries ---

  private siteClause(siteId?: string): { clause: string; params: unknown[] } {
    if (siteId) return { clause: "AND site_id = ?", params: [siteId] };
    return { clause: "", params: [] };
  }

  totals(sinceTs: number, siteId?: string): { events: number; uniques: number; sites: number } {
    const { clause, params } = this.siteClause(siteId);
    const row = this.db
      .prepare(
        `SELECT COUNT(*) AS events,
                COUNT(DISTINCT ip_hash) AS uniques,
                COUNT(DISTINCT site_id) AS sites
         FROM events WHERE received_ts >= ? ${clause}`,
      )
      .get(sinceTs, ...params) as { events: number; uniques: number; sites: number };
    return row;
  }

  byCountry(sinceTs: number, siteId?: string, limit = 20): StatsRow[] {
    const { clause, params } = this.siteClause(siteId);
    return this.db
      .prepare(
        `SELECT COALESCE(NULLIF(country,''),'??') AS label, COUNT(*) AS count
         FROM events WHERE received_ts >= ? ${clause}
         GROUP BY label ORDER BY count DESC LIMIT ?`,
      )
      .all(sinceTs, ...params, limit) as StatsRow[];
  }

  bySignal(sinceTs: number, siteId?: string, limit = 20): StatsRow[] {
    const { clause, params } = this.siteClause(siteId);
    return this.db
      .prepare(
        `SELECT s.name AS label, COUNT(*) AS count
         FROM signals s JOIN events e ON e.id = s.event_id
         WHERE e.received_ts >= ? ${clause}
         GROUP BY s.name ORDER BY count DESC LIMIT ?`,
      )
      .all(sinceTs, ...params, limit) as StatsRow[];
  }

  timeline(sinceTs: number, bucketMs: number, siteId?: string): StatsRow[] {
    const { clause, params } = this.siteClause(siteId);
    return this.db
      .prepare(
        `SELECT CAST(received_ts / ? AS INTEGER) * ? AS bucket, COUNT(*) AS count
         FROM events WHERE received_ts >= ? ${clause}
         GROUP BY bucket ORDER BY bucket ASC`,
      )
      .all(bucketMs, bucketMs, sinceTs, ...params)
      .map((r) => ({
        label: String((r as { bucket: number }).bucket),
        count: (r as { count: number }).count,
      }));
  }

  recent(sinceTs: number, siteId?: string, limit = 100): StoredEvent[] {
    const { clause, params } = this.siteClause(siteId);
    return this.db
      .prepare(
        `SELECT * FROM events WHERE received_ts >= ? ${clause}
         ORDER BY received_ts DESC LIMIT ?`,
      )
      .all(sinceTs, ...params, limit) as StoredEvent[];
  }

  honeypotBreakdown(sinceTs: number, siteId?: string): StatsRow[] {
    const { clause, params } = this.siteClause(siteId);
    return this.db
      .prepare(
        `SELECT COALESCE(honeypot_action,'client') AS label, COUNT(*) AS count
         FROM events WHERE received_ts >= ? ${clause}
         GROUP BY label ORDER BY count DESC`,
      )
      .all(sinceTs, ...params) as StatsRow[];
  }

  /** Top offending sources (by hashed IP) in the window. */
  topOffenders(
    sinceTs: number,
    siteId?: string,
    limit = 50,
  ): Array<{
    label: string;
    count: number;
    country: string;
    lastAction: string | null;
  }> {
    const { clause, params } = this.siteClause(siteId);
    return this.db
      .prepare(
        `SELECT ip_hash AS label, COUNT(*) AS count,
                COALESCE(NULLIF(MAX(country),''),'??') AS country,
                MAX(honeypot_action) AS lastAction
         FROM events WHERE received_ts >= ? ${clause}
         GROUP BY ip_hash ORDER BY count DESC LIMIT ?`,
      )
      .all(sinceTs, ...params, limit) as Array<{
      label: string;
      count: number;
      country: string;
      lastAction: string | null;
    }>;
  }

  getConfig(siteId: string): Record<string, unknown> | null {
    const row = this.db.prepare(`SELECT data FROM site_config WHERE site_id = ?`).get(siteId) as
      { data: string } | undefined;
    if (!row) return null;
    try {
      return JSON.parse(row.data) as Record<string, unknown>;
    } catch {
      return null;
    }
  }

  setConfig(siteId: string, data: Record<string, unknown>): void {
    this.db
      .prepare(
        `INSERT INTO site_config (site_id, data, updated_ts) VALUES (?, ?, ?)
         ON CONFLICT(site_id) DO UPDATE SET data = excluded.data, updated_ts = excluded.updated_ts`,
      )
      .run(siteId, JSON.stringify(data), Date.now());
  }

  /** Event rows for adaptive analysis (signals parsed, hashed source only). */
  recentRows(
    sinceTs: number,
    siteId: string | undefined,
    limit = 5000,
  ): Array<{
    ts: number;
    signals: Array<{ name: string }>;
    country: string;
    honeypotAction: string | null;
    ipHash: string;
  }> {
    const { clause, params } = this.siteClause(siteId);
    const rows = this.db
      .prepare(
        `SELECT received_ts, signals_json, country, honeypot_action, ip_hash
         FROM events WHERE received_ts >= ? ${clause}
         ORDER BY received_ts DESC LIMIT ?`,
      )
      .all(sinceTs, ...params, limit) as Array<{
      received_ts: number;
      signals_json: string;
      country: string;
      honeypot_action: string | null;
      ip_hash: string;
    }>;
    return rows.map((r) => {
      let signals: Array<{ name: string }> = [];
      try {
        signals = (JSON.parse(r.signals_json) as Array<{ name: string }>).map((s) => ({ name: s.name }));
      } catch {
        /* ignore */
      }
      return {
        ts: r.received_ts,
        signals,
        country: r.country,
        honeypotAction: r.honeypot_action,
        ipHash: r.ip_hash,
      };
    });
  }

  // --- Proposals ---
  insertProposal(p: {
    id: string;
    siteId: string;
    createdTs: number;
    type: string;
    source: string;
    rationale: string;
    confidence: number;
    current?: string | number;
    proposed?: string | number;
    status: string;
  }): void {
    this.db
      .prepare(
        `INSERT OR REPLACE INTO proposals (id, site_id, created_ts, type, source, rationale, confidence, current_val, proposed_val, status)
         VALUES (@id, @siteId, @createdTs, @type, @source, @rationale, @confidence, @current, @proposed, @status)`,
      )
      .run({
        ...p,
        current: p.current === undefined ? null : String(p.current),
        proposed: p.proposed === undefined ? null : String(p.proposed),
      });
  }

  listProposals(siteId: string | undefined, status?: string, limit = 100): Array<Record<string, unknown>> {
    const parts: string[] = [];
    const params: unknown[] = [];
    if (siteId) {
      parts.push("site_id = ?");
      params.push(siteId);
    }
    if (status) {
      parts.push("status = ?");
      params.push(status);
    }
    const where = parts.length ? `WHERE ${parts.join(" AND ")}` : "";
    return this.db
      .prepare(`SELECT * FROM proposals ${where} ORDER BY created_ts DESC LIMIT ?`)
      .all(...params, limit) as Array<Record<string, unknown>>;
  }

  getProposal(id: string): Record<string, unknown> | null {
    return (
      (this.db.prepare(`SELECT * FROM proposals WHERE id = ?`).get(id) as Record<string, unknown>) ?? null
    );
  }

  setProposalStatus(id: string, status: string): void {
    this.db.prepare(`UPDATE proposals SET status = ? WHERE id = ?`).run(status, id);
  }

  // --- Knowledge ---
  knowledgeGet(
    siteId: string,
    pattern: string,
  ): {
    id: string;
    pattern: string;
    confidence: number;
    occurrences: number;
    firstSeen: number;
    lastSeen: number;
  } | null {
    const r = this.db
      .prepare(`SELECT * FROM knowledge WHERE site_id = ? AND pattern = ?`)
      .get(siteId, pattern) as
      | {
          id: string;
          pattern: string;
          confidence: number;
          occurrences: number;
          first_seen: number;
          last_seen: number;
        }
      | undefined;
    if (!r) return null;
    return {
      id: r.id,
      pattern: r.pattern,
      confidence: r.confidence,
      occurrences: r.occurrences,
      firstSeen: r.first_seen,
      lastSeen: r.last_seen,
    };
  }

  knowledgePut(
    siteId: string,
    sig: {
      id: string;
      pattern: string;
      confidence: number;
      occurrences: number;
      firstSeen: number;
      lastSeen: number;
    },
  ): void {
    this.db
      .prepare(
        `INSERT OR REPLACE INTO knowledge (site_id, pattern, id, confidence, occurrences, first_seen, last_seen)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(siteId, sig.pattern, sig.id, sig.confidence, sig.occurrences, sig.firstSeen, sig.lastSeen);
  }

  knowledgeList(
    siteId: string,
    limit = 50,
  ): Array<{
    id: string;
    pattern: string;
    confidence: number;
    occurrences: number;
    firstSeen: number;
    lastSeen: number;
  }> {
    const rows = this.db
      .prepare(`SELECT * FROM knowledge WHERE site_id = ? ORDER BY confidence DESC LIMIT ?`)
      .all(siteId, limit) as Array<{
      id: string;
      pattern: string;
      confidence: number;
      occurrences: number;
      first_seen: number;
      last_seen: number;
    }>;
    return rows.map((r) => ({
      id: r.id,
      pattern: r.pattern,
      confidence: r.confidence,
      occurrences: r.occurrences,
      firstSeen: r.first_seen,
      lastSeen: r.last_seen,
    }));
  }

  /** Distinct site ids that have config or recent events (for scheduled analysis). */
  knownSites(sinceTs: number): string[] {
    const a = this.db.prepare(`SELECT site_id FROM site_config`).all() as Array<{ site_id: string }>;
    const b = this.db
      .prepare(`SELECT DISTINCT site_id FROM events WHERE received_ts >= ?`)
      .all(sinceTs) as Array<{ site_id: string }>;
    return [...new Set([...a.map((x) => x.site_id), ...b.map((x) => x.site_id)])];
  }

  /** Delete events older than the retention cutoff. Returns rows removed. */
  pruneOlderThan(cutoffTs: number): number {
    const info = this.db.prepare(`DELETE FROM events WHERE received_ts < ?`).run(cutoffTs);
    return info.changes;
  }

  close(): void {
    this.db.close();
  }
}
