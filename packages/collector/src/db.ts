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
    `);
  }

  insertEvent(
    e: StoredEvent,
    signals: Array<{ type: string; name: string; confidence: number }>,
  ): number {
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
      .map((r) => ({ label: String((r as { bucket: number }).bucket), count: (r as { count: number }).count }));
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

  /** Delete events older than the retention cutoff. Returns rows removed. */
  pruneOlderThan(cutoffTs: number): number {
    const info = this.db.prepare(`DELETE FROM events WHERE received_ts < ?`).run(cutoffTs);
    return info.changes;
  }

  close(): void {
    this.db.close();
  }
}
