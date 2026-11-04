/**
 * Shared types for the antirea guard client library.
 */

/** Category of a detected reverse-engineering / analysis signal. */
export type SignalType =
  | "devtools"
  | "automation"
  | "integrity"
  | "console";

/** A single detection signal with an evadability note (honesty by design). */
export interface Signal {
  /** Category. */
  type: SignalType;
  /** Stable machine name, e.g. "navigator.webdriver". */
  name: string;
  /** Confidence 0..1 — heuristics are never certain. */
  confidence: number;
  /** Optional detail (never PII). */
  detail?: string;
}

/** A telemetry event sent to the collector. */
export interface GuardEvent {
  /** Schema version. */
  v: 1;
  /** Client-side timestamp (ms epoch). */
  ts: number;
  /** Non-persistent random session id (not cross-site stable). */
  sessionId: string;
  /** Site identifier configured by the integrator. */
  siteId: string;
  /** Detected signals in this event. */
  signals: Signal[];
  /** Page path (query stripped by default). */
  path: string;
  /** navigator.userAgent (coarse fingerprint, not PII on its own). */
  ua: string;
  /** Primary language. */
  lang: string;
  /** Screen "WxH". */
  screen: string;
  /** IANA timezone, best-effort. */
  tz: string;
}

/** Behaviour when signals are detected. */
export type GuardMode =
  /** Report only. Never touches the UI. Recommended default. */
  | "silent"
  /** Report + degrade: clear console, best-effort obstruction. */
  | "obstruct"
  /**
   * Report + halt the app. WARNING: harms legitimate users and
   * accessibility. Opt-in only, never the default.
   */
  | "aggressive";

/** Public configuration passed by the integrator. */
export interface GuardConfig {
  /** Required: identifies the protected site in the dashboard. */
  siteId: string;
  /** Collector endpoint, e.g. "https://collector.example.com/api/events". */
  endpoint: string;
  /** Behaviour on detection. Default: "silent". */
  mode?: GuardMode;
  /** How often to poll live detectors (ms). Default 1500. */
  pollMs?: number;
  /**
   * Run the CDP probe (incl. the intrusive `debugger`-timing trap). Catches
   * default/passive CDP attach (e.g. REA). Default true. Set false to avoid
   * `debugger` pauses when a developer legitimately opens DevTools.
   */
  cdpProbe?: boolean;
  /** How often to re-run the CDP probe (ms). Default 4000. */
  cdpIntervalMs?: number;
  /** Include full URL query in reports (may contain secrets!). Default false. */
  includeQuery?: boolean;
  /**
   * Force-enable in non-production. By default the guard disables itself
   * when it looks like a dev environment, to avoid breaking development.
   */
  enableInDev?: boolean;
  /** Optional callback invoked locally on every detection. */
  onDetect?: (signals: Signal[]) => void;
}
