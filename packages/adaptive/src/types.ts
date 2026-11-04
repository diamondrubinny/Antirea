/**
 * Types for the adaptive-defense layer.
 *
 * Design rule: the AI and the heuristics only ever produce PROPOSALS. Nothing
 * here mutates live defenses on its own. Applying a proposal is a separate,
 * bounded, logged, reversible step (human-approved by default). This keeps an
 * attacker who poisons the input telemetry from steering defenses directly.
 */

/** An aggregated, NON-PII snapshot of recent activity. Safe to send to an AI. */
export interface AttackSummary {
  windowStart: number;
  windowEnd: number;
  totalEvents: number;
  /** Events the honeypot flagged (would_decoy or decoy). */
  flaggedEvents: number;
  uniqueSources: number;
  /** signal name -> count. No raw UA, no IP. */
  bySignal: Record<string, number>;
  /** ISO country code -> count. */
  byCountry: Record<string, number>;
  /** honeypot action -> count. */
  byAction: Record<string, number>;
  /** Most frequent co-occurring signal sets (as sorted "a+b+c"). */
  topSignalCombos: Array<{ combo: string; count: number }>;
}

/** A learned attack signature stored in the knowledge base. */
export interface KnowledgeSignature {
  id: string;
  /** Sorted signal combo, e.g. "cadence+headerChurn". */
  pattern: string;
  confidence: number; // 0..1, grows with repeated observation
  occurrences: number;
  firstSeen: number;
  lastSeen: number;
}

export type ProposalType = "threshold" | "mode" | "watch";
export type ProposalStatus = "pending" | "approved" | "rejected" | "applied";
export type ProposalSource = "heuristic" | "ai";

/** A bounded, reversible recommendation to change a defense. */
export interface Proposal {
  id: string;
  createdTs: number;
  siteId: string;
  type: ProposalType;
  source: ProposalSource;
  /** Human-readable, non-authoritative rationale. */
  rationale: string;
  confidence: number; // 0..1
  /** Current value (for threshold/mode); informational for "watch". */
  current?: string | number;
  /** Proposed value (clamped to safe bounds before storage). */
  proposed?: string | number;
  status: ProposalStatus;
}

/** Hard safety bounds. The AI can never propose outside these. */
export const SAFE_BOUNDS = {
  /** Threshold is clamped here: never so low it would decoy most traffic. */
  thresholdMin: 0.4,
  thresholdMax: 0.95,
  /** Modes the adaptive layer may ever propose. Never auto-hard-block. */
  allowedModes: ["shadow", "live"] as const,
} as const;
