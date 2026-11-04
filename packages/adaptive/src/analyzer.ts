/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * Deterministic analysis: turns raw event rows into an aggregated, non-PII
 * AttackSummary and a set of heuristic proposals. No network, no AI — this
 * runs even when the AI layer is disabled, and is fully unit-testable.
 */
import { SAFE_BOUNDS, type AttackSummary, type Proposal } from "./types.js";

export interface EventRow {
  ts: number;
  signals: Array<{ name: string }>;
  country: string;
  honeypotAction: string | null;
  ipHash: string;
}

function clampThreshold(v: number): number {
  return Math.min(SAFE_BOUNDS.thresholdMax, Math.max(SAFE_BOUNDS.thresholdMin, v));
}

export function summarize(rows: EventRow[], windowStart: number, windowEnd: number): AttackSummary {
  const bySignal: Record<string, number> = {};
  const byCountry: Record<string, number> = {};
  const byAction: Record<string, number> = {};
  const combos = new Map<string, number>();
  const sources = new Set<string>();
  let flagged = 0;

  for (const r of rows) {
    sources.add(r.ipHash);
    const action = r.honeypotAction ?? "none";
    byAction[action] = (byAction[action] ?? 0) + 1;
    if (action === "decoy" || action === "would_decoy") flagged += 1;
    if (r.country) byCountry[r.country] = (byCountry[r.country] ?? 0) + 1;

    const names = [...new Set(r.signals.map((s) => s.name))].sort();
    for (const n of names) bySignal[n] = (bySignal[n] ?? 0) + 1;
    if (names.length >= 2) {
      const combo = names.join("+");
      combos.set(combo, (combos.get(combo) ?? 0) + 1);
    }
  }

  const topSignalCombos = [...combos.entries()]
    .map(([combo, count]) => ({ combo, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 10);

  return {
    windowStart,
    windowEnd,
    totalEvents: rows.length,
    flaggedEvents: flagged,
    uniqueSources: sources.size,
    bySignal,
    byCountry,
    byAction,
    topSignalCombos,
  };
}

export interface HeuristicContext {
  siteId: string;
  currentMode: "shadow" | "live";
  currentThreshold: number;
}

let heuristicCounter = 0;
function pid(prefix: string): string {
  heuristicCounter += 1;
  return `${prefix}-${Date.now().toString(36)}-${heuristicCounter}`;
}

/**
 * Heuristic proposals derived from the summary. Conservative and bounded:
 * these only tune sensitivity or surface patterns — never auto-hard-block.
 */
export function heuristicProposals(summary: AttackSummary, ctx: HeuristicContext): Proposal[] {
  const out: Proposal[] = [];
  const now = Date.now();
  const flaggedRate = summary.totalEvents > 0 ? summary.flaggedEvents / summary.totalEvents : 0;

  // 1. Strong, repeated attack evidence while only in shadow → suggest going live.
  if (ctx.currentMode === "shadow" && summary.flaggedEvents >= 20 && flaggedRate >= 0.3) {
    out.push({
      id: pid("h"),
      createdTs: now,
      siteId: ctx.siteId,
      type: "mode",
      source: "heuristic",
      rationale: `${summary.flaggedEvents} flagged events (${Math.round(flaggedRate * 100)}% of traffic) while in shadow. Consider enabling live decoys.`,
      confidence: Math.min(0.9, 0.4 + flaggedRate),
      current: ctx.currentMode,
      proposed: "live",
      status: "pending",
    });
  }

  // 2. Very high flagged rate → tighten threshold a little (more decoys).
  if (flaggedRate >= 0.5 && ctx.currentThreshold > SAFE_BOUNDS.thresholdMin + 0.05) {
    const proposed = clampThreshold(ctx.currentThreshold - 0.1);
    out.push({
      id: pid("h"),
      createdTs: now,
      siteId: ctx.siteId,
      type: "threshold",
      source: "heuristic",
      rationale: `Sustained attack pressure (${Math.round(flaggedRate * 100)}% flagged). Lowering the threshold catches more of the same pattern.`,
      confidence: 0.6,
      current: ctx.currentThreshold,
      proposed,
      status: "pending",
    });
  }

  // 3. Almost nothing flagged but threshold is aggressive → relax to cut false positives.
  if (summary.totalEvents >= 200 && flaggedRate < 0.01 && ctx.currentThreshold < 0.75) {
    const proposed = clampThreshold(ctx.currentThreshold + 0.1);
    out.push({
      id: pid("h"),
      createdTs: now,
      siteId: ctx.siteId,
      type: "threshold",
      source: "heuristic",
      rationale: `Very low flag rate over ${summary.totalEvents} events. Raising the threshold reduces false positives for real users.`,
      confidence: 0.5,
      current: ctx.currentThreshold,
      proposed,
      status: "pending",
    });
  }

  // 4. A dominant signal combo worth watching.
  const top = summary.topSignalCombos[0];
  if (top && top.count >= 10) {
    out.push({
      id: pid("h"),
      createdTs: now,
      siteId: ctx.siteId,
      type: "watch",
      source: "heuristic",
      rationale: `Recurring attack signature "${top.combo}" seen ${top.count} times. Added to the knowledge base for monitoring.`,
      confidence: Math.min(0.85, 0.3 + top.count / 100),
      current: top.combo,
      proposed: top.combo,
      status: "pending",
    });
  }

  return out;
}

export { clampThreshold };
