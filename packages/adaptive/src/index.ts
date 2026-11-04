/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * @antirea/adaptive — learns from attack telemetry and proposes bounded
 * defense changes. Suggest-only by default; applying is a separate step.
 */
export { summarize, heuristicProposals, clampThreshold } from "./analyzer.js";
export type { EventRow, HeuristicContext } from "./analyzer.js";
export { AnthropicAdvisor } from "./advisor.js";
export type { Advisor, AdvisorContext, AnthropicAdvisorOptions } from "./advisor.js";
export { MemoryKnowledgeStore, reinforce } from "./knowledge.js";
export type { KnowledgeStore } from "./knowledge.js";
export { SAFE_BOUNDS } from "./types.js";
export type {
  AttackSummary,
  KnowledgeSignature,
  Proposal,
  ProposalType,
  ProposalStatus,
  ProposalSource,
} from "./types.js";

import { heuristicProposals, summarize, type EventRow, type HeuristicContext } from "./analyzer.js";
import { reinforce, type KnowledgeStore } from "./knowledge.js";
import type { Advisor } from "./advisor.js";
import type { Proposal } from "./types.js";

export interface RecommendOptions {
  rows: EventRow[];
  windowStart: number;
  windowEnd: number;
  ctx: HeuristicContext;
  knowledge?: KnowledgeStore;
  /** Optional AI advisor; omit to run heuristics only. */
  advisor?: Advisor;
}

/**
 * Full analysis pass: summarize → heuristic proposals → reinforce knowledge →
 * optional AI proposals. Returns everything as PENDING proposals; nothing is
 * applied here.
 */
export async function recommend(opts: RecommendOptions): Promise<{
  summary: ReturnType<typeof summarize>;
  analysis: string;
  proposals: Proposal[];
}> {
  const summary = summarize(opts.rows, opts.windowStart, opts.windowEnd);
  const proposals: Proposal[] = heuristicProposals(summary, opts.ctx);

  if (opts.knowledge) {
    for (const { combo, count } of summary.topSignalCombos) reinforce(opts.knowledge, combo, count);
  }

  let analysis = "";
  if (opts.advisor) {
    try {
      const ai = await opts.advisor.advise(summary, opts.ctx);
      analysis = ai.analysis;
      proposals.push(...ai.proposals);
    } catch (e) {
      analysis = `AI advisor unavailable: ${(e as Error).message}`;
    }
  }

  return { summary, analysis, proposals };
}
