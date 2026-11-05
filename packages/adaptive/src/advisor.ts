/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * Optional AI advisor. Sends ONLY the aggregated, non-PII AttackSummary to an
 * LLM and asks for analysis + proposals. Default provider: Anthropic Claude
 * (bring your own API key). The SDK is lazy-loaded so the system runs without
 * it and without a key.
 *
 * SECURITY: the model output is UNTRUSTED. Every returned proposal is strictly
 * validated and clamped to SAFE_BOUNDS before it can become a stored proposal.
 * A poisoned or prompt-injected model therefore cannot push a defense change
 * outside the safe envelope, and nothing is applied without approval (unless
 * the operator explicitly enables bounded auto-apply).
 *
 * PRIVACY: only AttackSummary (counts, country codes, signal names) is sent —
 * never raw IPs or User-Agent strings.
 */
import { clampThreshold } from "./analyzer.js";
import { SAFE_BOUNDS, type AttackSummary, type Proposal } from "./types.js";

export interface AdvisorContext {
  siteId: string;
  currentMode: "shadow" | "live";
  currentThreshold: number;
}

export interface Advisor {
  advise(summary: AttackSummary, ctx: AdvisorContext): Promise<{ analysis: string; proposals: Proposal[] }>;
}

export interface AnthropicAdvisorOptions {
  /** API key. If absent, resolved by the SDK from the environment. */
  apiKey?: string;
  /** Model id. Default claude-opus-5-5. */
  model?: string;
  /** Hard cap on proposals accepted from the model. Default 5. */
  maxProposals?: number;
}

const SYSTEM_PROMPT = `You are a defensive-security analyst for an anti-reverse-engineering system.
You receive an AGGREGATED, anonymized summary of recent traffic (counts only; no IPs, no user agents).
Your job: judge whether the site is under automated analysis/scraping, and propose BOUNDED defense tweaks.

You may only propose these change types:
- "threshold": a detection sensitivity in [${SAFE_BOUNDS.thresholdMin}, ${SAFE_BOUNDS.thresholdMax}] (lower = more aggressive).
- "mode": either "shadow" (report only) or "live" (serve decoys).
- "watch": a signal pattern to monitor (no enforcement).

Rules:
- Be conservative. Only recommend aggressive changes with strong, repeated evidence.
- Never recommend blocking all traffic or anything outside the bounds above.
- Prefer "watch" and small threshold steps over large jumps.
Respond with ONLY a JSON object, no prose, no code fences:
{"analysis":"<=2 sentences","proposals":[{"type":"threshold|mode|watch","proposed":<number|string>,"rationale":"...","confidence":0..1}]}`;

function stripFences(s: string): string {
  return s
    .replace(/^```(?:json)?\s*/i, "")
    .replace(/\s*```$/i, "")
    .trim();
}

let counter = 0;
function pid(): string {
  counter += 1;
  return `ai-${Date.now().toString(36)}-${counter}`;
}

/** Validate + clamp a single model-proposed item into a safe Proposal, or drop it. */
function sanitize(raw: unknown, ctx: AdvisorContext): Proposal | null {
  if (!raw || typeof raw !== "object") return null;
  const o = raw as Record<string, unknown>;
  const type = o.type;
  const rationale = typeof o.rationale === "string" ? o.rationale.slice(0, 500) : "";
  let confidence = typeof o.confidence === "number" ? o.confidence : 0.5;
  confidence = Math.min(1, Math.max(0, confidence));
  const base = {
    id: pid(),
    createdTs: Date.now(),
    siteId: ctx.siteId,
    source: "ai" as const,
    rationale,
    confidence,
    status: "pending" as const,
  };

  if (type === "threshold") {
    const n = typeof o.proposed === "number" ? o.proposed : Number(o.proposed);
    if (!Number.isFinite(n)) return null;
    return { ...base, type: "threshold", current: ctx.currentThreshold, proposed: clampThreshold(n) };
  }
  if (type === "mode") {
    const m = String(o.proposed);
    if (!(SAFE_BOUNDS.allowedModes as readonly string[]).includes(m)) return null;
    return { ...base, type: "mode", current: ctx.currentMode, proposed: m };
  }
  if (type === "watch") {
    const p = typeof o.proposed === "string" ? o.proposed.slice(0, 200) : "";
    if (!p) return null;
    return { ...base, type: "watch", current: p, proposed: p };
  }
  return null;
}

export class AnthropicAdvisor implements Advisor {
  private readonly model: string;
  private readonly maxProposals: number;
  private readonly apiKey?: string;

  constructor(opts: AnthropicAdvisorOptions = {}) {
    this.model = opts.model ?? "claude-opus-5-5";
    this.maxProposals = opts.maxProposals ?? 5;
    this.apiKey = opts.apiKey;
  }

  async advise(
    summary: AttackSummary,
    ctx: AdvisorContext,
  ): Promise<{ analysis: string; proposals: Proposal[] }> {
    // Lazy-load the SDK so the package works without it installed.
    let Anthropic: new (opts?: { apiKey?: string }) => {
      messages: {
        create: (args: unknown) => Promise<{ content: Array<{ type: string; text?: string }> }>;
      };
    };
    try {
      // Non-literal specifier: optional peer dep, resolved only at runtime.
      const sdkName = "@anthropic-ai/sdk";
      const mod = (await import(sdkName)) as unknown as { default: typeof Anthropic };
      Anthropic = mod.default;
    } catch {
      throw new Error("[adaptive] @anthropic-ai/sdk not installed; cannot run the AI advisor");
    }

    const client = new Anthropic(this.apiKey ? { apiKey: this.apiKey } : undefined);
    const userContent = JSON.stringify({
      currentMode: ctx.currentMode,
      currentThreshold: ctx.currentThreshold,
      summary,
    });

    const response = await client.messages.create({
      model: this.model,
      max_tokens: 1024,
      thinking: { type: "adaptive" },
      system: SYSTEM_PROMPT,
      messages: [{ role: "user", content: userContent }],
    });

    const textBlock = response.content.find((b) => b.type === "text");
    const text = textBlock?.text ?? "";
    let parsed: { analysis?: unknown; proposals?: unknown } = {};
    try {
      parsed = JSON.parse(stripFences(text)) as typeof parsed;
    } catch {
      return { analysis: "AI response could not be parsed.", proposals: [] };
    }

    const analysis = typeof parsed.analysis === "string" ? parsed.analysis.slice(0, 1000) : "";
    const rawList = Array.isArray(parsed.proposals) ? parsed.proposals.slice(0, this.maxProposals) : [];
    const proposals = rawList.map((r) => sanitize(r, ctx)).filter((p): p is Proposal => p !== null);
    return { analysis, proposals };
  }
}
