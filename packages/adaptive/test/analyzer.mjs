/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * Unit test for the deterministic analyzer + knowledge base (no network, no AI).
 * Build first (tsc), then: node packages/adaptive/test/analyzer.mjs
 */
import { summarize, heuristicProposals, MemoryKnowledgeStore, reinforce, SAFE_BOUNDS } from "../dist/index.js";

let pass = 0;
let fail = 0;
const ok = (c, m) => { if (c) pass++; else { fail++; console.log("FAIL:", m); } };

function rows(n, action, signals, country = "US", ip = (i) => "h" + i) {
  return Array.from({ length: n }, (_, i) => ({
    ts: 1000 + i, honeypotAction: action, country,
    ipHash: ip(i), signals: signals.map((name) => ({ name })),
  }));
}

// summarize counts correctly
{
  const data = [...rows(30, "would_decoy", ["cadence", "headerChurn"]), ...rows(70, "none", ["viewport.gap"])];
  const s = summarize(data, 0, 2000);
  ok(s.totalEvents === 100, "total events");
  ok(s.flaggedEvents === 30, "flagged events");
  ok(s.bySignal["cadence"] === 30, "signal count");
  ok(s.topSignalCombos[0].combo === "cadence+headerChurn" && s.topSignalCombos[0].count === 30, "top combo");
}

// heuristic: shadow + strong attack → propose live
{
  const s = summarize(rows(40, "would_decoy", ["cadence", "headerChurn"]), 0, 1);
  const p = heuristicProposals(s, { siteId: "x", currentMode: "shadow", currentThreshold: 0.7 });
  ok(p.some((x) => x.type === "mode" && x.proposed === "live"), "proposes live under attack");
}

// heuristic: high flag rate → lower threshold, clamped to bounds
{
  const s = summarize(rows(60, "decoy", ["cadence"]), 0, 1);
  const p = heuristicProposals(s, { siteId: "x", currentMode: "live", currentThreshold: 0.7 });
  const thr = p.find((x) => x.type === "threshold");
  ok(thr && thr.proposed >= SAFE_BOUNDS.thresholdMin && thr.proposed < 0.7, "lowers threshold within bounds");
}

// heuristic: large quiet traffic + aggressive threshold → raise it
{
  const s = summarize(rows(300, "none", ["viewport.gap"]), 0, 1);
  const p = heuristicProposals(s, { siteId: "x", currentMode: "live", currentThreshold: 0.5 });
  ok(p.some((x) => x.type === "threshold" && x.proposed > 0.5), "raises threshold when quiet");
}

// knowledge base confidence grows and stays < 1
{
  const kb = new MemoryKnowledgeStore();
  const a = reinforce(kb, "cadence+headerChurn", 5);
  const b = reinforce(kb, "cadence+headerChurn", 50);
  ok(b.confidence > a.confidence && b.confidence < 1, "confidence grows, bounded < 1");
  ok(b.occurrences === 55, "occurrences accumulate");
}

console.log(`\nRESULT: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
