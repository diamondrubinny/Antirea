/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * Opens one issue asking Copilot to update REA signatures, and assigns Copilot.
 *
 * Called by .github/workflows/rea-watch.yml when npm `rea-agents` is newer than
 * the verified release. Reads public GitHub issue state only. Never downloads
 * or runs REA.
 *
 * Env:
 *   GITHUB_REPOSITORY   owner/repo
 *   VERIFIED            release our signatures were verified against
 *   LATEST              latest npm release
 *   GH_TOKEN            workflow token (issue create/comment/close)
 *   COPILOT_ASSIGN_TOKEN  user PAT that can assign Copilot (required to assign)
 *
 * `node scripts/open-rea-signature-task.mjs --print-body` prints the issue
 * body and exits, with no API calls.
 */
import { pathToFileURL } from "node:url";

const TITLE_RE = /^Re-verify REA signatures against rea-agents (\d+\.\d+\.\d+)$/;

const verified = process.env.VERIFIED ?? "";
const latest = process.env.LATEST ?? "";
const repo = process.env.GITHUB_REPOSITORY ?? "";

export function issueTitle(version) {
  return `Re-verify REA signatures against rea-agents ${version}`;
}

export function issueBody(verifiedVersion, latestVersion) {
  return `REA published **${latestVersion}**; our signatures were last verified against **${verifiedVersion}**.

Update the signatures and open a pull request. Do not merge.

This is defensive housekeeping for our own detection. Read public \`morluto/rea\` source at tag \`rea-agents-${latestVersion}\`. Do not clone REA to run it, do not attack any site, and do not write bypasses or stealth advice.

## What to compare

Against the verified release, read the changelog and these files for changes that reach a target site:

- \`src/browser/WebSourceMapFetcher.ts\` — \`Accept\`, \`redirect\`, \`credentials\`, \`referrerPolicy\`, and any new request headers
- \`src/domain/browserScenarioValues.ts\` and \`src/browser/PlaywrightScenarioBrowser.ts\` — launch defaults (headless, viewport, locale, timezone, color scheme, reduced motion, service workers) and any stealth or UA override
- \`src/browser/PlaywrightScenarioServiceWorkers.ts\` — \`rea-service-workers-\` / \`rea-restore-\` markers
- \`src/inspector/V8InspectorCaptureProjection.ts\` — pause suppression (\`setSkipAllPauses\`, \`setBreakpointsActive\`)
- \`src/browser/execution/CdpRuntimeSources.ts\` and \`src/browser/CdpCaptureEventHandlers.ts\` — source-map URL guessing vs declared maps

If a fingerprint moved, update the detector or signature pack, cite the source file, and record evadability in \`docs/REA-SIGNATURES.md\`. If nothing client-visible changed, still bump the verified version — do not invent signatures.

## Checklist

- [ ] Re-capture fixtures: \`xvfb-run -a node packages/honeypot/test/fixtures/capture.mjs\` and review the diff. Update \`expect\` only when the new behaviour is understood.
- [ ] Update \`reaVersion\` in the capture script, \`packages/honeypot/src/signatures.ts\`, \`packages/honeypot/signatures/default.json\` (regenerate with \`scripts/gen-signature-pack.mjs\` after a honeypot build), \`docs/REA-SIGNATURES.md\` (matrix, line citations, verified date) and the CHANGELOG.
- [ ] \`npm test\` — the fixture suite must report 0 false positives.
- [ ] Open a pull request that follows \`.github/pull_request_template.md\` and includes \`Fixes\` plus this issue number. Do not merge.

_Opened automatically by the \`REA upstream watch\` workflow._
`;
}

function customInstructions() {
  return (
    "Defensive signature update only. Read public rea-agents source; do not run REA and do not write bypasses. " +
    "Change fingerprints only when upstream behaviour changed; otherwise bump the verified version, citations, fixtures, and changelog. " +
    "Open a pull request. Do not merge. npm test must report 0 false positives."
  );
}

function fail(message) {
  console.error(message);
  process.exit(1);
}

function ghHeaders(token) {
  return {
    authorization: `Bearer ${token}`,
    accept: "application/vnd.github+json",
    "x-github-api-version": "2022-11-28",
    "user-agent": "antirea-rea-watch",
  };
}

async function gh(token, path, init = {}) {
  const res = await fetch(`https://api.github.com${path}`, {
    ...init,
    headers: { ...ghHeaders(token), ...(init.body ? { "content-type": "application/json" } : {}), ...init.headers },
    signal: AbortSignal.timeout(20_000),
  });
  const text = await res.text();
  let body = text;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    /* keep text */
  }
  if (!res.ok) {
    const detail = typeof body === "string" ? body : JSON.stringify(body);
    throw new Error(`${init.method ?? "GET"} ${path} → ${res.status}: ${detail.slice(0, 500)}`);
  }
  return body;
}

function isCopilot(login) {
  return login === "Copilot" || login === "copilot-swe-agent" || login === "copilot-swe-agent[bot]";
}

async function listOpenIssues(token) {
  const issues = [];
  for (let page = 1; page <= 5; page++) {
    const batch = await gh(token, `/repos/${repo}/issues?state=open&per_page=100&page=${page}`);
    if (!Array.isArray(batch) || batch.length === 0) break;
    for (const item of batch) if (!item.pull_request) issues.push(item);
    if (batch.length < 100) break;
  }
  return issues;
}

async function main() {
  if (process.argv.includes("--print-body")) {
    process.stdout.write(issueBody(verified || "0.0.0", latest || "0.0.0"));
    return;
  }
  if (!/^\d+\.\d+\.\d+/.test(verified) || !/^\d+\.\d+\.\d+/.test(latest)) {
    fail("VERIFIED and LATEST must be semver versions");
  }
  if (!/^[^/\s]+\/[^/\s]+$/.test(repo)) fail("GITHUB_REPOSITORY must be owner/repo");
  const token = process.env.GH_TOKEN;
  if (!token) fail("GH_TOKEN is required");

  const title = issueTitle(latest);
  const open = await listOpenIssues(token);
  let issue = open.find((item) => item.title === title);

  if (!issue) {
    issue = await gh(token, `/repos/${repo}/issues`, {
      method: "POST",
      body: JSON.stringify({ title, body: issueBody(verified, latest) }),
    });
    console.log(`Opened #${issue.number}: ${title}`);
  } else {
    console.log(`Issue #${issue.number} for ${latest} is already open.`);
  }

  const superseded = open.filter((item) => {
    if (item.number === issue.number) return false;
    return TITLE_RE.test(item.title);
  });
  for (const old of superseded) {
    await gh(token, `/repos/${repo}/issues/${old.number}/comments`, {
      method: "POST",
      body: JSON.stringify({
        body: `Superseded by #${issue.number} (rea-agents ${latest}). Do not update signatures against this older release.`,
      }),
    });
    await gh(token, `/repos/${repo}/issues/${old.number}`, {
      method: "PATCH",
      body: JSON.stringify({ state: "closed", state_reason: "not_planned" }),
    });
    console.log(`Closed superseded #${old.number}`);
  }

  const assignees = issue.assignees ?? [];
  if (assignees.some((a) => isCopilot(a.login))) {
    console.log(`#${issue.number} is already assigned to Copilot; not assigning again.`);
    return;
  }

  const assignToken = process.env.COPILOT_ASSIGN_TOKEN;
  if (!assignToken) {
    fail(
      `Issue #${issue.number} is open but Copilot was not assigned. Add repository secret COPILOT_ASSIGN_TOKEN ` +
        "(fine-grained PAT: metadata read; actions, contents, issues, and pull requests read/write). " +
        "The workflow GITHUB_TOKEN cannot assign Copilot.",
    );
  }

  await gh(assignToken, `/repos/${repo}/issues/${issue.number}/assignees`, {
    method: "POST",
    body: JSON.stringify({
      assignees: ["copilot-swe-agent[bot]"],
      agent_assignment: {
        target_repo: repo,
        base_branch: "main",
        custom_instructions: customInstructions(),
      },
    }),
  });
  console.log(`Assigned Copilot to #${issue.number}`);
}

const invokedDirectly =
  process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (invokedDirectly) {
  main().catch((err) => fail(err.message));
}
