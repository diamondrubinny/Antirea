# Contributing to Antirea

Thanks for your interest! Antirea is an Apache-2.0 project authored by
**Diamond Rubinny**. Contributions are welcome under the terms below.

## Ground rules

- **Keep the credit.** Per Apache-2.0 §4 and `NOTICE`, retain the per-file
  credit headers and attribution. Add yourself to a `Co-authored-by` trailer if
  you like — don't remove existing notices.
- **Be honest in docs and comments.** This project deliberately states what is
  hermetic (server-side execution) and what is only deterrence (client-side).
  Don't add claims that client-delivered code is unbreakable.
- **No secrets in code.** Use env vars; never commit API keys, tokens, or real
  personal data.

## Development

Requirements: Node.js ≥ 20 (22 recommended).

```bash
npm install                      # workspaces
npm run build --workspaces --if-present
npm test   --workspaces --if-present
```

Per-package:

```bash
npm run build -w @antirea/guard      # tsc + vite (produces dist/)
npm test       -w @antirea/honeypot  # behaviour + scoring suites
```

The collector needs native deps (`better-sqlite3`) and, optionally,
`geoip-lite`; run a full `npm install` (without `--ignore-scripts`) before
starting it. See `packages/collector/.env.example`.

## Tests

Every package ships a dependency-free test runner (`node test/*.mjs`). Add a
case for any detection rule or security-relevant change. Keep tests
deterministic (no network).

## Adding a dashboard language

The control panel is translated in `packages/collector/public/i18n.js`. Add a
language by copying the `en` block, translating the values (keep the keys), and
setting `_dir` to `"rtl"` for right-to-left scripts. English is authoritative;
untranslated keys fall back to English automatically.

## Adding or updating a REA / tool signature

Verify new fingerprints against the tool's **public source** and record the
source file and the signature's **evadability** in `docs/REA-SIGNATURES.md`.
Don't ship a signature you can't point to in source.

## Pull requests

- One focused change per PR; describe what and why.
- Run the build + tests locally first; CI must be green.
- Update docs (`README.md`, `PLAN.md`, `docs/`) when behaviour changes.
