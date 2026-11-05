# Security Policy

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.**

Report privately via GitHub's **"Report a vulnerability"** button under the
repository's **Security** tab (Security advisories → Report a vulnerability).
This opens a private channel with the maintainer.

Please include:

- affected package(s) and version/commit,
- a description and, if possible, a minimal reproduction,
- the impact you foresee.

You can expect an initial acknowledgement within a reasonable time; fixes are
prioritized by severity.

## Scope and honest expectations

Antirea is defensive tooling. Its guarantees differ by layer, and this is
stated plainly in the README and source:

- **`@antirea/secure-fn` (server-side execution)** is the only layer that
  *hermetically* protects proprietary logic — code that never reaches the
  browser cannot be reverse-engineered.
- **Client-side detection, honeypot, and fingerprints** are deterrence and
  intelligence. They raise the cost of analysis and surface attempts; they do
  **not** make client-delivered code unreadable, and a determined operator can
  evade individual signals (documented per signature).

Reports that a client-side signal can be evaded are **expected behaviour**, not
vulnerabilities — see `docs/REA-SIGNATURES.md`. Genuine security issues include:
authentication/authorization bypass in the collector, injection, SSRF, secret
leakage, bypass of the `secure-fn` session/replay/rate-limit guards, or the
adaptive layer applying an out-of-bounds change.

## Supported versions

This project is pre-1.0. Only the latest `main` receives security fixes.

| Version | Supported |
|---|---|
| `main` (latest) | ✅ |
| older commits | ❌ |
