# Plan — website accessibility, 404, security.txt, sitemap

Scope: `website/` only (static site, norea.rubinny.net). No tracking, no new
third parties, no personal data. Approved under "you decide the rest".

## Baseline (measured, axe-core 4 in Chromium, en/he/ar)

| Page | Violations |
|---|---|
| index.html | `link-in-text-block` (serious, 3 nodes), `region` (moderate, `#support`) |
| privacy.html | `link-in-text-block` (serious, 3–4 nodes) |

## Work items

1. **Fix the baseline violations**
   - Underline links inside running text (WCAG 1.4.1 — not colour alone).
   - Move `#support` inside a landmark.
2. **Accessibility statement** — `accessibility.html`, 6 languages (`a.*` keys):
   commitment; target WCAG 2.1 AA / IS 5568; adjustments made; how it was tested
   (self-assessed, automated + manual — *not* an external audit); known
   limitations (machine translations; images of the dashboard are illustrative);
   how to report a problem (GitHub issue — no personal email in the repo);
   response-time target; date.
3. **Accessibility toolbar** — `a11y.js`, a small keyboard/screen-reader-operable
   panel: larger text, high contrast, underline links, readable font, stop
   motion. Persisted in `localStorage` (strictly-necessary preference, same
   category as the consent choice; listed in the privacy table). Not a
   substitute for accessible code — stated in the statement.
4. **404 page** — `404.html`, localized, `noindex`. Wired for GitHub Pages
   (automatic), Apache (`ErrorDocument`) and nginx (`error_page`).
5. **security.txt** (RFC 9116) — `/.well-known/security.txt`: `Contact` = GitHub
   private advisory URL, `Expires` < 1 year, `Policy` = SECURITY.md,
   `Preferred-Languages`, `Canonical`.
6. **Sitemap** — add `accessibility.html`; `xhtml:link` hreflang alternates
   (`?lang=xx`, already supported by `i18n.js`) for every page.
7. **CSP hardening** — move privacy.html's 12 inline `style=""` attributes into
   `styles.css`, then drop `style-src 'unsafe-inline'` from `.htaccess` and the
   nginx example.
8. **Footer** — "Accessibility statement" + "Accessibility" links on all pages.

## Verification

- axe-core: 0 violations on every page × en/he/ar.
- Keyboard-only pass of toolbar, consent banner, language select.
- Mobile 390px: no horizontal scroll (RTL and LTR); 200% zoom.
- `curl` the served files: 404 status page, security.txt fields.

## Needs a human

- Accessibility statement: review by an accessibility professional before
  relying on it for IS 5568 / Equal Rights for Persons with Disabilities
  regulations (an accessibility coordinator may be required for a business).
- Enable GitHub Pages (Settings → Pages → Source: GitHub Actions).
