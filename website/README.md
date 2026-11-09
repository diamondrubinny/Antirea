# NoREA website (norea.rubinny.net)

Static marketing + docs landing page for Antirea / NoREA.

## Local preview

```bash
cd website
python3 -m http.server 8080
# open http://localhost:8080
```

## Deploy (GitHub Pages)

A workflow (`.github/workflows/pages.yml`) publishes this folder to GitHub Pages
on every push to `main` that touches `website/`.

One-time setup (repo owner):

1. **Settings → Pages → Build and deployment → Source: GitHub Actions.**
2. **Custom domain:** the `website/CNAME` file already sets `norea.rubinny.net`.
   In your DNS, add a `CNAME` record:
   `norea` → `diamondrubinny.github.io`.
   (Or an `ALIAS`/`ANAME` at the apex if you later use a root domain.)
3. Wait for DNS + the Pages "Enforce HTTPS" checkbox to become available, then
   enable it.

Any other static host (Netlify, Cloudflare Pages, S3) also works — just serve
the `website/` folder, including the hidden `.well-known/` directory
(`security.txt`), and configure `404.html` as the not-found page (GitHub Pages
does this automatically; `.htaccess` and `nginx-norea.conf.example` include it).

## Pages

| File | Purpose |
|---|---|
| `index.html` | Landing page |
| `privacy.html` | Privacy & cookie policy (lists every browser-storage key) |
| `accessibility.html` | Accessibility statement (WCAG 2.1 AA / IS 5568 target) |
| `404.html` | Localized not-found page (`noindex`) |
| `.well-known/security.txt` | RFC 9116 security contact — **renew `Expires` before 2027-11-08** |

## Scripts

All first-party, no third parties, CSP `script-src 'self'` / `style-src 'self'`.
Load order matters (all `defer`): page dictionary (`i18n-a11y.js`, statement
page only) → `a11y.js` (toolbar) → `i18n.js` → `consent.js`.

Accessibility check (axe-core, every page × en/he/ar) is described in
`docs/plans/website-compliance.md`.
