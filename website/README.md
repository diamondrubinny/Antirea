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
the `website/` folder.
