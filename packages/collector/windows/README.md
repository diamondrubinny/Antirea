# Running the Antirea collector on Windows Server

The collector (telemetry ingest API + control panel) can run as a **Windows
Service** that starts on boot. This is the right way to run a server component
on Windows — not the Microsoft Store.

> **Why not the Microsoft Store?** Store (MSIX) apps are per-user, sandboxed
> desktop apps; they are not designed to run as an always-on system service,
> and Windows Server often has no Store. A background server belongs in a
> Windows Service (below), a Docker container (`docker-compose.yml` at the repo
> root), or behind IIS as a reverse proxy.
>
> The **protection** packages (`@antirea/honeypot`, `@antirea/secure-fn`) need
> no installer at all — they install with `npm install` into your Node app and
> run the same on Windows and Linux.

## Prerequisites

- Windows Server (or Windows 10/11) with **Node.js 22+** installed (Node 24 LTS recommended).
- A build toolchain for the native `better-sqlite3` module: install
  **"Desktop development with C++"** (Visual Studio Build Tools) and Python 3,
  or run `npm install --global windows-build-tools` (older setups).

## Install (PowerShell / CMD as Administrator)

```powershell
# from the repo root
npm install
npm run build -w @antirea/adaptive
npm run build -w @antirea/collector

cd packages\collector
copy .env.example .env
# edit .env and set IP_SALT and ADMIN_TOKEN (generate strong values):
#   node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"

npm install node-windows
node windows\install.mjs
```

The service **Antirea Collector** is now installed and running on
`http://localhost:8080/`. Open it and enter your `ADMIN_TOKEN`.

- Manage it in `services.msc`, or `sc start "Antirea Collector"` /
  `sc stop "Antirea Collector"`.
- Logs are written by node-windows under the service's `daemon` folder.

## Uninstall

```powershell
cd packages\collector
node windows\uninstall.mjs
```

## Exposing it securely

Put the collector behind a reverse proxy that terminates TLS and forwards to
`127.0.0.1:8080` (IIS with ARR, or nginx/Caddy for Windows). Set
`TRUST_PROXY=true` (one proxy) in `.env` so the real client IP is read from
`X-Forwarded-For` — use `2` if a CDN also sits in front. Only the entry that many
hops from the right is trusted, so clients cannot forge their IP. Also
restrict `ALLOWED_ORIGINS` to your real site origins.

## Building a signed installer (optional)

To ship a double-click installer to customers:

- **MSI** — package the built `packages/collector` folder plus a bundled Node
  runtime with **WiX Toolset** or **Advanced Installer**, and have the MSI run
  `node windows\install.mjs` as a custom action. Sign it with an EV/OV code-
  signing certificate.
- **Single .exe** — bundle with Node **SEA** (Single Executable Applications)
  or `pkg`. Note: `better-sqlite3` is native, so ship its `.node` binary beside
  the exe (or switch the collector's storage to a pure-JS store for a clean
  single-file build).
- **nssm** — alternatively, [nssm](https://nssm.cc) can register
  `node dist\server.js` as a service without node-windows.

These packaging steps run on a Windows machine; the scripts in this folder are
the service definition they wrap.
