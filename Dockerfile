# Build and run the Antirea collector (control panel + ingest API).
# Usage: docker compose up --build   (see docker-compose.yml)

FROM node:24-bookworm AS build
WORKDIR /app
COPY . .
# Full install (compiles better-sqlite3, prepares geoip-lite), then build the
# workspace packages the collector imports (adaptive, watermark) and the
# collector itself. Keep this list in sync with packages/collector/package.json.
RUN npm install --no-audit --no-fund \
 && npm run build -w @antirea/adaptive -w @antirea/watermark \
 && npm run build -w @antirea/collector \
 && npm prune --omit=dev --no-audit --no-fund

FROM node:24-bookworm-slim
WORKDIR /app
ENV NODE_ENV=production \
    DB_FILE=/data/antirea.db
# Copy the built workspace (production deps only, incl. the compiled native module).
COPY --from=build --chown=root:root /app /app
# Least privilege: run as the image's unprivileged "node" user. Only the data
# directory is writable by it; the application code stays root-owned/read-only.
RUN mkdir -p /data && chown node:node /data
USER node
VOLUME ["/data"]
WORKDIR /app/packages/collector
EXPOSE 8080
# Env (IP_SALT, ADMIN_TOKEN, …) is provided at runtime — see docker-compose.yml.
CMD ["node", "dist/server.js"]
