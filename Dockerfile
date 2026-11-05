# Build and run the Antirea collector (control panel + ingest API).
# Usage: docker compose up --build   (see docker-compose.yml)

FROM node:22-bookworm AS build
WORKDIR /app
COPY . .
# Full install (compiles better-sqlite3, prepares geoip-lite), then build the
# adaptive layer (collector depends on it) and the collector itself.
RUN npm install --no-audit --no-fund \
 && npm run build -w @antirea/adaptive \
 && npm run build -w @antirea/collector

FROM node:22-bookworm-slim
WORKDIR /app
ENV NODE_ENV=production
# Copy the built workspace, including the compiled native module and node_modules.
COPY --from=build /app /app
WORKDIR /app/packages/collector
EXPOSE 8080
# Env (IP_SALT, ADMIN_TOKEN, …) is provided at runtime — see docker-compose.yml.
CMD ["node", "dist/server.js"]
