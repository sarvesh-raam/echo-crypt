# syntax=docker/dockerfile:1

# ---- build: compile the crypto package, the server and the client ----
FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json tsconfig.base.json ./
COPY packages/crypto/package.json packages/crypto/
COPY server/package.json server/
COPY client/package.json client/
RUN npm ci
COPY packages/crypto packages/crypto
COPY server server
COPY client client
RUN npm run build

# ---- runtime: server production deps + built files only ----
FROM node:22-alpine
ENV NODE_ENV=production
WORKDIR /app
COPY package.json package-lock.json ./
COPY packages/crypto/package.json packages/crypto/
COPY server/package.json server/
COPY client/package.json client/
RUN npm ci --omit=dev -w server && npm cache clean --force
COPY --from=build /app/packages/crypto/dist packages/crypto/dist
COPY --from=build /app/server/dist server/dist
COPY --from=build /app/client/dist public
ENV STATIC_DIR=/app/public PORT=4000
USER node
EXPOSE 4000
HEALTHCHECK --interval=15s --timeout=3s --start-period=20s CMD wget -qO- "http://127.0.0.1:${PORT}/health" >/dev/null || exit 1
CMD ["node", "server/dist/index.js"]
