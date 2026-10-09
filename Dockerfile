FROM node:24-alpine@sha256:ebfe2f90462722a7a4de65e91990e97fe0d401c70e0e762c5b53302f905ec1c1 AS build
WORKDIR /app
RUN npm install --global pnpm@11.23.0
# Keep dependency inputs separate so source-only edits reuse the installed tree.
# Workspace manifests and pnpm patches are required by the frozen install.
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY patches ./patches
COPY apps/web/package.json ./apps/web/package.json
COPY packages/backend/package.json ./packages/backend/package.json
COPY packages/domain/package.json ./packages/domain/package.json
COPY packages/engine/package.json ./packages/engine/package.json
COPY packages/graph/package.json ./packages/graph/package.json
RUN pnpm install --frozen-lockfile
COPY . .
RUN pnpm build

FROM build AS production
RUN CI=true pnpm prune --prod \
    && node scripts/prepare-runtime.mjs \
    && rm -f /app/scripts/prepare-runtime.mjs \
    && rm -f /app/pnpm-lock.yaml /app/pnpm-workspace.yaml

FROM gcr.io/distroless/nodejs24-debian13:nonroot@sha256:4ac45c93b6c4b2304876569196e5962e55e8ba4ba095e7dde7bf6d7e00efc3b8 AS runtime
WORKDIR /app
ENV NODE_ENV=production
COPY --from=production --chown=65532:65532 /app /app
COPY --from=production --chown=65532:65532 /app/apps/web/.next/standalone /app/standalone
COPY --from=production --chown=65532:65532 /app/apps/web/.next/static /app/standalone/apps/web/.next/static
USER 65532:65532
EXPOSE 3200
ENTRYPOINT ["/nodejs/bin/node"]
CMD ["standalone/apps/web/server.js"]
