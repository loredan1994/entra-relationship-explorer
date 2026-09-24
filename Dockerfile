FROM node:25-alpine@sha256:bdf2cca6fe3dabd014ea60163eca3f0f7015fbd5c7ee1b0e9ccb4ced6eb02ef4 AS build
WORKDIR /app
RUN npm install --global pnpm@11.23.0
COPY . .
RUN pnpm install --frozen-lockfile
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
