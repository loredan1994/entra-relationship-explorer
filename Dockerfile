FROM node:26-alpine@sha256:aadf416b2cdce311a8811ba3f0608a61b77dbf997500e2eafe781b51f6a0b019 AS build
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

FROM gcr.io/distroless/nodejs24-debian13:nonroot@sha256:ffab599740d4aaa66029d02b9e6d3de4f622fefb7410081c5ef69c86430f364d AS runtime
WORKDIR /app
ENV NODE_ENV=production
COPY --from=production --chown=65532:65532 /app /app
COPY --from=production --chown=65532:65532 /app/apps/web/.next/standalone /app/standalone
COPY --from=production --chown=65532:65532 /app/apps/web/.next/static /app/standalone/apps/web/.next/static
USER 65532:65532
EXPOSE 3200
ENTRYPOINT ["/nodejs/bin/node"]
CMD ["standalone/apps/web/server.js"]
