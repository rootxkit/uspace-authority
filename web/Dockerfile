# The authority's console image (WP-21; docs/PLAN.md §10): Next.js
# standalone output, built in CI and pulled by tag. The server never runs
# `next build`.
#
#   docker build -t uspace-authority-web web     (or: make web-image)
#
# The context is web/. The generated API and frame types are committed,
# so the build needs nothing outside it. pnpm is the version package.json
# pins (packageManager), through corepack; the lockfile is frozen, so the
# uspace-ui tarball installed is the one whose integrity the lockfile
# records. The base image is pinned by digest (node 22, alpine); a
# dependabot docker update moves it.
FROM node:26-alpine@sha256:0b36e8c136b94cd4fcf02188228e76c31ad5872eef3fec8cbd2eee500cfd9e80 AS builder
WORKDIR /app
ENV NEXT_TELEMETRY_DISABLED=1 \
    COREPACK_ENABLE_DOWNLOAD_PROMPT=0
RUN corepack enable
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile
COPY . .
RUN pnpm build

FROM node:26-alpine@sha256:0b36e8c136b94cd4fcf02188228e76c31ad5872eef3fec8cbd2eee500cfd9e80 AS runner
WORKDIR /app
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=3000 \
    HOSTNAME=0.0.0.0
COPY --from=builder --chown=node:node /app/.next/standalone ./
COPY --from=builder --chown=node:node /app/.next/static ./.next/static
COPY --from=builder --chown=node:node /app/public ./public
USER node
EXPOSE 3000
CMD ["node", "server.js"]
