# syntax=docker/dockerfile:1

FROM node:22-alpine AS build

RUN corepack enable

WORKDIR /app

COPY package.json pnpm-workspace.yaml pnpm-lock.yaml ./
COPY packages/core/package.json packages/core/
COPY apps/api/package.json apps/api/

RUN pnpm install --frozen-lockfile

COPY packages/core packages/core
COPY apps/api apps/api

FROM node:22-alpine AS runner

RUN corepack enable

WORKDIR /app

ENV NODE_ENV=production
ENV HOST=0.0.0.0
ENV PORT=4001

RUN addgroup --system --gid 1001 nodejs && adduser --system --uid 1001 access

COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/package.json ./package.json
COPY --from=build /app/pnpm-workspace.yaml ./pnpm-workspace.yaml
COPY --from=build /app/packages/core ./packages/core
COPY --from=build /app/apps/api ./apps/api

USER access

EXPOSE 4001

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD wget -qO- http://127.0.0.1:4001/healthz || exit 1

CMD ["pnpm", "--filter", "@hardport/access", "start"]
