# Access service (`@hardport/access`)

HTTP API for the Hard Port **platform**: content, entitlements, partners, keywords (API), staff/partner sessions, and public `pk` routes.

- **Default port:** 4001  
- **Database role:** `hp_access` on platform Postgres (not the website DB)  
- **Route catalogue:** [`docs/platform-routes.md`](../../docs/platform-routes.md)  
- **Architecture:** [`docs/hardport-architecture.md`](../../docs/hardport-architecture.md)

```bash
pnpm platform:migrate   # once, platform DB
pnpm --filter @hardport/access start
```

## UI vs API (do not confuse)

| Artifact | Location / npm | Role |
|----------|----------------|------|
| **Access service** | `services/access`, npm **`@hardport/access`** | Fastify API you deploy (e.g. `access.thehardport.com`) |
| **@psyferblock/access** (console) | `packages/access-ui` | Installable Next mount at **`/thp/*`** — router + BFF + widgets ([psyferblock.io](https://psyferblock.io)) |

Customer sites install the **`access`** package, set env keys, and render `<AccessApp basePath="/thp" />`. The console talks to **this service** over HTTP; it is not embedded inside the Fastify process.

Website **application review** (`/review`, `apps/api` intake) is **not** part of either package above.

v1 partner portal API: [`docs/access-service-v1.md`](../../docs/access-service-v1.md). Migrate with `pnpm platform:migrate` (includes `006_partner_portal.sql`).
