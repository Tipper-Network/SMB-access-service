# Deploy Access API (`SMB-access-service` / `@hardport/access`)

Deploy **only** the platform Access HTTP API (:4001). Console and catalog UI stay on `apps/web` (later: npm `@psyferblock/access`).

**GitHub:** [Tipper-Network/SMB-access-service](https://github.com/Tipper-Network/SMB-access-service) — must contain `Dockerfile`, `packages/core`, `services/access`, not README-only.

---

## 0. Sync code to the service repo (from monorepo)

Deploy git root: **`deploy/smb-access-service/`** → [Tipper-Network/SMB-access-service](https://github.com/Tipper-Network/SMB-access-service).  
Monorepo **`services/access/`** stays dev source; sync copies core + access into the deploy folder.

After changing Access or core:

```bash
chmod +x scripts/publish/sync-smb-access-service.sh
./scripts/publish/sync-smb-access-service.sh
cd deploy/smb-access-service
git add -A
git commit -m "sync access service for deploy"
git push origin main
```

---

## 1. Platform database (once)

Use **Neon** or Postgres on the VPS — not the website intake DB.

From your laptop (owner `DATABASE_URL`):

```bash
export DATABASE_URL='postgres://OWNER@HOST/hp_platform'
pnpm platform:migrate
# Create hp_access_login — scripts/local/ensure-access-login.sql (strong prod password)
```

Generate **production** secrets (do not reuse local `.env`):

```bash
pnpm platform:secrets:local
```

Bootstrap tenant (save pk/sk/password/TOTP once):

```bash
export FIELD_KEYS='…'
pnpm platform:bootstrap -- \
  --slug hardport \
  --name "The Hard Port" \
  --email YOUR_EMAIL \
  --domain thehardport.com \
  --origin https://thehardport.com
```

---

## 2. Dokploy / Docker on VPS

**Build context:** repo root (where `Dockerfile` lives).

**Dockerfile path:** `./Dockerfile` (copied by sync script).

**Internal port:** `4001`

**Health check:** `GET /healthz` → `{"ok":true}`

### Required environment variables

| Variable | Production |
|----------|------------|
| `DATABASE_URL` | Runtime role (`hp_access_login` → platform DB) |
| `HOST` | `0.0.0.0` |
| `PORT` | `4001` |
| `ADMIN_ORIGINS` | `https://thehardport.com` (comma-separate if multiple) |
| `COOKIE_SECURE` | `true` |
| `TRUST_PROXY` | `true` |
| `IP_PEPPER` | From secrets |
| `FIELD_KEYS` | From secrets (must match bootstrap) |
| `INTERNAL_SIGNING_KEYS` | From secrets |
| `KEYWORD_SESSION_KEYS` | From secrets |
| `ACCESS_TEST_OTP` | e.g. `123456` until Resend works — then remove |
| `HP_S3_BUCKET`, `AWS_*`, `HP_S3_PUBLIC_BASE_URL` | If staff uploads should work in prod |

Optional later: `RESEND_API_KEY`, `MAIL_FROM`.

### Reverse proxy

Point **`https://access.thehardport.com`** (or your chosen host) → container `:4001` with TLS.

```bash
curl -sS https://access.thehardport.com/healthz
```

---

## 3. Wire the website (separate deploy)

On `apps/web` host:

| Variable | Value |
|----------|--------|
| `HP_ACCESS_URL` | `https://access.thehardport.com` |
| `NEXT_PUBLIC_HP_PUBLIC_KEY` | Bootstrap `hp_pk_…` |
| `HP_SECRET_KEY` | Bootstrap `hp_sk_…` |
| `HP_TENANT_SLUG` | `hardport` |
| `NEXT_PUBLIC_SITE_URL` | `https://thehardport.com` |

Redeploy web. Smoke: `/admin/thp/connection` — health + catalog API OK.

---

## 4. Smoke test

1. `GET https://access.thehardport.com/healthz`
2. Staff login at `/admin/thp/login` (bootstrap creds + TOTP unless `ACCESS_SKIP_2FA` — **never in prod**)
3. Public catalog `/thp/catalog` shows published items
4. Partner OTP with `ACCESS_TEST_OTP` if email not wired

---

## Alternative: build from full monorepo on VPS

If you clone the whole Hard Port repo instead of `SMB-access-service`:

```bash
docker build -f services/access/Dockerfile -t hardport-access .
docker run --env-file access.prod.env -p 4001:4001 hardport-access
```

Same env table as above.
