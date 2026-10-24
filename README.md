# SMB Access Service

Platform Access API — **`apps/api`** (`@hardport/access`, port 4001).

Read **`REPO-LAYOUT.md`** before adding files. Future web surfaces → **`apps/web`**.

```bash
pnpm install
cp apps/api/.env.example apps/api/.env   # fill secrets
pnpm --filter @hardport/access dev
```

Deploy: **`DEPLOY.md`**. Docker: **`Dockerfile`** at repo root.

Synced from Hard Port monorepo via `scripts/publish/sync-smb-access-service.sh` (updates `packages/core` + lockfile).
