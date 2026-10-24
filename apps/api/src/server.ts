import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createPool, Db } from '@hardport/core';
import { buildApp } from './app.js';
import { loadConfig } from './config.js';

const accessEnv = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '.env');
try {
  process.loadEnvFile(accessEnv);
} catch {
  // Production: inject env via host. Local: copy apps/api/.env.example and run pnpm platform:secrets:local
}

// Connect as the restricted runtime role (hp_access), never as the migration owner:
//   DATABASE_URL=postgres://hp_access_login:...@host/db
const config = loadConfig();
const db = new Db(createPool(process.env.DATABASE_URL!, 10));
const app = await buildApp({ db, config });
await app.listen({ host: config.host, port: config.port });
console.log(`[access] listening on ${config.host}:${config.port}`);

for (const sig of ['SIGINT', 'SIGTERM'] as const) {
  process.on(sig, async () => {
    await app.close();
    await db.close();
    process.exit(0);
  });
}
