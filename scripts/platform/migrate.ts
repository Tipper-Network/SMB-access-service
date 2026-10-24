import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';

// Applies db/migrations/*.sql in order, once each, each inside a transaction.
// Run with the MIGRATION OWNER connection string (never a runtime role):
//   DATABASE_URL=postgres://owner:...@host/platform pnpm platform:migrate

const dir = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'db', 'migrations');

/**
 * Applies `db/migrations/*.sql` in filename order, once each, each inside its own transaction.
 * Connect as the migration owner. Runtime roles cannot run this.
 *
 * @param connectionString - Owner `DATABASE_URL` for the platform database
 * @param log - Receives `applied <file>` or `nothing to apply`
 * @returns Names of the files applied on this run
 */
export async function migrate(connectionString: string, log: (msg: string) => void = console.log): Promise<string[]> {
  const client = new pg.Client({ connectionString });
  await client.connect();
  const applied: string[] = [];
  try {
    await client.query(`CREATE TABLE IF NOT EXISTS public.schema_migrations (name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`);
    const done = new Set((await client.query<{ name: string }>('SELECT name FROM public.schema_migrations')).rows.map((r) => r.name));
    const files = (await readdir(dir)).filter((f) => f.endsWith('.sql')).sort();
    for (const file of files) {
      if (done.has(file)) continue;
      const sql = await readFile(path.join(dir, file), 'utf8');
      await client.query('BEGIN');
      try {
        await client.query(sql);
        await client.query('INSERT INTO public.schema_migrations (name) VALUES ($1)', [file]);
        await client.query('COMMIT');
        applied.push(file);
        log(`applied ${file}`);
      } catch (err) {
        await client.query('ROLLBACK');
        throw new Error(`migration ${file} failed: ${(err as Error).message}`);
      }
    }
    if (applied.length === 0) log('nothing to apply');
  } finally {
    await client.end();
  }
  return applied;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  const url = process.env.DATABASE_URL;
  if (!url) {
    console.error('DATABASE_URL is required (use the migration owner, not a runtime role)');
    process.exit(1);
  }
  migrate(url).catch((err) => {
    console.error(err.message);
    process.exit(1);
  });
}
