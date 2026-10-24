import pg from 'pg';

// ---------------------------------------------------------------------------
// The ONLY way services touch tenant data.
//
// Every call opens a transaction and sets four values that the Postgres
// row-level-security policies read: app.tenant_id, app.role, app.partner_id,
// app.business_id. The settings are transaction-local, so they cannot leak to
// the next request that reuses the pooled connection. If nothing is set, every
// policy evaluates to "no rows" (fail closed).
// ---------------------------------------------------------------------------

export enum ACTOR_ROLES__Enum {
  OWNER = 'OWNER',
  ADMIN = 'ADMIN',
  STAFF = 'STAFF',
  PARTNER = 'PARTNER',
  BUSINESS = 'BUSINESS',
  PUBLIC = 'PUBLIC',
  SYSTEM = 'SYSTEM',
}
export type ActorRole = keyof typeof ACTOR_ROLES__Enum;

export interface Actor {
  tenantId: string;
  role: ActorRole;
  userId?: string | null;
  partnerId?: string | null;
  businessId?: string | null;
}

export type Queryable = Pick<pg.PoolClient, 'query'>;

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const IDENT_RE = /^[a-z_][a-z0-9_]*$/;

export class Db {
  /**
   * @param opts.testRole  TEST ONLY. When the pool connects as a superuser (as in
   *   the test suite), switch to the real runtime role inside each transaction so
   *   row-level security applies. In production the pool connects directly as
   *   hp_access / hp_payments and this stays undefined.
   */
  constructor(
    readonly pool: pg.Pool,
    private readonly opts: { testRole?: string } = {},
  ) {
    if (opts.testRole && !IDENT_RE.test(opts.testRole)) throw new Error('invalid test role');
  }

  /**
   * Opens one transaction, applies `settings` with `set_config(..., true)`, then commits.
   * A thrown error rolls the transaction back before the client returns to the pool.
   * @param settings - `app.*` values. An empty object leaves every policy closed.
   * @param fn - Queries to run on this client
   */
  private async run<T>(settings: Record<string, string>, fn: (q: Queryable) => Promise<T>): Promise<T> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      if (this.opts.testRole) await client.query(`SET LOCAL ROLE ${this.opts.testRole}`);
      const keys = Object.keys(settings);
      if (keys.length > 0) {
        await client.query('SELECT set_config(k, v, true) FROM unnest($1::text[], $2::text[]) AS t(k, v)', [
          keys,
          keys.map((k) => settings[k] as string),
        ]);
      }
      const result = await fn(client);
      await client.query('COMMIT');
      return result;
    } catch (err) {
      await client.query('ROLLBACK').catch(() => undefined);
      throw err;
    } finally {
      client.release();
    }
  }

  /**
   * Runs `fn` as one actor inside one tenant. Sets the transaction-local settings that row-level security reads.
   * @param actor - Tenant, role, and optional user, partner, or business id
   * @param fn - Queries to run before commit
   */
  withTenant<T>(actor: Actor, fn: (q: Queryable) => Promise<T>): Promise<T> {
    if (!UUID_RE.test(actor.tenantId)) throw new Error('withTenant: invalid tenant id');
    if (!Object.values(ACTOR_ROLES__Enum).includes(actor.role as ACTOR_ROLES__Enum)) throw new Error('withTenant: invalid role');
    for (const id of [actor.userId, actor.partnerId, actor.businessId]) {
      if (id && !UUID_RE.test(id)) throw new Error('withTenant: invalid actor id');
    }
    return this.run(
      {
        'app.tenant_id': actor.tenantId,
        'app.role': actor.role,
        'app.user_id': actor.userId ?? '',
        'app.partner_id': actor.partnerId ?? '',
        'app.business_id': actor.businessId ?? '',
      },
      fn,
    );
  }

  /**
   * Pre-authentication work (login, session and API-key lookup). No tenant is set,
   * so tenant tables return nothing; only the SECURITY DEFINER functions in the
   * platform schema can see across tenants, and only for narrow, audited purposes.
   */
  withoutTenant<T>(fn: (q: Queryable) => Promise<T>): Promise<T> {
    return this.run({}, fn);
  }

  /** Closes the pool. Call this on process shutdown. */
  async close(): Promise<void> {
    await this.pool.end();
  }
}

/**
 * Opens a Postgres pool. In production the connection string is the runtime role (`hp_access` or `hp_payments`), not the migration owner.
 * @param connectionString - `DATABASE_URL`
 * @param max - Pool size
 */
export function createPool(connectionString: string, max = 10): pg.Pool {
  return new pg.Pool({ connectionString, max, idleTimeoutMillis: 30_000 });
}
