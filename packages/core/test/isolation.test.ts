import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { Db, hashApiKey, generateApiKey, createPool, hashSessionToken, randomToken } from '../src/index.js';
import { createTestDb, seedMembership, seedTenant, seedUser, type TestDb } from '../../../test-support/db.js';

// These tests try to BREAK the tenant boundaries against a real Postgres, using the real
// runtime roles. If any of them fail, data could leak between customers.

let t: TestDb;
let access: Db;
let payments: Db;
let A: string;
let B: string;
let partnerA1: string;
let partnerA2: string;
let campA1: string;
let campA2: string;
let contentA: string;
let contentB: string;
let draftA: string;

const first = <T,>(rows: T[]): T => rows[0]!;

async function code(fn: () => Promise<unknown>): Promise<string | undefined> {
  try {
    await fn();
    return undefined;
  } catch (e) {
    return (e as { code?: string }).code;
  }
}

before(async () => {
  t = await createTestDb();
  access = new Db(createPool(t.url, 4), { testRole: 'hp_access' });
  payments = new Db(createPool(t.url, 4), { testRole: 'hp_payments' });
  A = await seedTenant(t.seed, 'alpha');
  B = await seedTenant(t.seed, 'bravo');

  const ins = async <R extends { id: string }>(sql: string, params: unknown[]) => first((await t.seed.query<R>(sql, params)).rows).id;
  partnerA1 = await ins('INSERT INTO access.partners (tenant_id, display_name, commission_pct) VALUES ($1, $2, 10) RETURNING id', [A, 'Sara']);
  partnerA2 = await ins('INSERT INTO access.partners (tenant_id, display_name, commission_pct) VALUES ($1, $2, 15) RETURNING id', [A, 'Omar']);
  campA1 = await ins('INSERT INTO access.campaigns (tenant_id, title, partner_id) VALUES ($1, $2, $3) RETURNING id', [A, 'Sara video', partnerA1]);
  campA2 = await ins('INSERT INTO access.campaigns (tenant_id, title, partner_id) VALUES ($1, $2, $3) RETURNING id', [A, 'Omar video', partnerA2]);
  contentA = await ins(`INSERT INTO access.content_items (tenant_id, slug, title, kind, status) VALUES ($1, 'guide-a', 'Guide A', 'guide', 'published') RETURNING id`, [A]);
  draftA = await ins(`INSERT INTO access.content_items (tenant_id, slug, title, kind, status) VALUES ($1, 'draft-a', 'Draft A', 'guide', 'draft') RETURNING id`, [A]);
  contentB = await ins(`INSERT INTO access.content_items (tenant_id, slug, title, kind, status) VALUES ($1, 'guide-b', 'Guide B', 'guide', 'published') RETURNING id`, [B]);
  await t.seed.query(`INSERT INTO access.keywords (tenant_id, word, content_id, campaign_id) VALUES ($1, 'motion', $2, $3)`, [A, contentA, campA1]);
  await t.seed.query(`INSERT INTO access.keywords (tenant_id, word, content_id) VALUES ($1, 'motion', $2)`, [B, contentB]); // same word, other tenant: allowed
  await t.seed.query(`INSERT INTO access.customers (tenant_id, email) VALUES ($1, 'buyer@a.test'), ($2, 'buyer@b.test')`, [A, B]);
  await t.seed.query(`INSERT INTO access.events (tenant_id, type, campaign_id, partner_id, matched) VALUES ($1, 'keyword_lookup', $2, $3, true), ($1, 'keyword_lookup', $4, $5, true)`, [A, campA1, partnerA1, campA2, partnerA2]);

  const order = async (tenant: string, ref: string, partner: string | null) =>
    ins(
      `INSERT INTO payments.orders (tenant_id, external_ref, customer_email, item_ref, item_title, list_price_minor, discount_minor, total_minor, currency, partner_id, commission_pct)
       VALUES ($1, $2, 'c@x.test', 'guide-a', 'Guide A', 1000, 0, 1000, 'USD', $3, 10) RETURNING id`,
      [tenant, ref, partner],
    );
  const o1 = await order(A, 'o1', partnerA1);
  const o2 = await order(A, 'o2', partnerA2);
  await order(B, 'o3', null);
  await t.seed.query(`INSERT INTO payments.commissions (tenant_id, partner_id, order_id, amount_minor, currency, payable_after) VALUES ($1, $2, $3, 100, 'USD', now()), ($1, $4, $5, 150, 'USD', now())`, [A, partnerA1, o1, partnerA2, o2]);
});

after(async () => {
  await access.close();
  await payments.close();
  await t.drop();
});

// =========================================================================================

describe('schema safety nets', () => {
  test('every table with a tenant_id has RLS and a restrictive tenant_guard policy', async () => {
    const tables = (
      await t.seed.query<{ s: string; n: string }>(
        `SELECT c.table_schema AS s, c.table_name AS n
         FROM information_schema.columns c
         JOIN information_schema.tables x ON x.table_schema = c.table_schema AND x.table_name = c.table_name AND x.table_type = 'BASE TABLE'
         WHERE c.column_name = 'tenant_id' AND c.table_schema IN ('platform', 'access', 'payments')`,
      )
    ).rows;
    assert.ok(tables.length >= 19, `expected at least 19 tenant tables, found ${tables.length}`);

    const preAuthOnly = new Set(['platform.sessions']); // no tenant RLS, but must be unreachable by runtime roles
    const problems: string[] = [];
    for (const { s, n } of tables) {
      const full = `${s}.${n}`;
      if (preAuthOnly.has(full)) continue;
      const rls = first((await t.seed.query<{ on: boolean }>('SELECT relrowsecurity AS on FROM pg_class WHERE oid = $1::regclass', [full])).rows).on;
      const guard = (
        await t.seed.query(`SELECT 1 FROM pg_policies WHERE schemaname = $1 AND tablename = $2 AND policyname = 'tenant_guard' AND permissive = 'RESTRICTIVE'`, [s, n])
      ).rowCount;
      if (!rls) problems.push(`${full}: RLS not enabled`);
      if (!guard) problems.push(`${full}: no restrictive tenant_guard policy`);
    }
    assert.deepEqual(problems, []);
  });

  test('runtime roles have no direct access to pre-auth tables', async () => {
    for (const role of ['hp_access', 'hp_payments']) {
      for (const table of ['platform.users', 'platform.sessions', 'platform.login_attempts', 'platform.licenses', 'platform.tenants']) {
        for (const priv of ['SELECT', 'INSERT', 'UPDATE', 'DELETE']) {
          const r = await t.seed.query<{ ok: boolean }>('SELECT has_table_privilege($1, $2, $3) AS ok', [role, table, priv]);
          assert.equal(first(r.rows).ok, false, `${role} must not have ${priv} on ${table}`);
        }
      }
    }
  });

  test('the two products cannot read each other\'s schema', async () => {
    assert.equal(await code(() => access.withTenant({ tenantId: A, role: 'owner' }, (q) => q.query('SELECT * FROM payments.orders'))), '42501');
    assert.equal(await code(() => payments.withTenant({ tenantId: A, role: 'owner' }, (q) => q.query('SELECT * FROM access.customers'))), '42501');
  });
});

describe('tenant isolation', () => {
  test('each tenant sees only its own rows', async () => {
    const a = await access.withTenant({ tenantId: A, role: 'owner' }, async (q) => (await q.query('SELECT slug FROM access.content_items ORDER BY slug')).rows);
    const b = await access.withTenant({ tenantId: B, role: 'owner' }, async (q) => (await q.query('SELECT slug FROM access.content_items ORDER BY slug')).rows);
    assert.deepEqual(a.map((r) => r.slug), ['draft-a', 'guide-a']);
    assert.deepEqual(b.map((r) => r.slug), ['guide-b']);
  });

  test('with no tenant set, every table returns nothing (fail closed)', async () => {
    const rows = await access.withoutTenant(async (q) => {
      const content = await q.query('SELECT * FROM access.content_items');
      const customers = await q.query('SELECT * FROM access.customers');
      const events = await q.query('SELECT * FROM access.events');
      return content.rowCount! + customers.rowCount! + events.rowCount!;
    });
    assert.equal(rows, 0);
  });

  test('a tenant cannot write rows that belong to another tenant', async () => {
    const err = await code(() =>
      access.withTenant({ tenantId: A, role: 'owner' }, (q) =>
        q.query(`INSERT INTO access.content_items (tenant_id, slug, title, kind) VALUES ($1, 'sneaky', 'x', 'guide')`, [B]),
      ),
    );
    assert.equal(err, '42501'); // new row violates row-level security policy
  });

  test('a tenant cannot update or delete another tenant\'s rows', async () => {
    const result = await access.withTenant({ tenantId: A, role: 'owner' }, async (q) => {
      const u = await q.query(`UPDATE access.content_items SET title = 'hacked' WHERE id = $1`, [contentB]);
      const d = await q.query(`DELETE FROM access.content_items WHERE id = $1`, [contentB]);
      return [u.rowCount, d.rowCount];
    });
    assert.deepEqual(result, [0, 0]);
    const still = first((await t.seed.query('SELECT title FROM access.content_items WHERE id = $1', [contentB])).rows) as { title: string };
    assert.equal(still.title, 'Guide B');
  });

  test('composite foreign keys make cross-tenant references impossible, even for the superuser', async () => {
    const err = await code(() => t.seed.query(`INSERT INTO access.keywords (tenant_id, word, content_id) VALUES ($1, 'crossref', $2)`, [A, contentB]));
    assert.equal(err, '23503');
  });

  test('keywords are unique per tenant, not globally', async () => {
    const dupe = await code(() => t.seed.query(`INSERT INTO access.keywords (tenant_id, word, content_id) VALUES ($1, 'motion', $2)`, [A, contentA]));
    assert.equal(dupe, '23505');
  });
});

describe('role scoping inside a tenant', () => {
  const partner1 = () => ({ tenantId: A, role: 'partner' as const, partnerId: partnerA1 });

  test('a partner sees only their own campaigns and events', async () => {
    const camps = await access.withTenant(partner1(), async (q) => (await q.query('SELECT title FROM access.campaigns')).rows);
    assert.deepEqual(camps, [{ title: 'Sara video' }]);
    const events = await access.withTenant(partner1(), async (q) => (await q.query('SELECT partner_id FROM access.events')).rows as { partner_id: string }[]);
    assert.equal(events.length, 1);
    assert.equal(first(events).partner_id, partnerA1);
  });

  test('a partner can never read customer emails, other partners, or orders', async () => {
    const customers = await access.withTenant(partner1(), async (q) => (await q.query('SELECT * FROM access.customers')).rowCount);
    assert.equal(customers, 0);
    const partners = await access.withTenant(partner1(), async (q) => (await q.query('SELECT display_name FROM access.partners')).rows);
    assert.deepEqual(partners, [{ display_name: 'Sara' }]);
    const orders = await payments.withTenant(partner1(), async (q) => (await q.query('SELECT * FROM payments.orders')).rowCount);
    assert.equal(orders, 0);
  });

  test('a partner sees only their own commissions; staff see all in the tenant', async () => {
    const mine = await payments.withTenant(partner1(), async (q) => (await q.query('SELECT amount_minor FROM payments.commissions')).rows);
    assert.deepEqual(mine, [{ amount_minor: 100 }]);
    const staff = await payments.withTenant({ tenantId: A, role: 'staff' }, async (q) => (await q.query('SELECT amount_minor FROM payments.commissions ORDER BY amount_minor')).rows);
    assert.deepEqual(staff, [{ amount_minor: 100 }, { amount_minor: 150 }]);
  });

  test('a partner cannot write content, keywords or events', async () => {
    assert.equal(
      await code(() => access.withTenant(partner1(), (q) => q.query(`INSERT INTO access.content_items (tenant_id, slug, title, kind) VALUES ($1, 'p', 'p', 'guide')`, [A]))),
      '42501',
    );
    assert.equal(
      await code(() => access.withTenant(partner1(), (q) => q.query(`INSERT INTO access.events (tenant_id, type) VALUES ($1, 'page_view')`, [A]))),
      '42501',
    );
  });

  test('only owner/admin can see API keys; staff cannot', async () => {
    const site = first((await t.seed.query<{ id: string }>(`INSERT INTO platform.sites (tenant_id, domain) VALUES ($1, 'a.example') RETURNING id`, [A])).rows).id;
    const k = generateApiKey('secret');
    await t.seed.query(`INSERT INTO platform.api_keys (tenant_id, site_id, kind, key_prefix, key_hash) VALUES ($1, $2, 'secret', $3, $4)`, [A, site, k.prefix, k.hash]);
    const asAdmin = await access.withTenant({ tenantId: A, role: 'admin' }, async (q) => (await q.query('SELECT key_prefix FROM platform.api_keys')).rowCount);
    const asStaff = await access.withTenant({ tenantId: A, role: 'staff' }, async (q) => (await q.query('SELECT key_prefix FROM platform.api_keys')).rowCount);
    assert.equal(asAdmin, 1);
    assert.equal(asStaff, 0);
  });
});

describe('public (website visitor) role', () => {
  const pub = (tenantId: string) => ({ tenantId, role: 'public' as const });

  test('can read published content but not drafts', async () => {
    const rows = await access.withTenant(pub(A), async (q) => (await q.query('SELECT slug FROM access.content_items')).rows);
    assert.deepEqual(rows, [{ slug: 'guide-a' }]);
  });

  test('cannot read the keywords table, but the lookup function works within its own tenant only', async () => {
    const direct = await access.withTenant(pub(A), async (q) => (await q.query('SELECT * FROM access.keywords')).rowCount);
    assert.equal(direct, 0);
    const hitA = await access.withTenant(pub(A), async (q) => (await q.query('SELECT content_slug FROM access.lookup_keyword($1)', ['motion'])).rows);
    assert.deepEqual(hitA, [{ content_slug: 'guide-a' }]);
    const hitB = await access.withTenant(pub(B), async (q) => (await q.query('SELECT content_slug FROM access.lookup_keyword($1)', ['motion'])).rows);
    assert.deepEqual(hitB, [{ content_slug: 'guide-b' }]);
    const none = await access.withoutTenant(async (q) => (await q.query('SELECT * FROM access.lookup_keyword($1)', ['motion'])).rowCount);
    assert.equal(none, 0);
  });

  test('can record events but cannot read them, customers or entitlements', async () => {
    await access.withTenant(pub(A), (q) => q.query(`INSERT INTO access.events (tenant_id, type, keyword_text, matched) VALUES ($1, 'keyword_lookup', 'oops', false)`, [A]));
    const reads = await access.withTenant(pub(A), async (q) => {
      const e = await q.query('SELECT * FROM access.events');
      const c = await q.query('SELECT * FROM access.customers');
      const n = await q.query('SELECT * FROM access.entitlements');
      return e.rowCount! + c.rowCount! + n.rowCount!;
    });
    assert.equal(reads, 0);
  });
});

describe('append-only tables', () => {
  test('events cannot be updated or deleted by the app role', async () => {
    assert.equal(await code(() => access.withTenant({ tenantId: A, role: 'owner' }, (q) => q.query(`UPDATE access.events SET matched = false`))), '42501');
    assert.equal(await code(() => access.withTenant({ tenantId: A, role: 'owner' }, (q) => q.query(`DELETE FROM access.events`))), '42501');
  });

  test('audit log: app role can insert, cannot change; even the superuser is stopped by trigger', async () => {
    await access.withTenant({ tenantId: A, role: 'owner' }, (q) => q.query(`INSERT INTO platform.audit_log (tenant_id, action) VALUES ($1, 'test.action')`, [A]));
    assert.equal(await code(() => access.withTenant({ tenantId: A, role: 'owner' }, (q) => q.query(`UPDATE platform.audit_log SET action = 'x'`))), '42501');
    assert.equal(await code(() => access.withTenant({ tenantId: A, role: 'owner' }, (q) => q.query(`DELETE FROM platform.audit_log`))), '42501');
    assert.equal(await code(() => t.seed.query(`UPDATE platform.audit_log SET action = 'x'`)), '42501');
    assert.equal(await code(() => t.seed.query(`TRUNCATE platform.audit_log`)), '42501');
  });

  test('payment events and orders keep history (no delete, events immutable)', async () => {
    assert.equal(await code(() => payments.withTenant({ tenantId: A, role: 'system' }, (q) => q.query(`DELETE FROM payments.orders`))), '42501');
    assert.equal(await code(() => payments.withTenant({ tenantId: A, role: 'system' }, (q) => q.query(`UPDATE payments.payment_events SET decision = 'x'`))), '42501');
  });
});

describe('login, sessions and API keys (pre-auth functions)', () => {
  test('runtime role cannot read users directly but can use the narrow login function', async () => {
    const uid = await seedUser(t.seed, 'owner@alpha.test', { passwordHash: 'x' });
    await seedMembership(t.seed, A, uid, 'owner');
    assert.equal(await code(() => access.withoutTenant((q) => q.query('SELECT * FROM platform.users'))), '42501');
    const row = await access.withoutTenant(async (q) => first((await q.query('SELECT id, status FROM platform.get_user_for_login($1)', [' Owner@Alpha.Test '])).rows) as { id: string; status: string });
    assert.equal(row.id, uid);
  });

  test('session lifecycle: create, resolve, revoke; cannot create a session for a tenant you are not in', async () => {
    const uid = await seedUser(t.seed, 'staff@alpha.test', { passwordHash: 'x' });
    await seedMembership(t.seed, A, uid, 'staff');
    const token = randomToken();
    const hash = hashSessionToken(token);

    const ok = await access.withoutTenant(async (q) => first((await q.query<{ ok: boolean }>(`SELECT platform.create_session($1, $2, $3, interval '1 hour', 'iphash', 'ua') AS ok`, [uid, A, hash])).rows).ok);
    assert.equal(ok, true);
    const wrongTenant = await access.withoutTenant(async (q) => first((await q.query<{ ok: boolean }>(`SELECT platform.create_session($1, $2, $3, interval '1 hour', 'iphash', 'ua') AS ok`, [uid, B, hashSessionToken(randomToken())])).rows).ok);
    assert.equal(wrongTenant, false, 'membership in A must not grant a session in B');

    const resolved = await access.withoutTenant(async (q) => first((await q.query('SELECT tenant_id, role FROM platform.resolve_session($1)', [hash])).rows) as { tenant_id: string; role: string });
    assert.deepEqual(resolved, { tenant_id: A, role: 'staff' });

    await access.withoutTenant((q) => q.query('SELECT platform.revoke_session($1)', [hash]));
    const after = await access.withoutTenant(async (q) => (await q.query('SELECT * FROM platform.resolve_session($1)', [hash])).rowCount);
    assert.equal(after, 0);

    // payments product can resolve sessions too (shared identity) but cannot create them
    assert.equal(await code(() => payments.withoutTenant((q) => q.query(`SELECT platform.create_session($1, $2, 'h', interval '1 hour', 'i', 'u')`, [uid, A]))), '42501');
  });

  test('expired and suspended-tenant sessions do not resolve', async () => {
    const uid = await seedUser(t.seed, 'susp@alpha.test', { passwordHash: 'x' });
    const C = await seedTenant(t.seed, 'charlie');
    await seedMembership(t.seed, C, uid, 'owner');
    const h1 = hashSessionToken(randomToken());
    const h2 = hashSessionToken(randomToken());
    await t.seed.query(`INSERT INTO platform.sessions (token_hash, user_id, tenant_id, expires_at) VALUES ($1, $2, $3, now() - interval '1 minute'), ($4, $2, $3, now() + interval '1 hour')`, [h1, uid, C, h2]);
    const resolve = (h: string) => access.withoutTenant(async (q) => (await q.query('SELECT * FROM platform.resolve_session($1)', [h])).rowCount);
    assert.equal(await resolve(h1), 0, 'expired');
    assert.equal(await resolve(h2), 1);
    await t.seed.query(`UPDATE platform.tenants SET status = 'suspended' WHERE id = $1`, [C]);
    assert.equal(await resolve(h2), 0, 'suspended tenant');
  });

  test('API keys resolve by hash; revoked keys and suspended tenants do not', async () => {
    const site = first((await t.seed.query<{ id: string }>(`INSERT INTO platform.sites (tenant_id, domain) VALUES ($1, 'b.example') RETURNING id`, [B])).rows).id;
    const k = generateApiKey('public');
    await t.seed.query(`INSERT INTO platform.api_keys (tenant_id, site_id, kind, key_prefix, key_hash, allowed_origins) VALUES ($1, $2, 'public', $3, $4, ARRAY['https://b.example'])`, [B, site, k.prefix, k.hash]);
    const resolve = () => access.withoutTenant(async (q) => (await q.query('SELECT tenant_id, kind, allowed_origins FROM platform.resolve_api_key($1)', [hashApiKey(k.key)])).rows);
    assert.deepEqual(await resolve(), [{ tenant_id: B, kind: 'public', allowed_origins: ['https://b.example'] }]);
    await t.seed.query(`UPDATE platform.api_keys SET revoked_at = now() WHERE key_hash = $1`, [k.hash]);
    assert.deepEqual(await resolve(), []);
  });

  test('login failure counters work and are keyed by hashes, not raw values', async () => {
    for (let i = 0; i < 3; i++) await access.withoutTenant((q) => q.query(`SELECT platform.record_login_attempt('emailhash', 'iphash', false)`));
    const f = await access.withoutTenant(async (q) => first((await q.query(`SELECT by_email, by_ip FROM platform.login_failures('emailhash', 'iphash', interval '15 minutes')`)).rows) as { by_email: number; by_ip: number });
    assert.deepEqual(f, { by_email: 3, by_ip: 3 });
  });
});

describe('Db helper hygiene', () => {
  test('tenant settings do not leak to the next transaction on a reused connection', async () => {
    const pool = createPool(t.url, 1); // single connection forces reuse
    const db = new Db(pool, { testRole: 'hp_access' });
    await db.withTenant({ tenantId: A, role: 'owner' }, (q) => q.query('SELECT 1'));
    const rows = await db.withoutTenant(async (q) => (await q.query('SELECT * FROM access.content_items')).rowCount);
    assert.equal(rows, 0);
    await db.close();
  });

  test('rejects malformed tenant ids and unknown roles before touching the database', () => {
    assert.throws(() => access.withTenant({ tenantId: "x'; drop table", role: 'owner' }, async () => 1));
    assert.throws(() => access.withTenant({ tenantId: A, role: 'superuser' as never }, async () => 1));
  });
});
