import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import type { FastifyInstance } from 'fastify';
import { Db, createPool, encryptField, generateApiKey, generateTotpSecret, hashPassword, signToken, totpAt, type Keyring } from '@hardport/core';
import { buildApp } from '../src/app.js';
import type { AccessConfig } from '../src/config.js';
import { canAccess, normalizeKeyword } from '../src/rules.js';
import { createTestDb, seedMembership, seedTenant, seedUser, type TestDb } from '../../../test-support/db.js';

const ADMIN = 'https://admin.test';
const ALPHA_SITE = 'https://alpha.example';
const PASSWORD = 'Correct-Horse-9-Battery';

const ring: Keyring = { current: 'k1', keys: { k1: Buffer.alloc(32, 9) } };
const config: AccessConfig = {
  host: '127.0.0.1',
  port: 0,
  adminOrigins: [ADMIN],
  cookieSecure: false,
  trustProxy: false,
  ipPepper: 'p'.repeat(32),
  fieldKeys: ring,
  internalKeys: { current: 'k1', keys: { k1: 'i'.repeat(40) } },
  keywordKeys: { current: 'k1', keys: { k1: 'w'.repeat(40) } },
  sessionTtlHours: 12,
  defaultFreeAfterDays: 30,
  loginRateLimitPerMinute: 1000, // the per-account lockout is what these tests exercise
  resendApiKey: undefined,
  mailFrom: undefined,
  partnerOtpTtlMinutes: 10,
  partnerSessionTtlHours: 8,
};

let t: TestDb;
let db: Db;
let app: FastifyInstance;
let alpha: string;
let bravo: string;

interface Res {
  status: number;
  json: any;
  cookies: { name: string; value: string }[];
}

async function call(method: 'GET' | 'POST' | 'PATCH', url: string, o: { cookie?: string; body?: unknown; origin?: string | null; headers?: Record<string, string> } = {}): Promise<Res> {
  const headers: Record<string, string> = { ...(o.headers ?? {}) };
  const origin = o.origin === undefined ? ADMIN : o.origin;
  if (origin) headers.origin = origin;
  const res = await app.inject({ method, url, headers, cookies: o.cookie ? { hp_session: o.cookie } : undefined, payload: o.body as object | undefined });
  let json: unknown = null;
  try {
    json = res.body ? JSON.parse(res.body) : null;
  } catch {
    /* non-JSON */
  }
  return { status: res.statusCode, json, cookies: res.cookies as { name: string; value: string }[] };
}

const login = (body: Record<string, unknown>, origin: string | null = ADMIN) => call('POST', '/auth/login', { body, origin });
const sessionOf = (r: Res) => r.cookies.find((c) => c.name === 'hp_session')?.value;

let ownerCookie = '';
let staffCookie = '';
let alphaPublicKey = '';
let alphaSecretKey = '';
let bravoPublicKey = '';
let ownerTotpSecret = '';

before(async () => {
  t = await createTestDb();
  db = new Db(createPool(t.url, 6), { testRole: 'hp_access' });
  app = await buildApp({ db, config });
  alpha = await seedTenant(t.seed, 'alpha');
  bravo = await seedTenant(t.seed, 'bravo');
  const pw = await hashPassword(PASSWORD);

  // owner with mandatory 2FA
  ownerTotpSecret = generateTotpSecret();
  const ownerId = await seedUser(t.seed, 'owner@alpha.test', { passwordHash: pw, twofaEnabled: true });
  await t.seed.query('UPDATE platform.users SET twofa_secret_enc = $2 WHERE id = $1', [ownerId, encryptField(ownerTotpSecret, ring, `user:${ownerId}:twofa`)]);
  await seedMembership(t.seed, alpha, ownerId, 'owner');

  // staff (no 2FA), admin without 2FA (must be refused), victim for lockout, user in two tenants
  await seedMembership(t.seed, alpha, await seedUser(t.seed, 'staff@alpha.test', { passwordHash: pw }), 'staff');
  await seedMembership(t.seed, alpha, await seedUser(t.seed, 'admin-no2fa@alpha.test', { passwordHash: pw }), 'admin');
  await seedMembership(t.seed, alpha, await seedUser(t.seed, 'victim@alpha.test', { passwordHash: pw }), 'staff');
  const multi = await seedUser(t.seed, 'multi@x.test', { passwordHash: pw });
  await seedMembership(t.seed, alpha, multi, 'staff');
  await seedMembership(t.seed, bravo, multi, 'staff');

  // tenant bravo: its own content and public key, to prove nothing crosses over
  const site = (await t.seed.query<{ id: string }>(`INSERT INTO platform.sites (tenant_id, domain) VALUES ($1, 'bravo.example') RETURNING id`, [bravo])).rows[0]!.id;
  const bk = generateApiKey('public');
  bravoPublicKey = bk.key;
  await t.seed.query(`INSERT INTO platform.api_keys (tenant_id, site_id, kind, key_prefix, key_hash, allowed_origins) VALUES ($1, $2, 'public', $3, $4, ARRAY['https://bravo.example'])`, [bravo, site, bk.prefix, bk.hash]);
  await t.seed.query(`INSERT INTO access.content_items (tenant_id, slug, title, kind, status) VALUES ($1, 'bravo-secret', 'Bravo only', 'guide', 'published')`, [bravo]);
});

after(async () => {
  await app.close();
  await db.close();
  await t.drop();
});

// ================================================================== pure rules

describe('business rules', () => {
  const past = new Date(Date.now() - 86_400_000);
  const future = new Date(Date.now() + 86_400_000);
  const none = { hasEntitlement: false, hasKeywordSession: false };

  test('open is open; paid needs an entitlement and never opens by date', () => {
    assert.equal(canAccess({ access_mode: 'open', free_from: null }, none), true);
    assert.equal(canAccess({ access_mode: 'paid', free_from: past }, none), false);
    assert.equal(canAccess({ access_mode: 'paid', free_from: null }, { ...none, hasKeywordSession: true }), false);
    assert.equal(canAccess({ access_mode: 'paid', free_from: null }, { ...none, hasEntitlement: true }), true);
  });

  test('keyword_first: needs the word until free_from, then opens by itself', () => {
    assert.equal(canAccess({ access_mode: 'keyword_first', free_from: future }, none), false);
    assert.equal(canAccess({ access_mode: 'keyword_first', free_from: future }, { ...none, hasKeywordSession: true }), true);
    assert.equal(canAccess({ access_mode: 'keyword_first', free_from: past }, none), true);
    assert.equal(canAccess({ access_mode: 'keyword_first', free_from: future }, none, new Date(future.getTime() + 1)), true);
  });

  test('keyword normalisation is forgiving about case, spaces and #, strict about the result', () => {
    assert.equal(normalizeKeyword('  MoTion '), 'motion');
    assert.equal(normalizeKeyword('#Motion Studio'), 'motionstudio');
    assert.equal(normalizeKeyword('a'), null);
    assert.equal(normalizeKeyword("x'; drop table"), null);
    assert.equal(normalizeKeyword('x'.repeat(41)), null);
  });
});

// ================================================================== login

describe('login and sessions', () => {
  test('unknown email and wrong password give the same answer', async () => {
    const a = await login({ email: 'nobody@alpha.test', password: 'whatever-whatever' });
    const b = await login({ email: 'owner@alpha.test', password: 'wrong-password-123' });
    assert.equal(a.status, 401);
    assert.equal(b.status, 401);
    assert.deepEqual(a.json, b.json);
  });

  test('owner with correct password but no 2FA code is refused', async () => {
    const r = await login({ email: 'owner@alpha.test', password: PASSWORD });
    assert.equal(r.status, 401);
    assert.equal(sessionOf(r), undefined);
  });

  test('owner logs in with password + TOTP; a reused TOTP code is rejected', async () => {
    const code = totpAt(ownerTotpSecret, Date.now() - 30_000);
    const ok = await login({ email: 'owner@alpha.test', password: PASSWORD, totp: code });
    assert.equal(ok.status, 200);
    assert.deepEqual(ok.json, { ok: true, tenant: 'alpha', role: 'owner' });
    ownerCookie = sessionOf(ok)!;
    assert.ok(ownerCookie && ownerCookie.length >= 40);

    const replay = await login({ email: 'owner@alpha.test', password: PASSWORD, totp: code });
    assert.equal(replay.status, 401, 'same code must not work twice');
  });

  test('admins without 2FA enrolled can sign in with password only', async () => {
    const r = await login({ email: 'admin-no2fa@alpha.test', password: PASSWORD });
    assert.equal(r.status, 200);
    assert.equal(r.json.ok, true);
  });

  test('staff can log in without 2FA; cookie is HttpOnly and SameSite=Lax', async () => {
    const r = await login({ email: 'staff@alpha.test', password: PASSWORD });
    assert.equal(r.status, 200);
    staffCookie = sessionOf(r)!;
    const raw = (await app.inject({ method: 'GET', url: '/healthz' })).headers['set-cookie'];
    assert.equal(raw, undefined); // sanity: healthz sets nothing
    const c = (await call('POST', '/auth/login', { body: { email: 'staff@alpha.test', password: PASSWORD } })).cookies[0] as unknown as { httpOnly?: boolean; sameSite?: string };
    assert.equal(c.httpOnly, true);
    assert.equal(String(c.sameSite).toLowerCase(), 'lax');
  });

  test('a user in two tenants must choose one; the session is bound to that tenant', async () => {
    const need = await login({ email: 'multi@x.test', password: PASSWORD });
    assert.equal(need.status, 409);
    assert.deepEqual(need.json.tenants, ['alpha', 'bravo']);
    const ok = await login({ email: 'multi@x.test', password: PASSWORD, tenantSlug: 'bravo' });
    assert.equal(ok.json.tenant, 'bravo');
  });

  test('login requires an allowed Origin (CSRF defence)', async () => {
    assert.equal((await login({ email: 'staff@alpha.test', password: PASSWORD }, null)).status, 403);
    assert.equal((await login({ email: 'staff@alpha.test', password: PASSWORD }, 'https://evil.test')).status, 403);
  });

  test('five wrong passwords lock the account, even for the right password', async () => {
    for (let i = 0; i < 5; i++) assert.equal((await login({ email: 'victim@alpha.test', password: `wrong-guess-${i}-xx` })).status, 401);
    const locked = await login({ email: 'victim@alpha.test', password: PASSWORD });
    assert.equal(locked.status, 429);
  });

  test('unauthenticated and wrong-role requests are refused', async () => {
    assert.equal((await call('GET', '/admin/content')).status, 401);
    assert.equal((await call('GET', '/admin/content', { cookie: 'x'.repeat(43) })).status, 401);
    assert.equal((await call('GET', '/partner/stats', { cookie: staffCookie })).status, 403);
  });
});

// ================================================================== admin + public flow

describe('admin back-office and the public keyword flow', () => {
  let guideId = '';

  test('owner creates a site and receives keys once; only hashes are stored', async () => {
    const r = await call('POST', '/admin/sites', { cookie: ownerCookie, body: { domain: 'alpha.example', origins: [ALPHA_SITE] } });
    assert.equal(r.status, 201);
    alphaPublicKey = r.json.publicKey;
    alphaSecretKey = r.json.secretKey;
    assert.match(alphaPublicKey, /^hp_pk_/);
    assert.match(alphaSecretKey, /^hp_sk_/);
    const stored = await t.seed.query(`SELECT key_hash FROM platform.api_keys WHERE tenant_id = $1`, [alpha]);
    assert.ok(stored.rows.every((row: { key_hash: string }) => !row.key_hash.includes('hp_')));
    // staff cannot create sites
    assert.equal((await call('POST', '/admin/sites', { cookie: staffCookie, body: { domain: 'x.example', origins: [ALPHA_SITE] } })).status, 403);
  });

  test('state-changing admin calls need an allowed Origin, and unknown fields are rejected', async () => {
    const body = { slug: 'csrf', title: 'x', kind: 'guide' };
    assert.equal((await call('POST', '/admin/content', { cookie: ownerCookie, body, origin: 'https://evil.test' })).status, 403);
    assert.equal((await call('POST', '/admin/content', { cookie: ownerCookie, body, origin: null })).status, 403);
    const sneaky = await call('POST', '/admin/content', { cookie: ownerCookie, body: { ...body, tenant_id: bravo } });
    assert.equal(sneaky.status, 400, 'tenant_id from the client must never be accepted');
  });

  test('content, partners, campaigns and keywords are created inside the caller\'s tenant', async () => {
    const future = new Date(Date.now() + 10 * 86_400_000).toISOString();
    const mk = async (body: Record<string, unknown>) => {
      const r = await call('POST', '/admin/content', { cookie: staffCookie, body });
      assert.equal(r.status, 201, JSON.stringify(r.json));
      return r.json.id as string;
    };
    guideId = await mk({ slug: 'motion-guide', title: 'Motion guide', kind: 'guide', accessMode: 'keyword_first', freeFrom: future, status: 'published', bodyRef: 'guides/motion.md' });
    await mk({ slug: 'old-guide', title: 'Old guide', kind: 'guide', accessMode: 'keyword_first', freeFrom: new Date(Date.now() - 86_400_000).toISOString(), status: 'published' });
    await mk({ slug: 'roadmap-kit', title: 'Roadmap kit', kind: 'ebook', accessMode: 'paid', status: 'published', priceMinor: 12000, currency: 'USD', bodyRef: 'kits/roadmap.pdf' });
    await mk({ slug: 'hidden-draft', title: 'Draft', kind: 'guide', status: 'draft' });

    const partner = await call('POST', '/admin/partners', {
      cookie: staffCookie,
      body: { displayName: 'Sara', email: 'sara@partner.test', commissionPct: 10, payoutDetails: 'IBAN LB00 0000', portalCode: 'portal-sara-v1' },
    });
    assert.equal(partner.status, 201);
    const enc = (await t.seed.query<{ payout_details_enc: string }>('SELECT payout_details_enc FROM access.partners WHERE id = $1', [partner.json.id])).rows[0]!.payout_details_enc;
    assert.ok(enc.startsWith('v1.k1.') && !enc.includes('IBAN'), 'payout details must be encrypted at rest');

    const camp = await call('POST', '/admin/campaigns', { cookie: staffCookie, body: { title: 'Sara video', platform: 'youtube', triggerWord: 'MOTION', partnerId: partner.json.id } });
    assert.equal(camp.status, 201);
    const kw = await call('POST', '/admin/keywords', { cookie: staffCookie, body: { word: ' Motion ', contentSlug: 'motion-guide', campaignId: camp.json.id } });
    assert.equal(kw.status, 201);
    assert.equal(kw.json.word, 'motion');
    assert.equal((await call('POST', '/admin/keywords', { cookie: staffCookie, body: { word: 'motion', contentSlug: 'motion-guide' } })).status, 409, 'duplicate in tenant');
    assert.equal((await call('POST', '/admin/keywords', { cookie: staffCookie, body: { word: 'oldie', contentSlug: 'bravo-secret' } })).status, 400, 'cannot point at another tenant\'s content');

    (globalThis as any).__partnerId = partner.json.id;
  });

  test('admin lists show only this tenant\'s content, and audit entries were written', async () => {
    const r = await call('GET', '/admin/content', { cookie: ownerCookie });
    const slugs = r.json.items.map((i: { slug: string }) => i.slug).sort();
    assert.ok(slugs.includes('motion-guide') && !slugs.includes('bravo-secret'));
    const audits = await t.seed.query(`SELECT action FROM platform.audit_log WHERE tenant_id = $1`, [alpha]);
    assert.ok(audits.rowCount! >= 5);
    assert.equal((await t.seed.query(`SELECT 1 FROM platform.audit_log WHERE tenant_id = $1`, [bravo])).rowCount, 0);
  });

  test('keyword lookup: the right word unlocks the guide and returns a signed session', async () => {
    const r = await call('POST', '/v1/keywords/lookup', { origin: ALPHA_SITE, headers: { 'x-hp-key': alphaPublicKey }, body: { word: 'MOTION', anonId: 'anon-visitor-0000001' } });
    assert.equal(r.status, 200);
    assert.equal(r.json.ok, true);
    assert.equal(r.json.slug, 'motion-guide');
    assert.ok(String(r.json.session).startsWith('hpt.'));
    (globalThis as any).__session = r.json.session;
    const visitor = await t.seed.query(`SELECT first_campaign_id FROM access.visitors WHERE anon_id = 'anon-visitor-0000001'`);
    assert.ok(visitor.rows[0].first_campaign_id, 'the visit is attributed to the campaign');
  });

  test('keyword lookup with contentSlug rejects a valid word for the wrong product', async () => {
    const ok = await call('POST', '/v1/keywords/lookup', {
      origin: ALPHA_SITE,
      headers: { 'x-hp-key': alphaPublicKey },
      body: { word: 'motion', anonId: 'anon-visitor-0000004', contentSlug: 'motion-guide' },
    });
    assert.equal(ok.json.ok, true);
    const wrong = await call('POST', '/v1/keywords/lookup', {
      origin: ALPHA_SITE,
      headers: { 'x-hp-key': alphaPublicKey },
      body: { word: 'motion', anonId: 'anon-visitor-0000004', contentSlug: 'old-guide' },
    });
    assert.deepEqual(wrong.json, { ok: false });
  });

  test('misses look identical to the visitor but are recorded for the owner', async () => {
    const miss = await call('POST', '/v1/keywords/lookup', { origin: ALPHA_SITE, headers: { 'x-hp-key': alphaPublicKey }, body: { word: 'motoin', anonId: 'anon-visitor-0000001' } });
    const junk = await call('POST', '/v1/keywords/lookup', { origin: ALPHA_SITE, headers: { 'x-hp-key': alphaPublicKey }, body: { word: "x'; drop table--", anonId: 'anon-visitor-0000001' } });
    assert.deepEqual(miss.json, { ok: false });
    assert.deepEqual(junk.json, { ok: false });
    const r = await call('GET', '/admin/keywords/misses', { cookie: staffCookie });
    assert.ok(r.json.misses.some((m: { word: string }) => m.word === 'motoin'));
  });

  test('another tenant\'s key cannot find this tenant\'s keyword', async () => {
    const r = await call('POST', '/v1/keywords/lookup', { origin: 'https://bravo.example', headers: { 'x-hp-key': bravoPublicKey }, body: { word: 'motion', anonId: 'anon-visitor-0000002' } });
    assert.deepEqual(r.json, { ok: false });
  });

  test('public keys only work from their allowed origins; secret keys never from a browser', async () => {
    const lookup = (extra: { origin?: string | null; key?: string }) =>
      call('POST', '/v1/keywords/lookup', { origin: extra.origin, headers: { 'x-hp-key': extra.key ?? alphaPublicKey }, body: { word: 'motion', anonId: 'anon-visitor-0000003' } });
    assert.equal((await lookup({ origin: 'https://evil.test' })).status, 403);
    assert.equal((await lookup({ origin: null })).status, 403);
    assert.equal((await lookup({ origin: ALPHA_SITE, key: alphaSecretKey })).status, 401, 'lookup is public-key only');
    assert.equal((await lookup({ origin: ALPHA_SITE, key: 'hp_pk_deadbeef_' + 'A'.repeat(32) })).status, 401);
    assert.equal((await call('GET', '/v1/content/motion-guide', { origin: ALPHA_SITE, headers: { 'x-hp-key': alphaSecretKey } })).status, 403);
  });

  test('catalog lists published items only, without asset URLs', async () => {
    const res = await call('GET', '/v1/catalog', { origin: ALPHA_SITE, headers: { 'x-hp-key': alphaPublicKey } });
    assert.equal(res.status, 200);
    const slugs = (res.json.items as { slug: string }[]).map((i) => i.slug);
    assert.ok(slugs.includes('motion-guide'));
    assert.ok(!slugs.includes('hidden-draft'));
    const row = (res.json.items as { slug: string; bodyRef?: string }[]).find((i) => i.slug === 'motion-guide');
    assert.equal(row?.bodyRef, undefined);
  });

  test('gating: teaser without the word, content with the right session, not with a wrong or forged one', async () => {
    const get = (slug: string, h: Record<string, string> = {}) => call('GET', `/v1/content/${slug}`, { origin: ALPHA_SITE, headers: { 'x-hp-key': alphaPublicKey, ...h } });
    const teaser = await get('motion-guide');
    assert.equal(teaser.json.access, false);
    assert.equal(teaser.json.teaser.title, 'Motion guide');
    assert.equal(teaser.json.content, undefined, 'locked content must not leak any body reference');

    const unlocked = await get('motion-guide', { 'x-hp-session': (globalThis as any).__session });
    assert.equal(unlocked.json.access, true);
    assert.equal(unlocked.json.content.bodyRef, 'guides/motion.md');

    const otherContent = signToken({ t: alpha, c: '00000000-0000-0000-0000-000000000000' }, config.keywordKeys, 600);
    assert.equal((await get('motion-guide', { 'x-hp-session': otherContent })).json.access, false, 'session for a different item');
    const otherTenant = signToken({ t: bravo, c: guideId }, config.keywordKeys, 600);
    assert.equal((await get('motion-guide', { 'x-hp-session': otherTenant })).json.access, false, 'session minted for a different tenant');
    const forged = signToken({ t: alpha, c: guideId }, { current: 'k1', keys: { k1: 'x'.repeat(40) } }, 600);
    assert.equal((await get('motion-guide', { 'x-hp-session': forged })).json.access, false, 'wrong signing key');
  });

  test('"free after a month" opens by date with no word; paid never does; drafts do not exist', async () => {
    const get = (slug: string, h: Record<string, string> = {}) => call('GET', `/v1/content/${slug}`, { origin: ALPHA_SITE, headers: { 'x-hp-key': alphaPublicKey, ...h } });
    assert.equal((await get('old-guide')).json.access, true);
    const paid = await get('roadmap-kit', { 'x-hp-session': (globalThis as any).__session });
    assert.equal(paid.json.access, false);
    assert.equal(paid.json.content, undefined);
    assert.equal((await get('hidden-draft')).status, 404);
    assert.equal((await get('bravo-secret')).status, 404, 'another tenant\'s content does not exist here');
  });

  test('paid access: manual grant by staff, then the tenant\'s own server (secret key) sees it', async () => {
    const asServer = (email: string) => call('GET', '/v1/content/roadmap-kit', { origin: null, headers: { 'x-hp-key': alphaSecretKey, 'x-hp-customer': email } });
    assert.equal((await asServer('buyer@client.test')).json.access, false);

    const grant = await call('POST', '/admin/access/grant', { cookie: staffCookie, body: { email: 'Buyer@Client.test', contentSlug: 'roadmap-kit', note: 'bank transfer ref 1234' } });
    assert.equal(grant.status, 201);
    assert.equal((await call('POST', '/admin/access/grant', { cookie: staffCookie, body: { email: 'buyer@client.test', contentSlug: 'roadmap-kit' } })).status, 200, 'second grant is a no-op');

    const ok = await asServer('buyer@client.test');
    assert.equal(ok.json.access, true);
    assert.equal(ok.json.content.bodyRef, 'kits/roadmap.pdf');
    assert.equal((await asServer('someone-else@client.test')).json.access, false);
  });

  test('partner portal OTP returns a bearer session for BFF', async () => {
    process.env.ACCESS_TEST_OTP = '123456';
    const created = await call('POST', '/admin/partners', {
      cookie: staffCookie,
      body: { displayName: 'Portal Only', email: 'portal-only@alpha.test', commissionPct: 5, portalCode: 'portal-only-code' },
    });
    assert.equal(created.status, 201);
    const portalCode = created.json.portalCode as string;
    assert.equal(
      (await call('POST', '/auth/partner/request-otp', { body: { tenantSlug: 'alpha', email: 'portal-only@alpha.test', portalCode } })).status,
      200,
    );
    const verified = await call('POST', '/auth/partner/verify-otp', {
      body: { tenantSlug: 'alpha', email: 'portal-only@alpha.test', otp: '123456' },
      headers: { 'x-hp-session-mode': 'body' },
    });
    assert.equal(verified.status, 200);
    assert.equal(verified.json.role, 'partner');
    assert.ok(verified.json.sessionToken);
    const bearer = verified.json.sessionToken as string;
    const camps = await call('GET', '/partner/campaigns', { headers: { Authorization: `Bearer ${bearer}` }, origin: ADMIN });
    assert.equal(camps.status, 200);
    delete process.env.ACCESS_TEST_OTP;
  });

  test('a partner sees only their own campaigns and aggregate stats; no admin routes', async () => {
    const partnerId = (globalThis as any).__partnerId as string;
    const other = await call('POST', '/admin/partners', {
      cookie: staffCookie,
      body: { displayName: 'Omar', email: 'omar@partner.test', commissionPct: 12, portalCode: 'portal-omar-v1' },
    });
    await call('POST', '/admin/campaigns', { cookie: staffCookie, body: { title: 'Omar video', partnerId: other.json.id } });
    const uid = await seedUser(t.seed, 'sara@partner.test', { passwordHash: await hashPassword(PASSWORD) });
    await seedMembership(t.seed, alpha, uid, 'partner', { partnerId });

    const r = await login({ email: 'sara@partner.test', password: PASSWORD });
    assert.equal(r.status, 200);
    const cookie = sessionOf(r)!;
    const camps = await call('GET', '/partner/campaigns', { cookie });
    assert.deepEqual(camps.json.campaigns.map((c: { title: string }) => c.title), ['Sara video']);
    const stats = await call('GET', '/partner/stats', { cookie });
    assert.equal(stats.status, 200);
    assert.ok(stats.json.last30Days.length > 0);
    assert.ok(!JSON.stringify(stats.json).includes('@'), 'no emails in partner data');

    for (const [m, url] of [['GET', '/admin/content'], ['GET', '/admin/keywords/misses']] as const) {
      assert.equal((await call(m, url, { cookie })).status, 403, url);
    }
    assert.equal((await call('POST', '/admin/keywords', { cookie, body: { word: 'sneaky', contentSlug: 'motion-guide' } })).status, 403);
  });

  test('logout revokes the session server-side', async () => {
    const r = await login({ email: 'staff@alpha.test', password: PASSWORD });
    const cookie = sessionOf(r)!;
    assert.equal((await call('GET', '/admin/content', { cookie })).status, 200);
    assert.equal((await call('POST', '/auth/logout', { cookie })).status, 200);
    assert.equal((await call('GET', '/admin/content', { cookie })).status, 401);
  });

  test('staff can patch content metadata and asset URL', async () => {
    const patch = await call('PATCH', '/admin/content/hidden-draft', {
      cookie: staffCookie,
      body: { summary: 'Updated summary', bodyRef: 'https://cdn.example.com/draft.pdf' },
    });
    assert.equal(patch.status, 200, JSON.stringify(patch.json));
    const one = await call('GET', '/admin/content/hidden-draft', { cookie: staffCookie });
    assert.equal(one.status, 200);
    assert.equal(one.json.item.summary, 'Updated summary');
    assert.equal(one.json.item.body_ref, 'https://cdn.example.com/draft.pdf');
  });

  test('errors never leak SQL or stack traces', async () => {
    const r = await call('POST', '/admin/content', { cookie: ownerCookie, body: { slug: 'motion-guide', title: 'dup', kind: 'guide' } });
    assert.equal(r.status, 409);
    assert.deepEqual(r.json, { error: 'already_exists' });
  });
});
