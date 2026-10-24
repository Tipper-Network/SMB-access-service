import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import {
  burnPasswordCheck,
  cookieName,
  decryptField,
  hashSessionToken,
  pepperedHash,
  randomToken,
  resolveSessionActor,
  verifyPassword,
  verifyTotp,
} from '@hardport/core';
import { originAllowed, readSessionToken, type AppCtx } from '../context.js';
import { sessionPayload, wantsSessionBody } from '../session-response.js';

const LoginBody = z
  .object({
    email: z.string().email().max(254),
    password: z.string().min(1).max(200),
    totp: z.string().regex(/^\d{6}$/).optional(),
    tenantSlug: z.string().max(40).optional(),
  })
  .strict();

interface UserRow {
  id: string;
  password_hash: string | null;
  twofa_enabled: boolean;
  twofa_secret_enc: string | null;
  twofa_last_step: string | null; // bigint comes back as a string
  status: string;
}

/**
 * `POST /auth/login` and `POST /auth/logout`.
 * Login sets the session cookie used by Access and Payments staff routes. Origin must be in `ADMIN_ORIGINS`.
 * Every failure is `401 invalid_credentials`. Owner and admin must send a TOTP code.
 *
 * @param app - Access Fastify instance
 * @param ctx - Database and session settings
 */
export function registerAuthRoutes(app: FastifyInstance, ctx: AppCtx): void {
  const { db, config } = ctx;
  const name = cookieName(config.cookieSecure);

  app.post('/auth/login', { config: { rateLimit: { max: config.loginRateLimitPerMinute, timeWindow: '1 minute' } } }, async (req, reply) => {
    if (!originAllowed(ctx, req)) return reply.code(403).send({ error: 'bad_origin' });
    const body = LoginBody.parse(req.body);
    const email = body.email.trim().toLowerCase();
    const emailHash = pepperedHash(email, config.ipPepper);
    const ipHash = pepperedHash(req.ip, config.ipPepper);
    /** Records a failed attempt and returns the same 401 for every bad login. */
    const fail = async () => {
      await db.withoutTenant((q) => q.query('SELECT platform.record_login_attempt($1, $2, false)', [emailHash, ipHash]));
      // One message for every failure: unknown email, wrong password, wrong or reused 2FA code.
      return reply.code(401).send({ error: 'invalid_credentials' });
    };

    // 1. lockout (per email and per IP, both stored only as keyed hashes)
    const counts = (
      await db.withoutTenant((q) =>
        q.query<{ by_email: number; by_ip: number }>(`SELECT * FROM platform.login_failures($1, $2, interval '15 minutes')`, [emailHash, ipHash]),
      )
    ).rows[0];
    if ((counts?.by_email ?? 0) >= 5 || (counts?.by_ip ?? 0) >= 30) {
      return reply.code(429).send({ error: 'too_many_attempts' });
    }

    // 2. password (constant-ish time even when the email does not exist)
    const user = (await db.withoutTenant((q) => q.query<UserRow>('SELECT * FROM platform.get_user_for_login($1)', [email]))).rows[0];
    let passwordOk = false;
    if (user && user.status === 'active' && user.password_hash) passwordOk = await verifyPassword(body.password, user.password_hash);
    else await burnPasswordCheck(body.password);
    if (!passwordOk || !user) return fail();

    // 3. which tenant is this session for?
    const memberships = (
      await db.withoutTenant((q) =>
        q.query<{ tenant_id: string; tenant_slug: string; role: string }>('SELECT tenant_id, tenant_slug, role FROM platform.list_memberships($1)', [user.id]),
      )
    ).rows;
    if (memberships.length === 0) return reply.code(403).send({ error: 'no_access' });
    const chosen = body.tenantSlug ? memberships.find((m) => m.tenant_slug === body.tenantSlug) : memberships.length === 1 ? memberships[0] : undefined;
    if (!chosen) {
      if (body.tenantSlug) return fail();
      return reply.code(409).send({ error: 'tenant_required', tenants: memberships.map((m) => m.tenant_slug) });
    }

    // 4. second factor — only when enabled on the user (owners/admins may log in with password until 2FA is turned on)
    if (!config.skip2fa && user.twofa_enabled) {
      if (!body.totp || !user.twofa_secret_enc) return fail();
      const secret = decryptField(user.twofa_secret_enc, config.fieldKeys, `user:${user.id}:twofa`);
      const step = verifyTotp(secret, body.totp, { lastStep: user.twofa_last_step === null ? null : Number(user.twofa_last_step) });
      if (step === null) return fail();
      const accepted = (
        await db.withoutTenant((q) => q.query<{ ok: boolean }>('SELECT platform.accept_twofa_step($1, $2) AS ok', [user.id, step]))
      ).rows[0]?.ok;
      if (!accepted) return fail(); // lost a race with a replay of the same code
    }

    // 5. session: random token in an HttpOnly cookie; only its hash is stored
    const token = randomToken(32);
    const created = (
      await db.withoutTenant((q) =>
        q.query<{ ok: boolean }>('SELECT platform.create_session($1, $2, $3, make_interval(hours => $4::int), $5, $6) AS ok', [
          user.id,
          chosen.tenant_id,
          hashSessionToken(token),
          config.sessionTtlHours,
          ipHash,
          String(req.headers['user-agent'] ?? ''),
        ]),
      )
    ).rows[0]?.ok;
    if (!created) return fail();

    await db.withoutTenant((q) => q.query('SELECT platform.record_login_attempt($1, $2, true)', [emailHash, ipHash]));
    return sessionPayload(req, reply, config, token, config.sessionTtlHours, {
      tenant: chosen.tenant_slug,
      role: chosen.role,
    });
  });

  app.get('/auth/session', async (req, reply) => {
    const token = readSessionToken(req, config.cookieSecure);
    const actor = await resolveSessionActor(db, token);
    if (!actor) return reply.code(401).send({ error: 'unauthenticated' });
    const row = (
      await db.withoutTenant((q) =>
        q.query<{ slug: string }>('SELECT slug FROM platform.tenants WHERE id = $1', [actor.tenantId]),
      )
    ).rows[0];
    if (!row) return reply.code(401).send({ error: 'unauthenticated' });
    return {
      ok: true,
      tenant: row.slug,
      role: actor.role,
      partnerId: actor.partnerId ?? null,
    };
  });

  app.post('/auth/logout', async (req, reply) => {
    if (!originAllowed(ctx, req) && !wantsSessionBody(req)) return reply.code(403).send({ error: 'bad_origin' });
    const token = readSessionToken(req, config.cookieSecure);
    if (token) await db.withoutTenant((q) => q.query('SELECT platform.revoke_session($1)', [hashSessionToken(token)]));
    reply.clearCookie(name, { path: '/' });
    return { ok: true };
  });
}
