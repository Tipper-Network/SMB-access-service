import { randomInt } from 'node:crypto';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { burnPasswordCheck, hashSessionToken, hashPassword, pepperedHash, randomToken, verifyPassword } from '@hardport/core';
import { sendAccessMail } from '../mail.js';
import { sessionPayload } from '../session-response.js';
import type { AppCtx } from '../context.js';

const PortalBody = z
  .object({
    tenantSlug: z.string().min(1).max(40),
    email: z.string().email().max(254),
    portalCode: z.string().min(4).max(64),
  })
  .strict();

const VerifyOtpBody = z
  .object({
    tenantSlug: z.string().min(1).max(40),
    email: z.string().email().max(254),
    otp: z.string().regex(/^\d{6}$/),
  })
  .strict();

/**
 * Partner portal login (no OAuth). Email + portal code → OTP email → session.
 * Intended for server-side BFF calls (`x-hp-session-mode: body`). No ADMIN_ORIGINS check.
 */
export function registerPartnerAuthRoutes(app: FastifyInstance, ctx: AppCtx): void {
  const { db, config } = ctx;

  app.post('/auth/partner/request-otp', { config: { rateLimit: { max: 10, timeWindow: '1 minute' } } }, async (req, reply) => {
    const body = PortalBody.parse(req.body);
    const email = body.email.trim().toLowerCase();
    const emailHash = pepperedHash(email, config.ipPepper);
    const ipHash = pepperedHash(req.ip, config.ipPepper);

    const genericOk = () => reply.send({ ok: true });

    const counts = (
      await db.withoutTenant((q) =>
        q.query<{ by_email: number; by_ip: number }>(`SELECT * FROM platform.login_failures($1, $2, interval '15 minutes')`, [emailHash, ipHash]),
      )
    ).rows[0];
    if ((counts?.by_email ?? 0) >= 5 || (counts?.by_ip ?? 0) >= 30) {
      return reply.code(429).send({ error: 'too_many_attempts' });
    }

    const row = (
      await db.withoutTenant((q) =>
        q.query<{ tenant_id: string; partner_id: string; portal_code_hash: string; display_name: string }>(
          'SELECT * FROM access.find_partner_for_portal($1, $2)',
          [body.tenantSlug, email],
        ),
      )
    ).rows[0];

    let valid = false;
    if (row?.portal_code_hash) valid = await verifyPassword(body.portalCode, row.portal_code_hash);
    else await burnPasswordCheck(body.portalCode);

    if (!valid || !row) {
      await db.withoutTenant((q) => q.query('SELECT platform.record_login_attempt($1, $2, false)', [emailHash, ipHash]));
      return genericOk();
    }

    const otp =
      process.env.ACCESS_TEST_OTP?.match(/^\d{6}$/)?.[0] ?? String(randomInt(0, 1_000_000)).padStart(6, '0');
    const otpHash = pepperedHash(otp, config.ipPepper);
    const ttlMin = config.partnerOtpTtlMinutes;

    await db.withTenant({ tenantId: row.tenant_id, role: 'system' }, async (q) => {
      await q.query(
        `UPDATE access.partner_otp SET consumed_at = now()
         WHERE tenant_id = $1 AND partner_id = $2 AND consumed_at IS NULL`,
        [row.tenant_id, row.partner_id],
      );
      await q.query(
        `INSERT INTO access.partner_otp (tenant_id, partner_id, otp_hash, expires_at)
         VALUES ($1, $2, $3, now() + ($4::text || ' minutes')::interval)`,
        [row.tenant_id, row.partner_id, otpHash, ttlMin],
      );
    });

    await sendAccessMail(config, {
      to: email,
      subject: 'Your partner sign-in code',
      text: `Your one-time code is ${otp}. It expires in ${ttlMin} minutes.\n\n— Psyferblock Access`,
    });

    await db.withoutTenant((q) => q.query('SELECT platform.record_login_attempt($1, $2, true)', [emailHash, ipHash]));
    return genericOk();
  });

  app.post('/auth/partner/verify-otp', { config: { rateLimit: { max: 20, timeWindow: '1 minute' } } }, async (req, reply) => {
    const body = VerifyOtpBody.parse(req.body);
    const email = body.email.trim().toLowerCase();
    const emailHash = pepperedHash(email, config.ipPepper);
    const ipHash = pepperedHash(req.ip, config.ipPepper);
    const otpHash = pepperedHash(body.otp, config.ipPepper);

    const fail = async () => {
      await db.withoutTenant((q) => q.query('SELECT platform.record_login_attempt($1, $2, false)', [emailHash, ipHash]));
      return reply.code(401).send({ error: 'invalid_credentials' });
    };

    const partner = (
      await db.withoutTenant((q) =>
        q.query<{ tenant_id: string; partner_id: string }>('SELECT tenant_id, partner_id FROM access.find_partner_for_portal($1, $2)', [
          body.tenantSlug,
          email,
        ]),
      )
    ).rows[0];
    if (!partner) return fail();

    const otpRow = (
      await db.withTenant({ tenantId: partner.tenant_id, role: 'system' }, (q) =>
        q.query<{ id: string }>(
          `SELECT id FROM access.partner_otp
           WHERE tenant_id = $1 AND partner_id = $2 AND otp_hash = $3
             AND consumed_at IS NULL AND expires_at > now()
           ORDER BY created_at DESC LIMIT 1`,
          [partner.tenant_id, partner.partner_id, otpHash],
        ),
      )
    ).rows[0];
    if (!otpRow) return fail();

    const userId = (
      await db.withoutTenant((q) =>
        q.query<{ user_id: string }>('SELECT platform.ensure_partner_membership($1, $2, $3) AS user_id', [
          partner.tenant_id,
          partner.partner_id,
          email,
        ]),
      )
    ).rows[0]?.user_id;
    if (!userId) return fail();

    await db.withTenant({ tenantId: partner.tenant_id, role: 'system' }, (q) =>
      q.query('UPDATE access.partner_otp SET consumed_at = now() WHERE id = $1', [otpRow.id]),
    );

    const token = randomToken(32);
    const ttlHours = config.partnerSessionTtlHours;
    const created = (
      await db.withoutTenant((q) =>
        q.query<{ ok: boolean }>('SELECT platform.create_session($1, $2, $3, make_interval(hours => $4::int), $5, $6) AS ok', [
          userId,
          partner.tenant_id,
          hashSessionToken(token),
          ttlHours,
          ipHash,
          String(req.headers['user-agent'] ?? ''),
        ]),
      )
    ).rows[0]?.ok;
    if (!created) return fail();

    await db.withoutTenant((q) => q.query('SELECT platform.record_login_attempt($1, $2, true)', [emailHash, ipHash]));

    return sessionPayload(req, reply, config, token, ttlHours, {
      tenant: body.tenantSlug,
      role: 'partner',
    });
  });
}

/** Generates a portal code and its stored hash for admin partner create. */
export async function generatePortalCode(): Promise<{ portalCode: string; portalCodeHash: string }> {
  const portalCode = randomToken(12);
  const portalCodeHash = await hashPassword(portalCode);
  return { portalCode, portalCodeHash };
}
