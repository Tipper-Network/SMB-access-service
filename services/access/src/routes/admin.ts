import { randomUUID } from 'node:crypto';
import type { FastifyInstance, FastifyReply } from 'fastify';
import { z } from 'zod';
import { encryptField, generateApiKey, hashPassword } from '@hardport/core';
import { audit, pgCode, requireRole, type AppCtx } from '../context.js';
import { fail, ok, respond } from '../respond.js';
import { normalizeKeyword } from '../rules.js';
import { generatePortalCode } from './partner-auth.js';
import { createPresignedUpload, loadS3UploadConfig } from '../s3-upload.js';

// Staff session routes for a tenant's own operators. Catalogue: docs/platform-routes.md
// Tenant back-office. Every body schema is .strict(): unknown fields (like tenant_id) are
// rejected, so mass-assignment is impossible. The tenant always comes from the session.

export enum StaffRoles__Enum {
  OWNER = 'OWNER',
  ADMIN = 'ADMIN',
  STAFF = 'STAFF',
}
export enum AdminsRoles__Enum {
  OWNER = 'OWNER',
  ADMIN = 'ADMIN',
}
export type StaffRoles = keyof typeof StaffRoles__Enum;
export  type AdminsRoles = keyof typeof AdminsRoles__Enum;

const contentFields = {
  slug: z.string().regex(/^[a-z0-9][a-z0-9-]{0,80}$/),
  title: z.string().min(1).max(200),
  summary: z.string().max(1000).optional(),
  kind: z.enum(['guide', 'part', 'video', 'session', 'ebook', 'download']),
  accessMode: z.enum(['open', 'keyword_first', 'paid']),
  freeFrom: z.string().datetime().optional(),
  bodyRef: z.string().max(500).optional(),
  bookingUrl: z.string().url().max(500).optional(),
  youtubeUrl: z.string().url().max(500).optional(),
  substackUrl: z.string().url().max(500).optional(),
  sourceLabel: z.string().max(200).optional(),
  sourceUrl: z.string().url().max(500).optional(),
  priceMinor: z.number().int().min(0).max(100_000_000).optional(),
  currency: z.string().length(3).optional(),
  status: z.enum(['draft', 'published', 'archived']),
};

const ContentBody = z
  .object({
    ...contentFields,
    accessMode: contentFields.accessMode.default('keyword_first'),
    status: z.enum(['draft', 'published']).default('draft'),
  })
  .strict();

const ContentPatchBody = z
  .object({
    title: contentFields.title.optional(),
    summary: contentFields.summary,
    kind: contentFields.kind.optional(),
    accessMode: contentFields.accessMode.optional(),
    freeFrom: contentFields.freeFrom,
    bodyRef: z.union([contentFields.bodyRef, z.literal('')]).optional(),
    bookingUrl: z.union([contentFields.bookingUrl, z.literal('')]).optional(),
    youtubeUrl: z.union([contentFields.youtubeUrl, z.literal('')]).optional(),
    substackUrl: z.union([contentFields.substackUrl, z.literal('')]).optional(),
    sourceLabel: z.union([contentFields.sourceLabel, z.literal('')]).optional(),
    sourceUrl: z.union([contentFields.sourceUrl, z.literal('')]).optional(),
    priceMinor: contentFields.priceMinor,
    currency: contentFields.currency,
    status: contentFields.status.optional(),
  })
  .strict()
  .refine((b) => Object.keys(b).length > 0, { message: 'empty_patch' });

const KeywordBody = z.object({ word: z.string().min(1).max(60), contentSlug: z.string().max(81), campaignId: z.string().uuid().optional() }).strict();
const PartnerBody = z
  .object({
    displayName: z.string().min(1).max(100),
    email: z.string().email().max(254),
    commissionPct: z.number().min(0).max(100).default(0),
    payoutDetails: z.string().max(500).optional(),
    portalCode: z.string().min(6).max(64).optional(),
  })
  .strict();
const CampaignBody = z
  .object({
    title: z.string().min(1).max(200),
    platform: z.enum(['youtube', 'short', 'tiktok', 'instagram', 'x', 'other']).optional(),
    postUrl: z.string().url().max(500).optional(),
    triggerWord: z.string().max(40).optional(),
    partnerId: z.string().uuid().optional(),
  })
  .strict();

const PresignUploadBody = z
  .object({
    slug: z.string().regex(/^[a-z0-9][a-z0-9-]{0,80}$/),
    filename: z.string().min(1).max(200),
    contentType: z.string().max(200).optional(),
  })
  .strict();
const GrantBody = z.object({ email: z.string().email().max(254), contentSlug: z.string().max(81), note: z.string().max(300).optional() }).strict();
const SiteBody = z.object({ domain: z.string().min(3).max(253).regex(/^[a-z0-9.-]+$/), origins: z.array(z.string().url().max(200)).min(1).max(10) }).strict();

/**
 * Staff session routes. Cookie from `POST /auth/login`. Unsafe methods also require an admin Origin.
 * Tenant id always comes from the session. Unknown body fields are rejected.
 *
 * `GET /admin/content`, `POST /admin/content`, `POST /admin/partners`, `POST /admin/campaigns`,
 * `POST /admin/keywords`, `GET /admin/keywords/misses`, `POST /admin/access/grant` — owner, admin, staff.
 * `POST /admin/sites` — owner, admin. Returns the public and secret keys once.
 *
 * @param app - Access Fastify instance
 * @param ctx - Database and field-encryption keys
 */
export function registerAdminRoutes(app: FastifyInstance, ctx: AppCtx): void {
  const { db, config } = ctx;

  // Database constraint violations become clean 4xx answers; anything else is a real error.
  /**
   * Turns unique and foreign-key failures into 409 or 400. Other errors propagate.
   * @param reply - Fastify reply
   * @param work - Transaction that may throw a Postgres error
   */
  const withDbErrors = async (reply: FastifyReply, work: Promise<unknown>) => {
    try {
      return await work;
    } catch (err) {
      const c = pgCode(err);
      if (c === '23505') return reply.code(409).send({ error: 'already_exists' });
      if (c === '23503') return reply.code(400).send({ error: 'unknown_reference' });
      if (c === '23514') return reply.code(400).send({ error: 'invalid_value' });
      throw err;
    }
  };

  const contentSelect =
    'id, slug, title, summary, kind, access_mode, free_from, status, price_minor, currency, body_ref, booking_url, youtube_url, substack_url, source_label, source_url';

  app.post('/admin/uploads/presign', { preHandler: requireRole(ctx, ...Object.values(StaffRoles__Enum)) }, async (req, reply) => {
    const b = PresignUploadBody.parse(req.body);
    const actor = req.actor!;
    const tenantRow = await db.withTenant(actor, async (q) =>
      (await q.query<{ slug: string }>('SELECT slug FROM platform.tenants WHERE id = $1', [actor.tenantId])).rows[0],
    );
    if (!tenantRow?.slug) return reply.code(500).send({ error: 'tenant_not_found' });
    const s3 = loadS3UploadConfig(tenantRow.slug);
    if (!s3) return reply.code(503).send({ error: 's3_not_configured' });
    try {
      const out = await createPresignedUpload(s3, {
        slug: b.slug,
        filename: b.filename,
        contentType: b.contentType?.trim() || 'application/octet-stream',
      });
      return { ok: true, ...out };
    } catch {
      return reply.code(500).send({ error: 'presign_failed' });
    }
  });

  app.get('/admin/content', { preHandler: requireRole(ctx, ...Object.values(StaffRoles__Enum)) }, async (req) =>
    db.withTenant(req.actor!, async (q) => ({
      items: (await q.query(`SELECT ${contentSelect} FROM access.content_items ORDER BY created_at DESC LIMIT 500`)).rows,
    })),
  );

  app.get<{ Params: { slug: string } }>('/admin/content/:slug', { preHandler: requireRole(ctx, ...Object.values(StaffRoles__Enum)) }, async (req, reply) => {
    const row = await db.withTenant(req.actor!, async (q) =>
      (await q.query(`SELECT ${contentSelect} FROM access.content_items WHERE slug = $1`, [req.params.slug])).rows[0],
    );
    if (!row) return reply.code(404).send({ error: 'not_found' });
    return { item: row };
  });

  app.post('/admin/content', { preHandler: requireRole(ctx, ...Object.values(StaffRoles__Enum)) }, async (req, reply) => {
    const b = ContentBody.parse(req.body);
    const actor = req.actor!;
    return withDbErrors(
      reply,
      respond(
        reply,
        db.withTenant(actor, async (q) => {
          const row = (
            await q.query<{ id: string }>(
              `INSERT INTO access.content_items
                 (tenant_id, slug, title, summary, kind, access_mode, free_from,
                  body_ref, booking_url, youtube_url, substack_url, source_label, source_url,
                  price_minor, currency, status, published_at)
               VALUES ($1, $2, $3, $4, $5, $6,
                       CASE WHEN $6 = 'keyword_first' THEN COALESCE($7::timestamptz, now() + make_interval(days => $17::int)) ELSE $7::timestamptz END,
                       $8, $9, $10, $11, $12, $13, $14, $15, $16, CASE WHEN $16 = 'published' THEN now() END)
               RETURNING id`,
              [
                actor.tenantId,
                b.slug,
                b.title,
                b.summary ?? null,
                b.kind,
                b.accessMode,
                b.freeFrom ?? null,
                b.bodyRef ?? null,
                b.bookingUrl ?? null,
                b.youtubeUrl ?? null,
                b.substackUrl ?? null,
                b.sourceLabel ?? null,
                b.sourceUrl ?? null,
                b.priceMinor ?? null,
                b.currency ?? null,
                b.status,
                config.defaultFreeAfterDays,
              ],
            )
          ).rows[0]!;
          await audit(q, actor, 'content.create', row.id, { slug: b.slug, accessMode: b.accessMode });
          return ok({ id: row.id }, 201);
        }),
      ),
    );
  });

  app.patch<{ Params: { slug: string } }>('/admin/content/:slug', { preHandler: requireRole(ctx, ...Object.values(StaffRoles__Enum)) }, async (req, reply) => {
    const b = ContentPatchBody.parse(req.body);
    const actor = req.actor!;
    return withDbErrors(
      reply,
      respond(
        reply,
        db.withTenant(actor, async (q) => {
          const existing = (await q.query<{ id: string }>('SELECT id FROM access.content_items WHERE slug = $1', [req.params.slug])).rows[0];
          if (!existing) return fail(404, 'not_found');

          const sets: string[] = [];
          const vals: unknown[] = [];
          let n = 1;
          const add = (col: string, val: unknown) => {
            sets.push(`${col} = $${n++}`);
            vals.push(val);
          };

          if (b.title !== undefined) add('title', b.title);
          if (b.summary !== undefined) add('summary', b.summary);
          if (b.kind !== undefined) add('kind', b.kind);
          if (b.accessMode !== undefined) add('access_mode', b.accessMode);
          if (b.freeFrom !== undefined) add('free_from', b.freeFrom ?? null);
          if (b.bodyRef !== undefined) add('body_ref', b.bodyRef === '' ? null : b.bodyRef);
          if (b.bookingUrl !== undefined) add('booking_url', b.bookingUrl === '' ? null : b.bookingUrl);
          if (b.youtubeUrl !== undefined) add('youtube_url', b.youtubeUrl === '' ? null : b.youtubeUrl);
          if (b.substackUrl !== undefined) add('substack_url', b.substackUrl === '' ? null : b.substackUrl);
          if (b.sourceLabel !== undefined) add('source_label', b.sourceLabel === '' ? null : b.sourceLabel);
          if (b.sourceUrl !== undefined) add('source_url', b.sourceUrl === '' ? null : b.sourceUrl);
          if (b.priceMinor !== undefined) add('price_minor', b.priceMinor);
          if (b.currency !== undefined) add('currency', b.currency);
          if (b.status !== undefined) {
            add('status', b.status);
            if (b.status === 'published') sets.push('published_at = COALESCE(published_at, now())');
            if (b.status === 'draft') sets.push('published_at = NULL');
          }

          vals.push(req.params.slug);
          await q.query(`UPDATE access.content_items SET ${sets.join(', ')} WHERE slug = $${n}`, vals);

          await audit(q, actor, 'content.update', existing.id, { slug: req.params.slug });
          return ok({ id: existing.id }, 200);
        }),
      ),
    );
  });

  app.get('/admin/partners', { preHandler: requireRole(ctx, ...Object.values(StaffRoles__Enum)) }, async (req) =>
    db.withTenant(req.actor!, async (q) => ({
      items: (
        await q.query(
          `SELECT id, display_name, email, commission_pct, created_at
           FROM access.partners
           ORDER BY created_at DESC
           LIMIT 500`,
        )
      ).rows,
    })),
  );

  app.post('/admin/partners', { preHandler: requireRole(ctx, ...Object.values(StaffRoles__Enum)) }, async (req, reply) => {
    const b = PartnerBody.parse(req.body);
    const actor = req.actor!;
    const id = randomUUID(); // generated here so the encryption context can include it
    return withDbErrors(
      reply,
      respond(
        reply,
        db.withTenant(actor, async (q) => {
          const enc = b.payoutDetails ? encryptField(b.payoutDetails, config.fieldKeys, `partner:${id}:payout`) : null;
          const email = b.email.trim().toLowerCase();
          const portal =
            b.portalCode !== undefined
              ? { portalCode: b.portalCode, portalCodeHash: await hashPassword(b.portalCode) }
              : await generatePortalCode();
          await q.query(
            'INSERT INTO access.partners (id, tenant_id, display_name, email, commission_pct, payout_details_enc, portal_code_hash) VALUES ($1, $2, $3, $4, $5, $6, $7)',
            [id, actor.tenantId, b.displayName, email, b.commissionPct, enc, portal.portalCodeHash],
          );
          await audit(q, actor, 'partner.create', id, { displayName: b.displayName, commissionPct: b.commissionPct, email });
          return ok({ id, portalCode: portal.portalCode }, 201);
        }),
      ),
    );
  });

  app.post('/admin/campaigns', { preHandler: requireRole(ctx, ...Object.values(StaffRoles__Enum)) }, async (req, reply) => {
    const b = CampaignBody.parse(req.body);
    const actor = req.actor!;
    return withDbErrors(
      reply,
      respond(
        reply,
        db.withTenant(actor, async (q) => {
          const row = (
            await q.query<{ id: string }>(
              'INSERT INTO access.campaigns (tenant_id, title, platform, post_url, trigger_word, partner_id) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id',
              [actor.tenantId, b.title, b.platform ?? null, b.postUrl ?? null, b.triggerWord ?? null, b.partnerId ?? null],
            )
          ).rows[0]!;
          await audit(q, actor, 'campaign.create', row.id, { title: b.title });
          return ok({ id: row.id }, 201);
        }),
      ),
    );
  });

  app.post('/admin/keywords', { preHandler: requireRole(ctx, ...Object.values(StaffRoles__Enum)) }, async (req, reply) => {
    const b = KeywordBody.parse(req.body);
    const word = normalizeKeyword(b.word);
    if (!word) return reply.code(400).send({ error: 'invalid_word' });
    const actor = req.actor!;
    return withDbErrors(
      reply,
      respond(
        reply,
        db.withTenant(actor, async (q) => {
          const content = (await q.query<{ id: string }>('SELECT id FROM access.content_items WHERE slug = $1', [b.contentSlug])).rows[0];
          if (!content) return fail(400, 'unknown_reference');
          const row = (
            await q.query<{ id: string }>('INSERT INTO access.keywords (tenant_id, word, content_id, campaign_id) VALUES ($1, $2, $3, $4) RETURNING id', [actor.tenantId, word, content.id, b.campaignId ?? null])
          ).rows[0]!;
          await audit(q, actor, 'keyword.create', row.id, { word });
          return ok({ id: row.id, word }, 201);
        }),
      ),
    );
  });

  // What visitors typed that matched nothing in the last 7 days: typos and unmet demand.
  app.get('/admin/keywords/misses', { preHandler: requireRole(ctx, ...Object.values(StaffRoles__Enum)) }, async (req) =>
    db.withTenant(req.actor!, async (q) => ({
      misses: (
        await q.query(
          `SELECT keyword_text AS word, count(*)::int AS tries FROM access.events
           WHERE type = 'keyword_lookup' AND matched = false AND created_at > now() - interval '7 days'
           GROUP BY keyword_text ORDER BY tries DESC LIMIT 50`,
        )
      ).rows,
    })),
  );

  // Manual entitlement. Checkout grants the same row from order.paid; this is the operator override.
  app.post('/admin/access/grant', { preHandler: requireRole(ctx, ...Object.values(StaffRoles__Enum)) }, async (req, reply) => {
    const b = GrantBody.parse(req.body);
    const actor = req.actor!;
    return withDbErrors(
      reply,
      respond(
        reply,
        db.withTenant(actor, async (q) => {
          const content = (await q.query<{ id: string }>('SELECT id FROM access.content_items WHERE slug = $1', [b.contentSlug])).rows[0];
          if (!content) return fail(400, 'unknown_reference');
          const customer = (
            await q.query<{ id: string }>(
              `INSERT INTO access.customers (tenant_id, email) VALUES ($1, $2)
               ON CONFLICT (tenant_id, lower(email)) DO UPDATE SET email = access.customers.email RETURNING id`,
              [actor.tenantId, b.email.trim()],
            )
          ).rows[0]!;
          const granted = await q.query(
            `INSERT INTO access.entitlements (tenant_id, customer_id, content_id, source, order_ref) VALUES ($1, $2, $3, 'admin_grant', $4)
             ON CONFLICT (tenant_id, customer_id, content_id) WHERE revoked_at IS NULL AND customer_id IS NOT NULL DO NOTHING`,
            [actor.tenantId, customer.id, content.id, b.note ?? null],
          );
          await audit(q, actor, 'access.grant', content.id, { customerId: customer.id, note: b.note });
          return ok({ granted: granted.rowCount === 1 }, granted.rowCount === 1 ? 201 : 200);
        }),
      ),
    );
  });

  // Create a site with its keys. Raw keys are returned ONCE; only hashes are stored.
  app.post('/admin/sites', { preHandler: requireRole(ctx, ...Object.values(AdminsRoles__Enum)) }, async (req, reply) => {
    const b = SiteBody.parse(req.body);
    const actor = req.actor!;
    return withDbErrors(
      reply,
      respond(
        reply,
        db.withTenant(actor, async (q) => {
          const site = (await q.query<{ id: string }>('INSERT INTO platform.sites (tenant_id, domain) VALUES ($1, $2) RETURNING id', [actor.tenantId, b.domain])).rows[0]!;
          const pk = generateApiKey('public');
          const sk = generateApiKey('secret');
          await q.query('INSERT INTO platform.api_keys (tenant_id, site_id, kind, key_prefix, key_hash, allowed_origins) VALUES ($1, $2, $3, $4, $5, $6)', [actor.tenantId, site.id, 'public', pk.prefix, pk.hash, b.origins]);
          await q.query('INSERT INTO platform.api_keys (tenant_id, site_id, kind, key_prefix, key_hash, allowed_origins) VALUES ($1, $2, $3, $4, $5, $6)', [actor.tenantId, site.id, 'secret', sk.prefix, sk.hash, []]);
          await audit(q, actor, 'site.create', site.id, { domain: b.domain });
          return ok({ siteId: site.id, publicKey: pk.key, secretKey: sk.key, note: 'Store the secret key now; it cannot be shown again.' }, 201);
        }),
      ),
    );
  });
}
