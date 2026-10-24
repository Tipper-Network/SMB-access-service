import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { signToken, verifyToken } from '@hardport/core';
import { resolveApiKey, type AppCtx } from '../context.js';
import { fail, ok, respond } from '../respond.js';
import { canAccess, normalizeKeyword } from '../rules.js';

// External content API. Catalogue: docs/platform-routes.md
// POST /v1/keywords/lookup   browser, public key + allowed Origin
// GET  /v1/content/:slug     browser (public key, optional x-hp-session) or tenant server (secret key, x-hp-customer)

const contentSlugField = z.string().regex(/^[a-z0-9][a-z0-9-]{0,80}$/)

const LookupBody = z
  .object({
    word: z.string().min(1).max(60),
    anonId: z.string().regex(/^[A-Za-z0-9_-]{16,64}$/),
    /** When set, the keyword must unlock this published product (not another slug). */
    contentSlug: contentSlugField.optional(),
  })
  .strict();

const KEYWORD_SESSION_DAYS = 30;

/**
 * Content routes a website calls with an API key. Bodies: docs/platform-routes.md.
 *
 * `POST /v1/keywords/lookup` — browser, public key, Origin on the key's allow-list.
 * `GET /v1/content/:slug` — browser with the public key and optional `x-hp-session`, or the tenant server with the secret key and `x-hp-customer`.
 * `OPTIONS /v1/*` — CORS preflight. It grants nothing.
 *
 * @param app - Access Fastify instance
 * @param ctx - Database, keyword signing keys, and API-key lookup
 */
export function registerPublicRoutes(app: FastifyInstance, ctx: AppCtx): void {
  const { db, config } = ctx;

  // CORS preflight carries no key, so it cannot be validated; it grants nothing by itself.
  // The real request is validated against the key's origin allow-list.
  app.options('/v1/*', async (req, reply) => {
    const origin = req.headers.origin;
    if (typeof origin === 'string') {
      reply.header('access-control-allow-origin', origin);
      reply.header('vary', 'origin');
    }
    reply.header('access-control-allow-methods', 'GET, POST, OPTIONS');
    reply.header('access-control-allow-headers', 'content-type, x-hp-key, x-hp-session');
    reply.header('access-control-max-age', '600');
    return reply.code(204).send();
  });

  app.post('/v1/keywords/lookup', { config: { rateLimit: { max: 20, timeWindow: '1 minute' } } }, async (req, reply) => {
    const key = await resolveApiKey(ctx, req, reply, ['public']);
    if (!key) return reply;
    const body = LookupBody.parse(req.body);
    const word = normalizeKeyword(body.word);
    const actor = { tenantId: key.tenantId, role: 'public' as const };

    return db.withTenant(actor, async (q) => {
      const visitor = (
        await q.query<{ id: string }>(
          `INSERT INTO access.visitors (tenant_id, anon_id) VALUES ($1, $2)
           ON CONFLICT (tenant_id, anon_id) DO UPDATE SET anon_id = EXCLUDED.anon_id RETURNING id`,
          [key.tenantId, body.anonId],
        )
      ).rows[0]!;

      const hit = word
        ? (
            await q.query<{ content_id: string; content_slug: string; campaign_id: string | null; partner_id: string | null }>(
              'SELECT content_id, content_slug, campaign_id, partner_id FROM access.lookup_keyword($1)',
              [word],
            )
          ).rows[0]
        : undefined;

      // Misses are recorded too: they show typos and demand. Only a short, capped copy of the text is kept.
      await q.query(
        `INSERT INTO access.events (tenant_id, visitor_id, type, keyword_text, matched, content_id, campaign_id, partner_id)
         VALUES ($1, $2, 'keyword_lookup', $3, $4, $5, $6, $7)`,
        [key.tenantId, visitor.id, (word ?? body.word).slice(0, 60), Boolean(hit), hit?.content_id ?? null, hit?.campaign_id ?? null, hit?.partner_id ?? null],
      );

      if (!hit) return { ok: false }; // identical response for "no such word", expired, unpublished, bad format
      if (body.contentSlug && hit.content_slug !== body.contentSlug) return { ok: false };

      if (hit.campaign_id) {
        await q.query(
          `UPDATE access.visitors SET first_campaign_id = COALESCE(first_campaign_id, $2), last_campaign_id = $2 WHERE id = $1`,
          [visitor.id, hit.campaign_id],
        );
      }
      const session = signToken({ t: key.tenantId, c: hit.content_id, v: visitor.id }, config.keywordKeys, KEYWORD_SESSION_DAYS * 86400);
      return { ok: true, slug: hit.content_slug, session };
    });
  });

  app.get('/v1/catalog', { config: { rateLimit: { max: 60, timeWindow: '1 minute' } } }, async (req, reply) => {
    const key = await resolveApiKey(ctx, req, reply, ['public', 'secret']);
    if (!key) return reply;
    const actor = { tenantId: key.tenantId, role: key.kind === 'secret' ? ('system' as const) : ('public' as const) };

    return respond(
      reply,
      db.withTenant(actor, async (q) => {
        const rows = (
          await q.query<{
            slug: string;
            title: string;
            summary: string | null;
            kind: string;
            access_mode: string;
            price_minor: number | null;
            currency: string | null;
          }>(
            `SELECT slug, title, summary, kind, access_mode, price_minor, currency
             FROM access.content_items
             WHERE status = 'published'
             ORDER BY published_at DESC NULLS LAST, title ASC
             LIMIT 200`,
          )
        ).rows;
        return ok({
          items: rows.map((row) => ({
            slug: row.slug,
            title: row.title,
            summary: row.summary,
            kind: row.kind,
            accessMode: row.access_mode,
            priceMinor: row.price_minor,
            currency: row.currency,
          })),
        });
      }),
    );
  });

  app.get<{ Params: { slug: string } }>('/v1/content/:slug', { config: { rateLimit: { max: 120, timeWindow: '1 minute' } } }, async (req, reply) => {
    const key = await resolveApiKey(ctx, req, reply, ['public', 'secret']);
    if (!key) return reply;
    const slug = z.string().regex(/^[a-z0-9][a-z0-9-]{0,80}$/).safeParse(req.params.slug);
    if (!slug.success) return reply.code(404).send({ error: 'not_found' });

    // The tenant's own server (secret key) may vouch for a customer; browsers only get what a keyword session unlocks.
    const actor = { tenantId: key.tenantId, role: key.kind === 'secret' ? ('system' as const) : ('public' as const) };
    const customerEmail = key.kind === 'secret' && typeof req.headers['x-hp-customer'] === 'string' ? req.headers['x-hp-customer'] : null;
    const sessionHeader = typeof req.headers['x-hp-session'] === 'string' ? req.headers['x-hp-session'] : null;

    return respond(reply, db.withTenant(actor, async (q) => {
      const item = (
        await q.query<{
          id: string;
          slug: string;
          title: string;
          summary: string | null;
          kind: string;
          access_mode: 'open' | 'keyword_first' | 'paid';
          free_from: Date | null;
          body_ref: string | null;
          booking_url: string | null;
          youtube_url: string | null;
          substack_url: string | null;
          source_label: string | null;
          source_url: string | null;
        }>(
          'SELECT id, slug, title, summary, kind, access_mode, free_from, body_ref, booking_url, youtube_url, substack_url, source_label, source_url FROM access.content_items WHERE slug = $1',
          [slug.data],
        )
      ).rows[0];
      if (!item) return fail(404, 'not_found'); // drafts look exactly like "does not exist"

      const session = sessionHeader ? verifyToken<{ t: string; c: string }>(sessionHeader, config.keywordKeys) : null;
      const hasKeywordSession = Boolean(session && session.t === key.tenantId && session.c === item.id);
      const hasEntitlement = customerEmail
        ? ((
            await q.query(
              `SELECT 1 FROM access.entitlements e
               JOIN access.customers c ON c.tenant_id = e.tenant_id AND c.id = e.customer_id
               WHERE e.content_id = $1 AND lower(c.email) = lower($2) AND e.revoked_at IS NULL`,
              [item.id, customerEmail],
            )
          ).rowCount ?? 0) > 0
        : false;

      if (!canAccess(item, { hasKeywordSession, hasEntitlement })) {
        return ok({ access: false, teaser: { slug: item.slug, title: item.title, summary: item.summary, accessMode: item.access_mode, freeFrom: item.free_from } });
      }
      await q.query(`INSERT INTO access.events (tenant_id, type, content_id) VALUES ($1, 'content_open', $2)`, [key.tenantId, item.id]);
      // TODO(production): exchange body_ref for a short-lived signed storage URL instead of returning it raw.
      return ok({
        access: true,
        content: {
          slug: item.slug,
          title: item.title,
          kind: item.kind,
          summary: item.summary,
          bodyRef: item.body_ref,
          bookingUrl: item.booking_url,
          youtubeUrl: item.youtube_url,
          substackUrl: item.substack_url,
          sourceLabel: item.source_label,
          sourceUrl: item.source_url,
        },
      });
    }));
  });
}
