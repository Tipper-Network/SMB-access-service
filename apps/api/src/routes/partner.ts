import type { FastifyInstance } from 'fastify';
import { requireRole, type AppCtx } from '../context.js';

// Partner session routes on Access. Commissions live on Payments. Catalogue: docs/platform-routes.md
// Partner panel data. Two layers protect it: explicit WHERE clauses here, and row-level
// security underneath (a partner session physically cannot read other partners' rows,
// customer emails or orders, even if a query here were written wrongly).

/**
 * Partner session routes on Access. Commissions are on Payments.
 *
 * `GET /partner/campaigns` — that partner's campaigns.
 * `GET /partner/stats` — counts for 30 days, no visitor emails.
 *
 * @param app - Access Fastify instance
 * @param ctx - Database. Row-level security also limits the partner to their own rows.
 */
export function registerPartnerRoutes(app: FastifyInstance, ctx: AppCtx): void {
  const { db } = ctx;

  app.get('/partner/campaigns', { preHandler: requireRole(ctx, 'partner') }, async (req) =>
    db.withTenant(req.actor!, async (q) => ({
      campaigns: (
        await q.query(
          'SELECT id, title, platform, post_url, trigger_word, published_on FROM access.campaigns WHERE partner_id = $1 ORDER BY created_at DESC',
          [req.actor!.partnerId],
        )
      ).rows,
    })),
  );

  // Aggregates only: counts, never individual visitors or emails.
  app.get('/partner/stats', { preHandler: requireRole(ctx, 'partner') }, async (req) =>
    db.withTenant(req.actor!, async (q) => ({
      last30Days: (
        await q.query(
          `SELECT type, matched, count(*)::int AS n FROM access.events
           WHERE partner_id = $1 AND created_at > now() - interval '30 days'
           GROUP BY type, matched ORDER BY type, matched`,
          [req.actor!.partnerId],
        )
      ).rows,
    })),
  );
}
