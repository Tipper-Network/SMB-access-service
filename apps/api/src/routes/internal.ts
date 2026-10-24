import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { verifyRequest } from '@hardport/core';
import type { AppCtx } from '../context.js';

// Payments -> Access. Catalogue: docs/platform-routes.md
// Receives signed events from the Payments product. Not reachable with a cookie or API key:
// the only credential is the HMAC signature (rotatable key ring, timestamp window, nonce).
// Delivery is at-least-once, so every event is de-duplicated through access.processed_events.

const EventBody = z.object({
  id: z.string().min(1).max(100),
  type: z.enum(['order.paid', 'order.refunded']),
  tenantId: z.string().uuid(),
  data: z.object({
    orderId: z.string().uuid(),
    customerEmail: z.string().email().max(254),
    itemRef: z.string().max(100),
  }),
});

/**
 * `POST /internal/events`. Called by the Payments outbox, not by a browser or an API key.
 * The only credential is `x-hp-signature`. `order.paid` creates an entitlement. `order.refunded` revokes it.
 * The same event id is acknowledged and ignored.
 *
 * @param app - Access Fastify instance
 * @param ctx - Database and the internal signing keys shared with Payments
 */
export function registerInternalRoutes(app: FastifyInstance, ctx: AppCtx): void {
  app.register(async (scope) => {
    // Keep the raw body: the signature is computed over the exact bytes that were sent.
    scope.addContentTypeParser('application/json', { parseAs: 'string' }, (_req, body, done) => done(null, body));

    scope.post('/internal/events', async (req, reply) => {
      const raw = typeof req.body === 'string' ? req.body : '';
      const verdict = await verifyRequest({
        keys: ctx.config.internalKeys,
        header: req.headers['x-hp-signature'] as string | undefined,
        method: 'POST',
        path: req.url,
        body: raw,
        nonceStore: ctx.nonceStore,
      });
      if (!verdict.ok) return reply.code(401).send({ error: 'unauthorized' });

      let parsed: unknown;
      try {
        parsed = JSON.parse(raw);
      } catch {
        return reply.code(400).send({ error: 'invalid_json' });
      }
      const event = EventBody.parse(parsed);

      return ctx.db.withTenant({ tenantId: event.tenantId, role: 'system' }, async (q) => {
        const fresh = await q.query('INSERT INTO access.processed_events (tenant_id, event_id) VALUES ($1, $2) ON CONFLICT DO NOTHING', [event.tenantId, event.id]);
        if (fresh.rowCount === 0) return { ok: true, duplicate: true };

        if (event.type === 'order.paid') {
          const content = (await q.query<{ id: string }>('SELECT id FROM access.content_items WHERE slug = $1', [event.data.itemRef])).rows[0];
          if (!content) {
            // Throwing rolls back the inbox row too, so Payments retries; an operator can fix the catalogue.
            throw Object.assign(new Error('unknown item'), { statusCode: 422 });
          }
          const customer = (
            await q.query<{ id: string }>(
              `INSERT INTO access.customers (tenant_id, email) VALUES ($1, $2)
               ON CONFLICT (tenant_id, lower(email)) DO UPDATE SET email = access.customers.email RETURNING id`,
              [event.tenantId, event.data.customerEmail],
            )
          ).rows[0]!;
          await q.query(
            `INSERT INTO access.entitlements (tenant_id, customer_id, content_id, source, order_ref) VALUES ($1, $2, $3, 'purchase', $4)
             ON CONFLICT (tenant_id, customer_id, content_id) WHERE revoked_at IS NULL AND customer_id IS NOT NULL DO NOTHING`,
            [event.tenantId, customer.id, content.id, event.data.orderId],
          );
        } else {
          await q.query(`UPDATE access.entitlements SET revoked_at = now() WHERE order_ref = $1 AND revoked_at IS NULL`, [event.data.orderId]);
        }
        return { ok: true };
      });
    });
  });
}
