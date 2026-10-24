import Fastify, { type FastifyInstance } from 'fastify';
import cookie from '@fastify/cookie';
import rateLimit from '@fastify/rate-limit';
import { ZodError } from 'zod';
import { MemoryNonceStore, type Db, type NonceStore } from '@hardport/core';
import type { AccessConfig } from './config.js';
import type { AppCtx } from './context.js';
import { registerAuthRoutes } from './routes/auth.js';
import { registerPublicRoutes } from './routes/public.js';
import { registerAdminRoutes } from './routes/admin.js';
import { registerPartnerRoutes } from './routes/partner.js';
import { registerPartnerAuthRoutes } from './routes/partner-auth.js';
import { registerInternalRoutes } from './routes/internal.js';

export interface BuildDeps {
  db: Db;
  config: AccessConfig;
  /** Use a shared store (Redis or a table) when running more than one instance. */
  nonceStore?: NonceStore;
}

/**
 * Builds the Access HTTP server: auth, public content, staff, partner, and the internal event route.
 * @param deps - Database pool, config, and an optional shared nonce store
 */
export async function buildApp(deps: BuildDeps): Promise<FastifyInstance> {
  const ctx: AppCtx = { db: deps.db, config: deps.config, nonceStore: deps.nonceStore ?? new MemoryNonceStore() };
  const app = Fastify({ logger: false, trustProxy: deps.config.trustProxy, bodyLimit: 100_000 });

  await app.register(cookie);
  // In-memory counters: fine for one instance. Behind several, pass a Redis store to this plugin.
  await app.register(rateLimit, { global: false });

  app.addHook('onRequest', async (_req, reply) => {
    reply.header('x-content-type-options', 'nosniff');
    reply.header('referrer-policy', 'no-referrer');
    reply.header('cache-control', 'no-store');
  });

  app.setErrorHandler((err: Error & { statusCode?: number }, _req, reply) => {
    if (err instanceof ZodError) return reply.code(400).send({ error: 'invalid_request', fields: err.issues.map((i) => i.path.join('.')) });
    if (err.statusCode === 422) return reply.code(422).send({ error: 'unprocessable' });
    if (err.statusCode && err.statusCode < 500) return reply.code(err.statusCode).send({ error: err.statusCode === 429 ? 'rate_limited' : 'request_failed' });
    // Never leak SQL, stack traces or table names to clients.
    console.error('[access] unhandled error:', err.message);
    return reply.code(500).send({ error: 'internal' });
  });

  app.get('/healthz', async () => ({ ok: true }));

  registerAuthRoutes(app, ctx);
  registerPartnerAuthRoutes(app, ctx);
  registerPublicRoutes(app, ctx);
  registerAdminRoutes(app, ctx);
  registerPartnerRoutes(app, ctx);
  registerInternalRoutes(app, ctx);
  return app;
}
