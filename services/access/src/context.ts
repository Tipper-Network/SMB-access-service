import type { FastifyReply, FastifyRequest } from 'fastify';
import {
  apiKeyKind,
  hashApiKey,
  resolveSessionActor,
  cookieName,
  type ActorRole,
  type ApiKeyKind,
  type Db,
  type NonceStore,
  type Queryable,
  type SessionActor,
} from '@hardport/core';
import type { AccessConfig } from './config.js';

export interface AppCtx {
  db: Db;
  config: AccessConfig;
  nonceStore: NonceStore;
}

export interface ResolvedKey {
  tenantId: string;
  siteId: string;
  kind: ApiKeyKind;
  allowedOrigins: string[];
}

declare module 'fastify' {
  interface FastifyRequest {
    actor?: SessionActor;
    apiKey?: ResolvedKey;
  }
}

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

/** Session cookie or `Authorization: Bearer` (BFF replay). */
export function readSessionToken(req: FastifyRequest, cookieSecure: boolean): string | undefined {
  const fromCookie = req.cookies[cookieName(cookieSecure)];
  if (fromCookie) return fromCookie;
  const auth = req.headers.authorization;
  if (typeof auth === 'string' && auth.startsWith('Bearer ')) {
    const token = auth.slice('Bearer '.length).trim();
    if (token.length >= 20 && token.length <= 200) return token;
  }
  return undefined;
}

/**
 * True when the request Origin is one of `ADMIN_ORIGINS`. Cookie mutations require this, on top of SameSite=Lax.
 * @param ctx - Access app context
 * @param req - Incoming request
 */
export function originAllowed(ctx: AppCtx, req: FastifyRequest): boolean {
  const origin = req.headers.origin;
  return typeof origin === 'string' && ctx.config.adminOrigins.includes(origin);
}

/**
 * Fastify preHandler. Loads the session cookie and refuses the request unless the role is listed.
 * POST, PUT, PATCH, and DELETE also require an Origin in `ADMIN_ORIGINS`.
 *
 * @param ctx - Access app context
 * @param roles - Roles allowed to pass
 * @returns A preHandler that sets `req.actor` or sends 401 or 403
 */
export function requireRole(ctx: AppCtx, ...roles: ActorRole[]) {
  return async (req: FastifyRequest, reply: FastifyReply) => {
    if (!SAFE_METHODS.has(req.method) && !originAllowed(ctx, req)) {
      return reply.code(403).send({ error: 'bad_origin' });
    }
    const actor = await resolveSessionActor(ctx.db, readSessionToken(req, ctx.config.cookieSecure));
    if (!actor) return reply.code(401).send({ error: 'unauthenticated' });
    if (!roles.includes(actor.role)) return reply.code(403).send({ error: 'forbidden' });
    req.actor = actor;
  };
}

/**
 * Resolves `x-hp-key`.
 * A public key is for the browser and must send an Origin on that key's allow-list.
 * A secret key is for the tenant server. An Origin header means the key leaked into a browser, so the call is refused.
 *
 * @param ctx - Access app context
 * @param req - Incoming request
 * @param reply - Used to send 401 or 403. The caller should return when this function returns null.
 * @param allowed - Key kinds this route accepts
 * @returns The tenant and key kind, or null after the error response has been sent
 */
export async function resolveApiKey(
  ctx: AppCtx,
  req: FastifyRequest,
  reply: FastifyReply,
  allowed: ApiKeyKind[],
): Promise<ResolvedKey | null> {
  const raw = req.headers['x-hp-key'];
  const kind = typeof raw === 'string' ? apiKeyKind(raw) : null;
  if (typeof raw !== 'string' || !kind || !allowed.includes(kind)) {
    await reply.code(401).send({ error: 'invalid_key' });
    return null;
  }
  const row = (
    await ctx.db.withoutTenant((q) =>
      q.query<{ tenant_id: string; site_id: string; kind: ApiKeyKind; allowed_origins: string[] }>(
        'SELECT * FROM platform.resolve_api_key($1)',
        [hashApiKey(raw)],
      ),
    )
  ).rows[0];
  if (!row) {
    await reply.code(401).send({ error: 'invalid_key' });
    return null;
  }
  const origin = req.headers.origin;
  if (row.kind === 'public') {
    if (typeof origin !== 'string' || !row.allowed_origins.includes(origin)) {
      await reply.code(403).send({ error: 'origin_not_allowed' });
      return null;
    }
    reply.header('access-control-allow-origin', origin);
    reply.header('vary', 'origin');
  } else if (origin !== undefined) {
    await reply.code(403).send({ error: 'secret_key_used_from_browser' });
    return null;
  }
  const key: ResolvedKey = { tenantId: row.tenant_id, siteId: row.site_id, kind: row.kind, allowedOrigins: row.allowed_origins };
  req.apiKey = key;
  return key;
}

/**
 * Appends one audit row in the caller's transaction. The table rejects update and delete.
 * @param q - Transaction already scoped to the actor's tenant
 * @param actor - Staff session that performed the action
 * @param action - Stable name such as `content.create`
 * @param target - Id of the row that changed, or null
 * @param details - Extra JSON stored with the row
 */
export async function audit(q: Queryable, actor: SessionActor, action: string, target: string | null, details?: unknown): Promise<void> {
  await q.query(
    'INSERT INTO platform.audit_log (tenant_id, actor_user_id, actor_role, action, target, details) VALUES ($1, $2, $3, $4, $5, $6)',
    [actor.tenantId, actor.userId, actor.role, action, target, details === undefined ? null : JSON.stringify(details)],
  );
}

/** Postgres `code` from a driver error, or undefined when the throw was not a database error. */
export const pgCode = (err: unknown): string | undefined => (err as { code?: string } | null)?.code;
