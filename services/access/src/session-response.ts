import type { FastifyReply, FastifyRequest } from 'fastify';
import { cookieName } from '@hardport/core';
import type { AccessConfig } from './config.js';

/** When set by the BFF, return the raw session token in JSON instead of Set-Cookie. */
export function wantsSessionBody(req: FastifyRequest): boolean {
  const mode = req.headers['x-hp-session-mode'];
  return mode === 'body' || mode === 'bff';
}

export function issueSessionCookie(
  reply: FastifyReply,
  config: AccessConfig,
  token: string,
  ttlHours: number,
): void {
  reply.setCookie(cookieName(config.cookieSecure), token, {
    httpOnly: true,
    secure: config.cookieSecure,
    sameSite: 'lax',
    path: '/',
    maxAge: ttlHours * 3600,
  });
}

export function sessionPayload(
  req: FastifyRequest,
  reply: FastifyReply,
  config: AccessConfig,
  token: string,
  ttlHours: number,
  meta: { tenant: string; role: string },
) {
  if (wantsSessionBody(req)) {
    return {
      ok: true as const,
      sessionToken: token,
      expiresInSeconds: ttlHours * 3600,
      tenant: meta.tenant,
      role: meta.role,
    };
  }
  issueSessionCookie(reply, config, token, ttlHours);
  return { ok: true as const, tenant: meta.tenant, role: meta.role };
}
