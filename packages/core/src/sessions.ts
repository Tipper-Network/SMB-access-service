import { sha256Hex } from './crypto.js';
import type { Actor, ActorRole, Db } from './db.js';

// Shared by every service: turn a session cookie into an Actor. Only the hash of
// the session token is stored in the database.

/** SHA-256 of the cookie value. The database stores this, not the raw token. */
export const hashSessionToken = (token: string): string => sha256Hex(token);

export interface SessionActor extends Actor {
  userId: string;
  isPlatformAdmin: boolean;
}

/**
 * Turns a session cookie into the actor for this request. Returns null when the cookie is missing, expired, or has no tenant.
 * @param db - Platform database. The lookup goes through `platform.resolve_session`.
 * @param token - Raw cookie value
 */
export async function resolveSessionActor(db: Db, token: string | undefined): Promise<SessionActor | null> {
  if (!token || token.length < 20 || token.length > 200) return null;
  const rows = await db.withoutTenant(async (q) => {
    const res = await q.query<{
      user_id: string;
      tenant_id: string | null;
      role: string;
      partner_id: string | null;
      business_id: string | null;
      is_platform_admin: boolean;
    }>('SELECT * FROM platform.resolve_session($1)', [hashSessionToken(token)]);
    return res.rows;
  });
  const row = rows[0];
  // Platform-admin sessions carry no tenant; they cannot use tenant routes.
  if (!row || !row.tenant_id) return null;
  return {
    tenantId: row.tenant_id,
    role: row.role as ActorRole,
    userId: row.user_id,
    partnerId: row.partner_id,
    businessId: row.business_id,
    isPlatformAdmin: row.is_platform_admin,
  };
}

export const COOKIE_NAME_SECURE = '__Host-hp_session';
export const COOKIE_NAME_DEV = 'hp_session';
/**
 * Cookie name for the staff session. The `__Host-` prefix is used when the cookie is marked Secure.
 * @param secure - True in production (`COOKIE_SECURE=true`)
 */
export const cookieName = (secure: boolean): string => (secure ? COOKIE_NAME_SECURE : COOKIE_NAME_DEV);
