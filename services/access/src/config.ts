import { z } from 'zod';
import { parseKeyring, parseSigningKeys, type Keyring, type SigningKeys } from '@hardport/core';

const Env = z.object({
  DATABASE_URL: z.string().min(1),
  HOST: z.string().default('127.0.0.1'),
  PORT: z.coerce.number().int().default(4001),
  // Origins allowed to use cookie sessions (your admin/partner front-ends). Comma separated.
  ADMIN_ORIGINS: z.string().default(''),
  COOKIE_SECURE: z.enum(['true', 'false']).default('true'),
  TRUST_PROXY: z.enum(['true', 'false']).default('false'),
  // Secrets: provide through your secret manager, never commit them.
  IP_PEPPER: z.string().min(16),
  FIELD_KEYS: z.string().min(1), // {"current":"k1","keys":{"k1":"<base64 32 bytes>"}}
  INTERNAL_SIGNING_KEYS: z.string().min(1), // {"current":"k1","keys":{"k1":"<32+ chars>"}}  (shared with Payments)
  KEYWORD_SESSION_KEYS: z.string().min(1),
  SESSION_TTL_HOURS: z.coerce.number().int().min(1).max(168).default(12),
  DEFAULT_FREE_AFTER_DAYS: z.coerce.number().int().min(0).max(3650).default(30),
  // Per-IP request limit on /auth/login (on top of the per-account lockout in the database).
  LOGIN_RATE_LIMIT_PER_MINUTE: z.coerce.number().int().min(1).max(10_000).default(20),
  RESEND_API_KEY: z.string().optional(),
  MAIL_FROM: z.string().optional(),
  PARTNER_OTP_TTL_MINUTES: z.coerce.number().int().min(5).max(60).default(10),
  PARTNER_SESSION_TTL_HOURS: z.coerce.number().int().min(1).max(24).default(8),
  /** When true, staff login skips TOTP (local dogfood only). */
  ACCESS_SKIP_2FA: z.enum(['true', 'false']).default('false'),
});

export interface AccessConfig {
  host: string;
  port: number;
  adminOrigins: string[];
  cookieSecure: boolean;
  trustProxy: boolean;
  ipPepper: string;
  fieldKeys: Keyring;
  internalKeys: SigningKeys;
  keywordKeys: SigningKeys;
  sessionTtlHours: number;
  defaultFreeAfterDays: number;
  loginRateLimitPerMinute: number;
  resendApiKey: string | undefined;
  mailFrom: string | undefined;
  partnerOtpTtlMinutes: number;
  partnerSessionTtlHours: number;
  skip2fa: boolean;
}

/**
 * Reads Access environment variables and refuses to start when one is missing or malformed.
 * @param env - Defaults to `process.env`
 */
export function loadConfig(env: Record<string, string | undefined> = process.env): AccessConfig {
  const e = Env.parse(env);
  return {
    host: e.HOST,
    port: e.PORT,
    adminOrigins: e.ADMIN_ORIGINS.split(',').map((s) => s.trim()).filter(Boolean),
    cookieSecure: e.COOKIE_SECURE === 'true',
    trustProxy: e.TRUST_PROXY === 'true',
    ipPepper: e.IP_PEPPER,
    fieldKeys: parseKeyring(e.FIELD_KEYS),
    internalKeys: parseSigningKeys(e.INTERNAL_SIGNING_KEYS),
    keywordKeys: parseSigningKeys(e.KEYWORD_SESSION_KEYS),
    sessionTtlHours: e.SESSION_TTL_HOURS,
    defaultFreeAfterDays: e.DEFAULT_FREE_AFTER_DAYS,
    loginRateLimitPerMinute: e.LOGIN_RATE_LIMIT_PER_MINUTE,
    resendApiKey: e.RESEND_API_KEY?.trim() || undefined,
    mailFrom: e.MAIL_FROM?.trim() || undefined,
    partnerOtpTtlMinutes: e.PARTNER_OTP_TTL_MINUTES,
    partnerSessionTtlHours: e.PARTNER_SESSION_TTL_HOURS,
    skip2fa: e.ACCESS_SKIP_2FA === 'true',
  };
}
