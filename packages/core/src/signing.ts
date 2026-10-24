import { b64u, fromB64u, hmacHex, randomToken, safeEqual, sha256Hex } from './crypto.js';

// ---------------------------------------------------------------------------
// Service-to-service request signing (Access <-> Payments).
//
// Every internal call carries:  kid=<key id>,t=<unix seconds>,n=<nonce>,s=<hex hmac>
// The HMAC covers timestamp, nonce, method, path+query and a hash of the body,
// so a captured request cannot be modified, redirected to another path, or
// replayed (timestamp window + nonce store).
// ---------------------------------------------------------------------------

export interface SigningKeys {
  current: string;
  keys: Record<string, string>;
}

/**
 * Parses `INTERNAL_SIGNING_KEYS` or `KEYWORD_KEYS`.
 * Shape: `{ "current": "k1", "keys": { "k1": "<at least 32 chars>" } }`.
 * @param json - JSON string from the environment
 */
export function parseSigningKeys(json: string): SigningKeys {
  const raw = JSON.parse(json) as { current?: string; keys?: Record<string, string> };
  if (!raw.current || !raw.keys || !raw.keys[raw.current]) throw new Error('signing keys: "current" is missing');
  for (const [id, secret] of Object.entries(raw.keys)) {
    if (!/^[A-Za-z0-9_-]{1,32}$/.test(id)) throw new Error(`signing keys: invalid id "${id}"`);
    if (secret.length < 32) throw new Error(`signing keys: secret "${id}" must be at least 32 characters`);
  }
  return { current: raw.current, keys: raw.keys };
}

export interface NonceStore {
  /** Records the nonce. Returns true if it had already been seen. */
  seen(nonce: string, ttlSec: number): Promise<boolean>;
}

/** In-memory store for development and tests. Use Redis or a database table in production. */
export class MemoryNonceStore implements NonceStore {
  private readonly map = new Map<string, number>();
  /**
   * Records `nonce` until `ttlSec` elapses. Returns true when this nonce was already stored.
   * @param nonce - Value from the `n` field of `x-hp-signature`
   * @param ttlSec - How long to remember it. Callers pass the signature skew window.
   */
  async seen(nonce: string, ttlSec: number): Promise<boolean> {
    const now = Date.now();
    for (const [k, exp] of this.map) if (exp <= now) this.map.delete(k);
    if (this.map.has(nonce)) return true;
    this.map.set(nonce, now + ttlSec * 1000);
    return false;
  }
}

/**
 * Canonical string covered by the internal HMAC: time, nonce, method, path, body hash.
 * @param t - Unix seconds
 * @param n - One-time nonce
 * @param method - HTTP method
 * @param path - Path and query, exactly as the receiver will see it
 * @param body - Raw body bytes as a string
 */
function stringToSign(t: number, n: string, method: string, path: string, body: string): string {
  return `${t}\n${n}\n${method.toUpperCase()}\n${path}\n${sha256Hex(body)}`;
}

/**
 * Builds the `x-hp-signature` header for a call between Access, Payments, and a tenant server.
 * Header shape: `kid=<id>,t=<unix>,n=<nonce>,s=<hex hmac>`.
 *
 * @param args.keys - Signing ring. The `current` key is used.
 * @param args.method - HTTP method
 * @param args.path - Path the receiver verifies, with no host
 * @param args.body - Exact JSON string that will be sent
 * @param args.nowMs - Clock, injectable in tests
 * @param args.nonce - Leave unset in production so each call gets a new nonce
 * @returns The header value
 */
export function signRequest(args: {
  keys: SigningKeys;
  method: string;
  path: string;
  body: string;
  nowMs?: number;
  nonce?: string;
}): string {
  const t = Math.floor((args.nowMs ?? Date.now()) / 1000);
  const n = args.nonce ?? randomToken(16);
  const secret = args.keys.keys[args.keys.current];
  if (!secret) throw new Error('signing: current key missing');
  const s = hmacHex(secret, stringToSign(t, n, args.method, args.path, args.body));
  return `kid=${args.keys.current},t=${t},n=${n},s=${s}`;
}

export type VerifyResult = { ok: true; kid: string } | { ok: false; reason: string };

/**
 * Checks `x-hp-signature` against the raw body, method, and path.
 * Rejects a missing header, a bad MAC, a stale timestamp, an unknown key id, and a nonce that was already used.
 *
 * @param args.header - Value of `x-hp-signature`
 * @param args.method - HTTP method of this request
 * @param args.path - Path Fastify saw, including the query string when one is present
 * @param args.body - Raw body, the same bytes that were signed
 * @param args.nonceStore - Remembers nonces for the skew window
 * @param args.maxSkewSec - How far the timestamp may drift. The default lives in the implementation.
 * @returns `{ ok: true, kid }` or `{ ok: false, reason }`
 */
export async function verifyRequest(args: {
  keys: SigningKeys;
  header: string | undefined;
  method: string;
  path: string;
  body: string;
  nonceStore: NonceStore;
  nowMs?: number;
  maxSkewSec?: number;
}): Promise<VerifyResult> {
  if (!args.header) return { ok: false, reason: 'missing_signature' };
  const fields = Object.fromEntries(
    args.header.split(',').map((p) => {
      const i = p.indexOf('=');
      return [p.slice(0, i).trim(), p.slice(i + 1).trim()] as const;
    }),
  );
  const { kid, t, n, s } = fields;
  if (!kid || !t || !n || !s || !/^\d+$/.test(t)) return { ok: false, reason: 'malformed_signature' };
  const secret = args.keys.keys[kid];
  if (!secret) return { ok: false, reason: 'unknown_key' };

  const nowSec = Math.floor((args.nowMs ?? Date.now()) / 1000);
  const maxSkew = args.maxSkewSec ?? 300;
  if (Math.abs(nowSec - Number(t)) > maxSkew) return { ok: false, reason: 'stale_timestamp' };

  const expected = hmacHex(secret, stringToSign(Number(t), n, args.method, args.path, args.body));
  if (!safeEqual(expected, s)) return { ok: false, reason: 'bad_signature' };

  // Only record the nonce after the signature is valid, so attackers cannot fill the store.
  if (await args.nonceStore.seen(`${kid}:${n}`, maxSkew * 2)) return { ok: false, reason: 'replayed' };
  return { ok: true, kid };
}

// ---------------------------------------------------------------------------
// Short-lived signed tokens (e.g. the "keyword session" that unlocks one guide
// for one browser). Format: hpt.<kid>.<payload>.<mac>
// ---------------------------------------------------------------------------

/**
 * Signs a short-lived token such as the keyword session returned to a browser.
 * Format: `hpt.<kid>.<payload>.<mac>`.
 *
 * @param payload - Claims. `exp` is added here.
 * @param keys - Keyword signing ring
 * @param ttlSec - Lifetime in seconds
 * @param nowMs - Clock, injectable in tests
 */
export function signToken(payload: Record<string, unknown>, keys: SigningKeys, ttlSec: number, nowMs = Date.now()): string {
  const secret = keys.keys[keys.current];
  if (!secret) throw new Error('signing: current key missing');
  const body = b64u(Buffer.from(JSON.stringify({ ...payload, exp: Math.floor(nowMs / 1000) + ttlSec })));
  const mac = hmacHex(secret, `hpt.${keys.current}.${body}`);
  return `hpt.${keys.current}.${body}.${mac}`;
}

/**
 * Verifies a token from `signToken`. Returns null for a bad MAC, an unknown key, or an expired token.
 * @param token - `hpt.` token from `x-hp-session` or a similar header
 * @param keys - Ring that signed it. Retired key ids still verify while they remain in `keys`.
 * @param nowMs - Clock used for `exp`
 */
export function verifyToken<T extends Record<string, unknown>>(token: string, keys: SigningKeys, nowMs = Date.now()): T | null {
  const parts = token.split('.');
  if (parts.length !== 4 || parts[0] !== 'hpt') return null;
  const [, kid, body, mac] = parts as [string, string, string, string];
  const secret = keys.keys[kid];
  if (!secret) return null;
  if (!safeEqual(hmacHex(secret, `hpt.${kid}.${body}`), mac)) return null;
  try {
    const payload = JSON.parse(fromB64u(body).toString('utf8')) as T & { exp?: number };
    if (typeof payload.exp !== 'number' || payload.exp * 1000 < nowMs) return null;
    return payload;
  } catch {
    return null;
  }
}
