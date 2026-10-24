import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  randomBytes,
  scrypt as scryptCb,
  timingSafeEqual,
} from 'node:crypto';

// ---------------------------------------------------------------------------
// Small primitives
// ---------------------------------------------------------------------------

/** Base64url without padding. */
export const b64u = (b: Buffer): string => b.toString('base64url');
/** Inverse of `b64u`. */
export const fromB64u = (s: string): Buffer => Buffer.from(s, 'base64url');
/** SHA-256 hex digest of a string or buffer. */
export const sha256Hex = (s: string | Buffer): string => createHash('sha256').update(s).digest('hex');
/** HMAC-SHA256 hex digest. */
export const hmacHex = (secret: string | Buffer, data: string | Buffer): string =>
  createHmac('sha256', secret).update(data).digest('hex');
/** URL-safe random token. Default is 32 bytes. */
export const randomToken = (bytes = 32): string => randomBytes(bytes).toString('base64url');

/**
 * Constant-time comparison. A length mismatch returns false and does not throw.
 * @param a - First value, usually a computed MAC
 * @param b - Second value, usually the MAC from the request
 */
export function safeEqual(a: string | Buffer, b: string | Buffer): boolean {
  const ab = Buffer.isBuffer(a) ? a : Buffer.from(a);
  const bb = Buffer.isBuffer(b) ? b : Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

/**
 * Keyed hash for values we compare but never store raw, such as login emails and IP addresses.
 * The pepper lives in the environment, so a leaked database alone cannot be reversed by brute force.
 * @param value - Raw email or IP
 * @param pepper - `IP_PEPPER` from the environment
 * @returns First 32 hex characters of HMAC-SHA256
 */
export function pepperedHash(value: string, pepper: string): string {
  return hmacHex(pepper, value).slice(0, 32);
}

// ---------------------------------------------------------------------------
// Passwords (scrypt, built into Node, no native build step)
// Swap for argon2id (@node-rs/argon2) if you prefer; the stored format is
// self-describing so both can coexist during a migration.
// ---------------------------------------------------------------------------

const SCRYPT = { N: 2 ** 15, r: 8, p: 1, keylen: 32 } as const;

/**
 * scrypt as a promise. The password is normalized to NFKC before hashing.
 * @param password - User password
 * @param salt - Per-hash salt
 * @param keylen - Derived key length in bytes
 * @param N - CPU/memory cost
 * @param r - Block size
 * @param p - Parallelism
 */
function scryptAsync(password: string, salt: Buffer, keylen: number, N: number, r: number, p: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scryptCb(password.normalize('NFKC'), salt, keylen, { N, r, p, maxmem: 128 * N * r * 2 }, (err, key) =>
      err ? reject(err) : resolve(key),
    );
  });
}

/**
 * Hashes a password with scrypt (N=2^15). Stored form: `scrypt$N$r$p$salt$key`.
 * @param password - Plain password. It is not stored.
 */
export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16);
  const key = await scryptAsync(password, salt, SCRYPT.keylen, SCRYPT.N, SCRYPT.r, SCRYPT.p);
  return ['scrypt', SCRYPT.N, SCRYPT.r, SCRYPT.p, b64u(salt), b64u(key)].join('$');
}

/**
 * Checks a password against a `hashPassword` string. A malformed stored value returns false.
 * @param password - Plain password from the login form
 * @param stored - Value from `platform.users.password_hash`
 */
export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const parts = stored.split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;
  const N = Number(parts[1]);
  const r = Number(parts[2]);
  const p = Number(parts[3]);
  if (![N, r, p].every(Number.isInteger) || N < 2 ** 14 || N > 2 ** 20 || r < 1 || r > 16 || p < 1 || p > 4) return false;
  const salt = fromB64u(parts[4] ?? '');
  const expected = fromB64u(parts[5] ?? '');
  if (salt.length < 8 || expected.length < 16) return false;
  const actual = await scryptAsync(password, salt, expected.length, N, r, p);
  return timingSafeEqual(actual, expected);
}

/**
 * True when the stored hash uses a cheaper scrypt cost than the current parameters.
 * @param stored - Value from `hashPassword`
 */
export function passwordNeedsRehash(stored: string): boolean {
  const parts = stored.split('$');
  return !(parts[0] === 'scrypt' && Number(parts[1]) >= SCRYPT.N && Number(parts[2]) >= SCRYPT.r);
}

let dummyHash: Promise<string> | undefined;
/**
 * Spends the same time as a real password check, so an unknown email is not detectable by timing.
 * Called from `POST /auth/login` when the email does not exist.
 * @param password - Whatever the client sent. It is checked against a dummy hash.
 */
export async function burnPasswordCheck(password: string): Promise<void> {
  dummyHash ??= hashPassword('not-a-real-password-used-for-timing-only');
  await verifyPassword(password, await dummyHash);
}

// ---------------------------------------------------------------------------
// Field encryption (AES-256-GCM) with key rotation and context binding.
// Use for payout details, gateway credentials, 2FA secrets.
// The AAD (e.g. "gw:<tenantId>:cybersource:live") is authenticated, so a
// ciphertext copied into another row or tenant fails to decrypt.
// ---------------------------------------------------------------------------

export interface Keyring {
  current: string;
  keys: Record<string, Buffer>;
}

/**
 * Parses `FIELD_KEYS`. Each key is 32 bytes, base64. `current` must name one of them.
 * @param json - JSON string from the environment
 */
export function parseKeyring(json: string): Keyring {
  const raw = JSON.parse(json) as { current?: string; keys?: Record<string, string> };
  if (!raw.current || !raw.keys || !raw.keys[raw.current]) throw new Error('keyring: "current" key is missing');
  const keys: Record<string, Buffer> = {};
  for (const [id, value] of Object.entries(raw.keys)) {
    if (!/^[A-Za-z0-9_-]{1,32}$/.test(id)) throw new Error(`keyring: invalid key id "${id}"`);
    const buf = Buffer.from(value, 'base64');
    if (buf.length !== 32) throw new Error(`keyring: key "${id}" must be 32 bytes (base64)`);
    keys[id] = buf;
  }
  return { current: raw.current, keys };
}

/**
 * Encrypts a field with AES-256-GCM. `aad` is bound into the ciphertext, so a copy pasted onto another row will not decrypt.
 * @param plaintext - Secret such as gateway credentials or a TOTP seed
 * @param keyring - Current field key and any keys still needed for old rows
 * @param aad - Context string, for example `gw:<tenantId>:cybersource:test`
 */
export function encryptField(plaintext: string, keyring: Keyring, aad: string): string {
  const key = keyring.keys[keyring.current];
  if (!key) throw new Error('keyring: current key missing');
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(aad));
  const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return ['v1', keyring.current, b64u(iv), b64u(cipher.getAuthTag()), b64u(ct)].join('.');
}

/**
 * Decrypts a value from `encryptField`. The same `aad` that encrypted it is required.
 * @param token - `v1.<keyId>.<iv>.<tag>.<ciphertext>`
 * @param keyring - Must still contain the key id stored in the token
 * @param aad - Context string used at encryption time
 */
export function decryptField(token: string, keyring: Keyring, aad: string): string {
  const parts = token.split('.');
  if (parts.length !== 5 || parts[0] !== 'v1') throw new Error('decrypt: unsupported format');
  const key = keyring.keys[parts[1] ?? ''];
  if (!key) throw new Error('decrypt: unknown key id');
  const decipher = createDecipheriv('aes-256-gcm', key, fromB64u(parts[2] ?? ''));
  decipher.setAAD(Buffer.from(aad));
  decipher.setAuthTag(fromB64u(parts[3] ?? ''));
  return Buffer.concat([decipher.update(fromB64u(parts[4] ?? '')), decipher.final()]).toString('utf8');
}

/**
 * True when the value was encrypted with a key that is no longer `current`. Re-encrypt it with `encryptField`.
 * @param token - Stored `v1.` ciphertext
 * @param keyring - Ring whose `current` id is the one new writes use
 */
export function needsReencrypt(token: string, keyring: Keyring): boolean {
  return token.split('.')[1] !== keyring.current;
}

// ---------------------------------------------------------------------------
// API keys: "hp_pk_<prefix>_<secret>" (public) and "hp_sk_..." (secret).
// Only the SHA-256 hash is stored; the key is shown once at creation.
// SHA-256 (not a slow hash) is correct here because the keys are 192-bit random.
// ---------------------------------------------------------------------------

export type ApiKeyKind = 'public' | 'secret';

/** SHA-256 of a full API key. This is the only form stored. */
export const hashApiKey = (key: string): string => sha256Hex(key);

/**
 * Creates a public (`hp_pk_`) or secret (`hp_sk_`) key. Show `key` once. Store `hash`.
 * @param kind - `public` for the browser, `secret` for the tenant server
 */
export function generateApiKey(kind: ApiKeyKind): { key: string; prefix: string; hash: string } {
  const tag = kind === 'public' ? 'pk' : 'sk';
  const prefix = `hp_${tag}_${randomBytes(4).toString('hex')}`;
  const key = `${prefix}_${randomBytes(24).toString('base64url')}`;
  return { key, prefix, hash: hashApiKey(key) };
}

/**
 * Classifies a raw API key from its prefix. Returns null when the shape is wrong.
 * @param key - Full key from `x-hp-key`
 */
export function apiKeyKind(key: string): ApiKeyKind | null {
  if (/^hp_pk_[0-9a-f]{8}_[A-Za-z0-9_-]{32}$/.test(key)) return 'public';
  if (/^hp_sk_[0-9a-f]{8}_[A-Za-z0-9_-]{32}$/.test(key)) return 'secret';
  return null;
}
