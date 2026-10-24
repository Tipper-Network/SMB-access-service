import { createHmac, randomBytes } from 'node:crypto';

// RFC 6238 TOTP (HMAC-SHA1, 30 s step) for admin and owner two-factor login.

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/** Encodes bytes as the base32 alphabet TOTP secrets use. */
export function base32Encode(buf: Buffer): string {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

/**
 * Decodes a base32 TOTP secret. Spaces and padding are ignored.
 * @param input - Secret shown to the user, or stored encrypted
 * @throws Error `invalid base32` when a character is outside the alphabet
 */
export function base32Decode(input: string): Buffer {
  const clean = input.replace(/=+$/, '').replace(/\s+/g, '').toUpperCase();
  let bits = 0;
  let value = 0;
  const bytes: number[] = [];
  for (const ch of clean) {
    const idx = ALPHABET.indexOf(ch);
    if (idx === -1) throw new Error('invalid base32');
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

/** New 160-bit TOTP secret, base32. Show it once, then store it encrypted. */
export const generateTotpSecret = (): string => base32Encode(randomBytes(20));

/**
 * HOTP code for one counter value. TOTP calls this with the current time step.
 * @param secret - Raw secret bytes, not the base32 form
 * @param counter - Moving factor
 * @param digits - Code length. Login uses 6.
 */
export function hotp(secret: Buffer, counter: number, digits = 6): string {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const h = createHmac('sha1', secret).update(buf).digest();
  const offset = (h[h.length - 1] ?? 0) & 0x0f;
  const bin =
    (((h[offset] ?? 0) & 0x7f) << 24) |
    (((h[offset + 1] ?? 0) & 0xff) << 16) |
    (((h[offset + 2] ?? 0) & 0xff) << 8) |
    ((h[offset + 3] ?? 0) & 0xff);
  return String(bin % 10 ** digits).padStart(digits, '0');
}

/** Time-step counter. Default step is 30 seconds. */
export const totpStep = (timeMs: number, stepSec = 30): number => Math.floor(timeMs / 1000 / stepSec);

/**
 * TOTP code at one instant. Used by tests and by the enrolment screen.
 * @param secretB32 - Base32 secret
 * @param timeMs - Unix time in milliseconds
 */
export function totpAt(secretB32: string, timeMs: number, digits = 6, stepSec = 30): string {
  return hotp(base32Decode(secretB32), totpStep(timeMs, stepSec), digits);
}

/**
 * Checks a TOTP code within plus or minus `window` steps. Returns the matched step, or null.
 * Pass `lastStep` (stored per user) so a code cannot be reused.
 *
 * @param secretB32 - Base32 secret
 * @param code - Digits from the authenticator
 * @param opts.window - Steps of clock skew to allow. Default is 1.
 * @param opts.lastStep - Highest step already accepted for this user
 * @returns The matched step, which the caller stores as `lastStep`
 */
export function verifyTotp(
  secretB32: string,
  code: string,
  opts: { nowMs?: number; window?: number; lastStep?: number | null; digits?: number } = {},
): number | null {
  const { nowMs = Date.now(), window = 1, lastStep = null, digits = 6 } = opts;
  if (!new RegExp(`^\\d{${digits}}$`).test(code)) return null;
  const secret = base32Decode(secretB32);
  const current = totpStep(nowMs);
  for (let delta = -window; delta <= window; delta++) {
    const step = current + delta;
    if (lastStep !== null && step <= lastStep) continue;
    if (hotp(secret, step, digits) === code) return step;
  }
  return null;
}

/**
 * `otpauth://` URI for a QR code during enrolment.
 * @param secretB32 - Base32 secret
 * @param account - Label, usually the user's email
 * @param issuer - Name shown in the authenticator app
 */
export function otpauthUri(secretB32: string, account: string, issuer: string): string {
  const label = encodeURIComponent(`${issuer}:${account}`);
  return `otpauth://totp/${label}?secret=${secretB32}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
}
