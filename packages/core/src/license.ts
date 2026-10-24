import { generateKeyPairSync, sign, verify, createPublicKey, createPrivateKey } from 'node:crypto';
import { b64u, fromB64u } from './crypto.js';

// ---------------------------------------------------------------------------
// Licence keys for the self-install edition.
//
// A licence is a signed statement: "customer X may run product Y, plan Z, on up
// to N sites until date D". You sign it with a private key that never leaves your
// machine; every installation embeds only the PUBLIC key and verifies offline.
//
// Be realistic about enforcement: anyone who has the source can remove the
// check. The licence gives honest customers a clear entitlement, lets you expire
// and revoke (via the optional phone-home), and gives your terms of use something
// concrete to point at. It is not copy protection.
// ---------------------------------------------------------------------------

export interface LicensePayload {
  v: 1;
  lid: string; // licence id, also stored in platform.licenses so it can be revoked
  customer: string;
  product: 'access' | 'payments' | 'bundle';
  plan: string;
  features: string[];
  maxSites: number;
  issuedAt: number; // unix seconds
  expiresAt: number; // unix seconds
}

/**
 * Creates an Ed25519 key pair for self-install licences. Keep the private key off every customer machine.
 * @returns PEM public and private keys
 */
export function generateLicenseKeypair(): { publicKeyPem: string; privateKeyPem: string } {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return {
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
  };
}

/**
 * Signs a licence. Format: `HP1.<payload>.<signature>`.
 * @param privateKeyPem - Ed25519 private key from `generateLicenseKeypair`
 * @param payload - Customer, product, plan, site limit, and expiry
 */
export function signLicense(privateKeyPem: string, payload: LicensePayload): string {
  const body = b64u(Buffer.from(JSON.stringify(payload)));
  const sig = sign(null, Buffer.from(`HP1.${body}`), createPrivateKey(privateKeyPem));
  return `HP1.${body}.${b64u(sig)}`;
}

export type LicenseCheck =
  | { ok: true; payload: LicensePayload }
  | { ok: false; reason: 'malformed' | 'bad_signature' | 'expired' | 'revoked' | 'wrong_product' };

/**
 * Checks a licence offline against the embedded public key.
 * @param publicKeyPem - Ed25519 public key shipped with the install
 * @param token - `HP1.` licence string
 * @param opts.nowSec - Clock for expiry
 * @param opts.product - When set, a licence for a different product fails
 * @param opts.revokedIds - Licence ids that must no longer pass
 */
export function verifyLicense(
  publicKeyPem: string,
  token: string,
  opts: { nowSec?: number; product?: LicensePayload['product']; revokedIds?: ReadonlySet<string> } = {},
): LicenseCheck {
  const parts = token.split('.');
  if (parts.length !== 3 || parts[0] !== 'HP1') return { ok: false, reason: 'malformed' };
  const [, body, sig] = parts as [string, string, string];

  let valid = false;
  try {
    valid = verify(null, Buffer.from(`HP1.${body}`), createPublicKey(publicKeyPem), fromB64u(sig));
  } catch {
    return { ok: false, reason: 'malformed' };
  }
  if (!valid) return { ok: false, reason: 'bad_signature' };

  let payload: LicensePayload;
  try {
    payload = JSON.parse(fromB64u(body).toString('utf8')) as LicensePayload;
  } catch {
    return { ok: false, reason: 'malformed' };
  }
  if (payload.v !== 1) return { ok: false, reason: 'malformed' };

  const now = opts.nowSec ?? Math.floor(Date.now() / 1000);
  if (payload.expiresAt <= now) return { ok: false, reason: 'expired' };
  if (opts.revokedIds?.has(payload.lid)) return { ok: false, reason: 'revoked' };
  if (opts.product && payload.product !== opts.product && payload.product !== 'bundle') {
    return { ok: false, reason: 'wrong_product' };
  }
  return { ok: true, payload };
}
