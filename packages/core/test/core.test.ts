import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  apiKeyKind,
  base32Decode,
  base32Encode,
  decryptField,
  encryptField,
  generateApiKey,
  generateLicenseKeypair,
  hashApiKey,
  hashPassword,
  MemoryNonceStore,
  needsReencrypt,
  parseKeyring,
  passwordNeedsRehash,
  signLicense,
  signRequest,
  signToken,
  totpAt,
  verifyLicense,
  verifyPassword,
  verifyRequest,
  verifyToken,
  verifyTotp,
  type LicensePayload,
  type SigningKeys,
} from '../src/index.js';

// ---------------------------------------------------------------- passwords

test('password hash verifies and rejects wrong passwords', async () => {
  const h = await hashPassword('correct horse battery staple');
  assert.ok(h.startsWith('scrypt$'));
  assert.equal(await verifyPassword('correct horse battery staple', h), true);
  assert.equal(await verifyPassword('wrong', h), false);
  assert.equal(passwordNeedsRehash(h), false);
});

test('password verify rejects garbage stored values without throwing', async () => {
  assert.equal(await verifyPassword('x', 'nonsense'), false);
  assert.equal(await verifyPassword('x', 'scrypt$1$1$1$aa$bb'), false);
});

// --------------------------------------------------------- field encryption

const ring = (id: string, byte: number) => ({
  current: id,
  keys: { [id]: Buffer.alloc(32, byte) },
});

test('field encryption round-trips and binds to context', () => {
  const kr = ring('k1', 1);
  const token = encryptField('iban: LB00 1234', kr, 'partner:abc:payout');
  assert.equal(decryptField(token, kr, 'partner:abc:payout'), 'iban: LB00 1234');
  assert.throws(() => decryptField(token, kr, 'partner:OTHER:payout'));
});

test('field encryption detects tampering and supports key rotation', () => {
  const old = ring('k1', 1);
  const token = encryptField('secret', old, 'ctx');
  const parts = token.split('.');
  parts[4] = Buffer.from('tampered').toString('base64url');
  assert.throws(() => decryptField(parts.join('.'), old, 'ctx'));

  const rotated = { current: 'k2', keys: { k1: Buffer.alloc(32, 1), k2: Buffer.alloc(32, 2) } };
  assert.equal(decryptField(token, rotated, 'ctx'), 'secret');
  assert.equal(needsReencrypt(token, rotated), true);
  assert.equal(needsReencrypt(encryptField('x', rotated, 'ctx'), rotated), false);
});

test('parseKeyring validates key length', () => {
  const good = JSON.stringify({ current: 'k1', keys: { k1: Buffer.alloc(32, 7).toString('base64') } });
  assert.equal(parseKeyring(good).current, 'k1');
  const bad = JSON.stringify({ current: 'k1', keys: { k1: Buffer.alloc(16).toString('base64') } });
  assert.throws(() => parseKeyring(bad));
});

// ----------------------------------------------------------------- api keys

test('api keys are typed, hashed and distinguishable', () => {
  const pk = generateApiKey('public');
  const sk = generateApiKey('secret');
  assert.equal(apiKeyKind(pk.key), 'public');
  assert.equal(apiKeyKind(sk.key), 'secret');
  assert.equal(apiKeyKind('hp_pk_zzzz_short'), null);
  assert.equal(pk.hash, hashApiKey(pk.key));
  assert.notEqual(pk.hash, sk.hash);
});

// -------------------------------------------------------------------- totp

test('TOTP matches RFC 6238 test vectors (SHA1, 8 digits)', () => {
  const secret = base32Encode(Buffer.from('12345678901234567890'));
  assert.equal(secret, 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
  assert.equal(totpAt(secret, 59_000, 8), '94287082');
  assert.equal(totpAt(secret, 1_111_111_109_000, 8), '07081804');
  assert.equal(totpAt(secret, 1_234_567_890_000, 8), '89005924');
  assert.equal(totpAt(secret, 2_000_000_000_000, 8), '69279037');
});

test('base32 round-trips', () => {
  const buf = Buffer.from('hello world, this is a test');
  assert.deepEqual(base32Decode(base32Encode(buf)), buf);
});

test('TOTP verify accepts neighbours, rejects replays and wrong codes', () => {
  const secret = base32Encode(Buffer.from('12345678901234567890'));
  const now = 1_700_000_000_000;
  const code = totpAt(secret, now);
  const step = verifyTotp(secret, code, { nowMs: now });
  assert.notEqual(step, null);
  assert.equal(verifyTotp(secret, totpAt(secret, now - 30_000), { nowMs: now }) !== null, true);
  assert.equal(verifyTotp(secret, code, { nowMs: now, lastStep: step }), null, 'replay must be rejected');
  assert.equal(verifyTotp(secret, '000000', { nowMs: now }), null);
  assert.equal(verifyTotp(secret, 'abcdef', { nowMs: now }), null);
});

// ----------------------------------------------------------------- signing

const keys: SigningKeys = { current: 'k1', keys: { k1: 'a'.repeat(40) } };
const base = { keys, method: 'POST', path: '/internal/events', body: '{"x":1}' };

test('signed request verifies once, then rejects replay', async () => {
  const store = new MemoryNonceStore();
  const header = signRequest(base);
  assert.deepEqual(await verifyRequest({ ...base, header, nonceStore: store }), { ok: true, kid: 'k1' });
  const again = await verifyRequest({ ...base, header, nonceStore: store });
  assert.deepEqual(again, { ok: false, reason: 'replayed' });
});

test('signed request rejects tampering, wrong path, stale time and unknown key', async () => {
  const store = new MemoryNonceStore();
  const header = signRequest(base);
  assert.equal((await verifyRequest({ ...base, body: '{"x":2}', header, nonceStore: store })).ok, false);
  assert.equal((await verifyRequest({ ...base, path: '/internal/other', header, nonceStore: store })).ok, false);
  const old = signRequest({ ...base, nowMs: Date.now() - 10 * 60_000 });
  assert.deepEqual(await verifyRequest({ ...base, header: old, nonceStore: store }), { ok: false, reason: 'stale_timestamp' });
  const other = signRequest({ ...base, keys: { current: 'zz', keys: { zz: 'b'.repeat(40) } } });
  assert.deepEqual(await verifyRequest({ ...base, header: other, nonceStore: store }), { ok: false, reason: 'unknown_key' });
  assert.deepEqual(await verifyRequest({ ...base, header: undefined, nonceStore: store }), { ok: false, reason: 'missing_signature' });
});

test('signing key rotation: old key still verifies while it is in the ring', async () => {
  const oldHeader = signRequest(base);
  const rotated: SigningKeys = { current: 'k2', keys: { k1: 'a'.repeat(40), k2: 'c'.repeat(40) } };
  const res = await verifyRequest({ ...base, keys: rotated, header: oldHeader, nonceStore: new MemoryNonceStore() });
  assert.deepEqual(res, { ok: true, kid: 'k1' });
});

test('signed tokens verify, expire and resist tampering', () => {
  const now = 1_700_000_000_000;
  const token = signToken({ t: 'tenant', c: 'content' }, keys, 60, now);
  assert.deepEqual(verifyToken(token, keys, now + 1000)?.c, 'content');
  assert.equal(verifyToken(token, keys, now + 61_000), null, 'expired');
  const parts = token.split('.');
  parts[2] = Buffer.from(JSON.stringify({ t: 'other', c: 'content', exp: 9_999_999_999 })).toString('base64url');
  assert.equal(verifyToken(parts.join('.'), keys, now), null, 'tampered payload');
});

// ----------------------------------------------------------------- licence

const payload = (over: Partial<LicensePayload> = {}): LicensePayload => ({
  v: 1,
  lid: 'lic_001',
  customer: 'Acme Media',
  product: 'access',
  plan: 'self-install',
  features: ['partners', 'keywords'],
  maxSites: 3,
  issuedAt: 1_700_000_000,
  expiresAt: 1_800_000_000,
  ...over,
});

test('licence verifies, and fails on expiry, tampering, revocation and wrong key', () => {
  const kp = generateLicenseKeypair();
  const token = signLicense(kp.privateKeyPem, payload());
  const ok = verifyLicense(kp.publicKeyPem, token, { nowSec: 1_750_000_000 });
  assert.equal(ok.ok, true);

  assert.deepEqual(verifyLicense(kp.publicKeyPem, token, { nowSec: 1_900_000_000 }), { ok: false, reason: 'expired' });
  assert.deepEqual(
    verifyLicense(kp.publicKeyPem, token, { nowSec: 1_750_000_000, revokedIds: new Set(['lic_001']) }),
    { ok: false, reason: 'revoked' },
  );
  assert.deepEqual(verifyLicense(kp.publicKeyPem, token, { nowSec: 1_750_000_000, product: 'payments' }), {
    ok: false,
    reason: 'wrong_product',
  });

  const parts = token.split('.');
  parts[1] = Buffer.from(JSON.stringify(payload({ maxSites: 9999 }))).toString('base64url');
  assert.deepEqual(verifyLicense(kp.publicKeyPem, parts.join('.'), { nowSec: 1_750_000_000 }), {
    ok: false,
    reason: 'bad_signature',
  });

  const other = generateLicenseKeypair();
  assert.deepEqual(verifyLicense(other.publicKeyPem, token, { nowSec: 1_750_000_000 }), { ok: false, reason: 'bad_signature' });
  assert.deepEqual(verifyLicense(kp.publicKeyPem, 'junk'), { ok: false, reason: 'malformed' });
});

test('a bundle licence satisfies a single-product check', () => {
  const kp = generateLicenseKeypair();
  const token = signLicense(kp.privateKeyPem, payload({ product: 'bundle' }));
  assert.equal(verifyLicense(kp.publicKeyPem, token, { nowSec: 1_750_000_000, product: 'payments' }).ok, true);
});
