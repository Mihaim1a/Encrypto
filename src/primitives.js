/**
 * Thin wrappers around the Web Crypto API (crypto.subtle).
 *
 * All the real cryptography is done by the platform's native, audited implementation:
 *   X25519 (key agreement), Ed25519 (signatures), HKDF-SHA-256, HMAC-SHA-256, AES-256-GCM.
 * Keys are passed around as raw bytes so that session state can be serialized and stored.
 */
import { concatBytes, fromBase64Url, utf8ToBytes } from './encoding.js';

/**
 * Domain-separation prefix for every key derivation and signature in the protocol.
 * Changing it makes all existing keys, sessions and contact codes incompatible.
 */
export const PROTOCOL = 'E2EMessenger-v1';

const webcrypto = globalThis.crypto;
if (!webcrypto?.subtle || typeof webcrypto.getRandomValues !== 'function') {
  throw new Error(
    'The Web Crypto API (crypto.subtle) is not available. Use Node.js 20+, a current browser, ' +
      'or provide a WebCrypto implementation with X25519 and Ed25519 support.',
  );
}
const subtle = webcrypto.subtle;

/** Thrown when a message or attachment fails authentication or cannot be decrypted. */
export class DecryptionError extends Error {
  constructor(message) {
    super(message);
    this.name = 'DecryptionError';
  }
}

/** Builds a domain-separation label such as "E2EMessenger-v1/x3dh". */
export function label(name) {
  return utf8ToBytes(`${PROTOCOL}/${name}`);
}

export const ZERO_SALT = new Uint8Array(32);

export function randomBytes(length) {
  return webcrypto.getRandomValues(new Uint8Array(length));
}

function assertBytes(value, length, what) {
  if (!(value instanceof Uint8Array) || value.length !== length) {
    throw new TypeError(`${what} must be a ${length}-byte Uint8Array`);
  }
}

// ---------------------------------------------------------------------------
// Hashes and key derivation
// ---------------------------------------------------------------------------

export async function sha256(data) {
  return new Uint8Array(await subtle.digest('SHA-256', data));
}

export async function hmacSha256(key, data) {
  const cryptoKey = await subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await subtle.sign('HMAC', cryptoKey, data));
}

export async function hkdf(inputKeyMaterial, salt, info, length) {
  const cryptoKey = await subtle.importKey('raw', inputKeyMaterial, 'HKDF', false, ['deriveBits']);
  const bits = await subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, cryptoKey, length * 8);
  return new Uint8Array(bits);
}

// ---------------------------------------------------------------------------
// Curve25519 (X25519 key agreement, Ed25519 signatures)
// ---------------------------------------------------------------------------

// Fixed PKCS#8 headers for 32-byte Curve25519 private keys (RFC 8410).
const PKCS8_PREFIX = {
  X25519: Uint8Array.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20]),
  Ed25519: Uint8Array.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20]),
};

function importPrivateKey(algorithm, privateKey, usages, extractable = false) {
  assertBytes(privateKey, 32, `${algorithm} private key`);
  const pkcs8 = concatBytes(PKCS8_PREFIX[algorithm], privateKey);
  return subtle.importKey('pkcs8', pkcs8, { name: algorithm }, extractable, usages);
}

async function keyPairFromSeed(algorithm, seed, usages) {
  const key = await importPrivateKey(algorithm, seed, usages, true);
  const jwk = await subtle.exportKey('jwk', key);
  return { publicKey: fromBase64Url(jwk.x), privateKey: seed.slice() };
}

/** Deterministically creates an X25519 key pair from 32 secret bytes. */
export function x25519KeyPairFromSeed(seed) {
  return keyPairFromSeed('X25519', seed, ['deriveBits']);
}

/** Deterministically creates an Ed25519 key pair from 32 secret bytes. */
export function ed25519KeyPairFromSeed(seed) {
  return keyPairFromSeed('Ed25519', seed, ['sign']);
}

export function generateX25519KeyPair() {
  return x25519KeyPairFromSeed(randomBytes(32));
}

/** X25519 Diffie-Hellman. Returns the 32-byte shared secret. */
export async function x25519(privateKey, publicKey) {
  assertBytes(publicKey, 32, 'X25519 public key');
  const ourKey = await importPrivateKey('X25519', privateKey, ['deriveBits']);
  const theirKey = await subtle.importKey('raw', publicKey, { name: 'X25519' }, false, []);
  const shared = new Uint8Array(await subtle.deriveBits({ name: 'X25519', public: theirKey }, ourKey, 256));
  // Reject low-order points (an all-zero result), in case the platform does not already.
  if (shared.every((byte) => byte === 0)) throw new DecryptionError('Invalid public key');
  return shared;
}

export async function ed25519Sign(privateKey, message) {
  const key = await importPrivateKey('Ed25519', privateKey, ['sign']);
  return new Uint8Array(await subtle.sign({ name: 'Ed25519' }, key, message));
}

export async function ed25519Verify(publicKey, message, signature) {
  if (!(publicKey instanceof Uint8Array) || publicKey.length !== 32) return false;
  if (!(signature instanceof Uint8Array) || signature.length !== 64) return false;
  try {
    const key = await subtle.importKey('raw', publicKey, { name: 'Ed25519' }, false, ['verify']);
    return await subtle.verify({ name: 'Ed25519' }, key, signature, message);
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// AES-256-GCM
// ---------------------------------------------------------------------------

const IV_LENGTH = 12;
const TAG_LENGTH = 16;

/**
 * AES-256-GCM with a fresh random 96-bit IV, returned as `iv || ciphertext || tag`.
 * The IV is generated here, never by callers, so it cannot be reused by mistake.
 */
export async function aesGcmEncrypt(key, plaintext, associatedData) {
  assertBytes(key, 32, 'AES-256 key');
  const iv = randomBytes(IV_LENGTH);
  const cryptoKey = await subtle.importKey('raw', key, { name: 'AES-GCM' }, false, ['encrypt']);
  const params = { name: 'AES-GCM', iv, tagLength: TAG_LENGTH * 8 };
  if (associatedData) params.additionalData = associatedData;
  const ciphertext = new Uint8Array(await subtle.encrypt(params, cryptoKey, plaintext));
  return concatBytes(iv, ciphertext);
}

/** Reverses aesGcmEncrypt. Throws DecryptionError if the data or associated data was altered. */
export async function aesGcmDecrypt(key, data, associatedData) {
  assertBytes(key, 32, 'AES-256 key');
  if (!(data instanceof Uint8Array) || data.length < IV_LENGTH + TAG_LENGTH) {
    throw new DecryptionError('Ciphertext is too short');
  }
  const cryptoKey = await subtle.importKey('raw', key, { name: 'AES-GCM' }, false, ['decrypt']);
  const params = { name: 'AES-GCM', iv: data.subarray(0, IV_LENGTH), tagLength: TAG_LENGTH * 8 };
  if (associatedData) params.additionalData = associatedData;
  try {
    return new Uint8Array(await subtle.decrypt(params, cryptoKey, data.subarray(IV_LENGTH)));
  } catch {
    throw new DecryptionError('Message authentication failed');
  }
}
