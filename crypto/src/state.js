/**
 * Saving the account on the device.
 *
 * - The exported state is always encrypted (AES-256-GCM) with a 256-bit storage key. The app
 *   generates that key once with Account.generateStorageKey() and keeps it in the platform's
 *   secure key store (iOS Keychain, Android Keystore, ...). The encrypted blob itself can then
 *   live in an ordinary file or database.
 * - Everything read back is validated field by field before it is used, so corrupted or
 *   mismatched data fails loudly with InvalidStateError instead of causing subtle bugs.
 */
import { bytesToUtf8, concatBytes, fromBase64, toBase64, utf8ToBytes } from './encoding.js';
import { DecryptionError, aesGcmDecrypt, aesGcmEncrypt, label, randomBytes } from './primitives.js';

const BLOB_FORMAT = 1;

/** Thrown when saved state cannot be decrypted or does not pass validation. */
export class InvalidStateError extends Error {
  constructor(message) {
    super(message);
    this.name = 'InvalidStateError';
  }
}

/** Thrown when auto-save fails. The operation that triggered it was undone. */
export class PersistenceError extends Error {
  constructor(message, options) {
    super(message, options);
    this.name = 'PersistenceError';
  }
}

export function generateStorageKey() {
  return toBase64(randomBytes(32));
}

export function parseStorageKey(storageKey) {
  try {
    return fromBase64(storageKey, 32);
  } catch {
    throw new TypeError('The storage key must be 32 bytes in base64. Create one with Account.generateStorageKey().');
  }
}

function blobAssociatedData(format) {
  return concatBytes(label('account-state'), Uint8Array.of(format));
}

/** Encrypts a state snapshot. Returns a base64 string. */
export async function sealState(snapshot, storageKey) {
  const key = parseStorageKey(storageKey);
  try {
    const ciphertext = await aesGcmEncrypt(key, utf8ToBytes(JSON.stringify(snapshot)), blobAssociatedData(BLOB_FORMAT));
    return toBase64(concatBytes(Uint8Array.of(BLOB_FORMAT), ciphertext));
  } finally {
    key.fill(0);
  }
}

/** Decrypts a blob from sealState. Throws InvalidStateError for a wrong key or altered data. */
export async function openState(blob, storageKey) {
  const key = parseStorageKey(storageKey);
  try {
    let bytes;
    try {
      bytes = fromBase64(blob);
    } catch {
      throw new InvalidStateError('Saved state is not valid base64');
    }
    if (bytes.length === 0 || bytes[0] !== BLOB_FORMAT) throw new InvalidStateError('Unknown saved state format');
    let json;
    try {
      json = await aesGcmDecrypt(key, bytes.subarray(1), blobAssociatedData(bytes[0]));
    } catch (error) {
      if (error instanceof DecryptionError) {
        throw new InvalidStateError('Saved state could not be decrypted: wrong storage key, or the data was altered');
      }
      throw error;
    }
    try {
      return JSON.parse(bytesToUtf8(json));
    } catch {
      throw new InvalidStateError('Saved state is not valid JSON');
    }
  } finally {
    key.fill(0);
  }
}

// ---------------------------------------------------------------------------
// Validation helpers for reading state back
// ---------------------------------------------------------------------------

export function invalidState(path, problem) {
  throw new InvalidStateError(`Saved state is invalid at ${path}: ${problem}`);
}

export function expectObject(value, path) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) invalidState(path, 'expected an object');
  return value;
}

export function expectArray(value, path, maxLength = Infinity) {
  if (!Array.isArray(value)) invalidState(path, 'expected an array');
  if (value.length > maxLength) invalidState(path, `more than ${maxLength} entries`);
  return value;
}

export function expectInt(value, path, min = 0, max = 0xffffffff) {
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    invalidState(path, `expected an integer from ${min} to ${max}`);
  }
  return value;
}

export function expectBytes(value, path, length) {
  if (typeof value !== 'string') invalidState(path, 'expected base64 data');
  try {
    return fromBase64(value, length);
  } catch (error) {
    return invalidState(path, error.message);
  }
}

export function expectNullableBytes(value, path, length) {
  return value === null ? null : expectBytes(value, path, length);
}

export function expectKeyPair(value, path) {
  expectObject(value, path);
  return {
    publicKey: expectBytes(value.publicKey, `${path}.publicKey`, 32),
    privateKey: expectBytes(value.privateKey, `${path}.privateKey`, 32),
  };
}
