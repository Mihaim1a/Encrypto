/**
 * Long-term user keys: the recovery key, the identity key pair derived from it,
 * the shareable contact code, and the account-recovery challenge.
 *
 *   recovery key (32 random bytes, PRIVATE, written down by the user)
 *        │  HKDF
 *        ├─► identity signing key pair  (Ed25519)  ── public half = contact code (PUBLIC, shareable)
 *        └─► identity DH key pair       (X25519)   ── signed by the signing key ("binding")
 *
 * Because the identity is derived from the recovery key, typing the recovery key on a new
 * device recreates exactly the same identity and contact code. No key backup has to be
 * stored on the server.
 */
import { bytesEqual, concatBytes, fromBase32, groupString, toBase32 } from './encoding.js';
import {
  ZERO_SALT,
  ed25519KeyPairFromSeed,
  ed25519Sign,
  ed25519Verify,
  hkdf,
  label,
  randomBytes,
  sha256,
  x25519KeyPairFromSeed,
} from './primitives.js';

// A type byte inside every code stops a recovery key from being accepted as a contact code
// (and sent to the server) by mistake. Recovery keys start with "A", contact codes with "8".
const CODE_TYPE = { CONTACT: 0x43, RECOVERY: 0x52 };
const CODE_PAYLOAD_LENGTH = 32;
const CODE_CHECKSUM_LENGTH = 4;

/** Thrown when a contact code or recovery key is mistyped or is the wrong kind of code. */
export class InvalidCodeError extends Error {
  constructor(message) {
    super(message);
    this.name = 'InvalidCodeError';
  }
}

async function encodeCode(type, payload) {
  const body = concatBytes(Uint8Array.of(type), payload);
  const checksum = (await sha256(body)).subarray(0, CODE_CHECKSUM_LENGTH);
  return groupString(toBase32(concatBytes(body, checksum)), 5);
}

async function decodeCode(text, expectedType, name) {
  if (typeof text !== 'string') throw new InvalidCodeError(`The ${name} must be a string`);
  let bytes;
  try {
    bytes = fromBase32(text);
  } catch {
    throw new InvalidCodeError(`The ${name} contains invalid characters`);
  }
  if (bytes.length !== 1 + CODE_PAYLOAD_LENGTH + CODE_CHECKSUM_LENGTH) {
    throw new InvalidCodeError(`The ${name} has the wrong length`);
  }
  const body = bytes.subarray(0, 1 + CODE_PAYLOAD_LENGTH);
  const checksum = bytes.subarray(1 + CODE_PAYLOAD_LENGTH);
  const expected = (await sha256(body)).subarray(0, CODE_CHECKSUM_LENGTH);
  if (!bytesEqual(checksum, expected)) {
    throw new InvalidCodeError(`The ${name} is not valid. Check it for typos.`);
  }
  if (body[0] !== expectedType) {
    if (body[0] === CODE_TYPE.RECOVERY) {
      throw new InvalidCodeError('This is a recovery key, not a contact code. Never share your recovery key.');
    }
    if (body[0] === CODE_TYPE.CONTACT) {
      throw new InvalidCodeError('This is a contact code, not a recovery key.');
    }
    throw new InvalidCodeError(`The ${name} is not valid`);
  }
  return body.slice(1);
}

// ---------------------------------------------------------------------------
// Recovery key and identity
// ---------------------------------------------------------------------------

export function generateRecoverySeed() {
  return randomBytes(CODE_PAYLOAD_LENGTH);
}

export function encodeRecoveryKey(seed) {
  return encodeCode(CODE_TYPE.RECOVERY, seed);
}

export function decodeRecoveryKey(text) {
  return decodeCode(text, CODE_TYPE.RECOVERY, 'recovery key');
}

function bindingMessage(dhPublicKey) {
  return concatBytes(label('identity/binding'), dhPublicKey);
}

/**
 * Derives the long-term identity from the recovery key. Ed25519 signatures are deterministic,
 * so the same recovery key always yields the same keys and the same binding signature.
 */
export async function deriveIdentity(recoverySeed) {
  const signingSeed = await hkdf(recoverySeed, ZERO_SALT, label('identity/signing'), 32);
  const dhSeed = await hkdf(recoverySeed, ZERO_SALT, label('identity/dh'), 32);
  const signing = await ed25519KeyPairFromSeed(signingSeed);
  const dh = await x25519KeyPairFromSeed(dhSeed);
  const binding = await ed25519Sign(signing.privateKey, bindingMessage(dh.publicKey));
  signingSeed.fill(0);
  dhSeed.fill(0);
  return { signing, dh, binding };
}

/** Checks that `dhKey` really belongs to the owner of `signingKey`. */
export function verifyIdentityBinding({ signingKey, dhKey, binding }) {
  return ed25519Verify(signingKey, bindingMessage(dhKey), binding);
}

// ---------------------------------------------------------------------------
// Contact codes (the public key users share to be added)
// ---------------------------------------------------------------------------

export function encodeContactCode(identitySigningPublicKey) {
  return encodeCode(CODE_TYPE.CONTACT, identitySigningPublicKey);
}

/** Returns the 32-byte identity signing public key inside a contact code. */
export function decodeContactCode(text) {
  return decodeCode(text, CODE_TYPE.CONTACT, 'contact code');
}

// ---------------------------------------------------------------------------
// Account-recovery challenge (proves ownership of the identity to the server)
// ---------------------------------------------------------------------------

const MIN_CHALLENGE_LENGTH = 16;

function challengeMessage(challenge) {
  if (!(challenge instanceof Uint8Array) || challenge.length < MIN_CHALLENGE_LENGTH) {
    throw new TypeError(`The challenge must be at least ${MIN_CHALLENGE_LENGTH} bytes`);
  }
  // The label means a server-chosen challenge can never be a valid prekey or binding signature.
  return concatBytes(label('account-recovery'), challenge);
}

export function signChallenge(identity, challenge) {
  return ed25519Sign(identity.signing.privateKey, challengeMessage(challenge));
}

export function verifyChallenge(identitySigningPublicKey, challenge, signature) {
  return ed25519Verify(identitySigningPublicKey, challengeMessage(challenge), signature);
}
