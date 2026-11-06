/**
 * End-to-end encryption for the messenger: X3DH key agreement + Double Ratchet + AES-256-GCM.
 *
 * Client side:  Account, encryptAttachment, decryptAttachment, normalizeContactCode
 * Server side:  createRecoveryChallenge, verifyRecoveryChallenge (the server never decrypts anything)
 */
import { fromBase64, toBase64 } from './encoding.js';
import { decodeContactCode, encodeContactCode, verifyChallenge } from './keys.js';
import { randomBytes } from './primitives.js';

export { Account, NoSessionError } from './account.js';
export { encryptAttachment, decryptAttachment } from './attachments.js';
export { InvalidCodeError } from './keys.js';
export { DecryptionError, PROTOCOL } from './primitives.js';
export { UntrustedIdentityError } from './x3dh.js';

/**
 * Validates a contact code typed or pasted by the user and returns it in canonical form
 * (upper case, dashed groups). Throws InvalidCodeError with a user-facing message otherwise.
 */
export async function normalizeContactCode(text) {
  return encodeContactCode(await decodeContactCode(text));
}

/** Server: issue a fresh random challenge (base64). Store it and accept it only once. */
export function createRecoveryChallenge() {
  return toBase64(randomBytes(32));
}

/**
 * Server: check that `signature` (from account.signRecoveryChallenge) was made by the owner of
 * `contactCode`. If true, the user has proven they hold the recovery key, so a password reset
 * can be allowed.
 */
export async function verifyRecoveryChallenge(contactCode, challenge, signature) {
  try {
    return await verifyChallenge(await decodeContactCode(contactCode), fromBase64(challenge), fromBase64(signature, 64));
  } catch {
    return false;
  }
}
