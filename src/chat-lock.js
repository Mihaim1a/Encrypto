/**
 * Chat passwords: an optional password the user picks for an individual chat. It is separate
 * from the login password and from the recovery key, and it never leaves the device.
 *
 *   chat password ──PBKDF2-SHA-256 (600,000 rounds, random salt)──► password key
 *   password key  ──AES-256-GCM──► wraps a random 256-bit chat key
 *   chat key      ──AES-256-GCM──► encrypts that chat's ratchet sessions, plus anything the app
 *                                  stores for the chat (message history, drafts) via sealChatData
 *
 * While a chat is locked, its keys exist only in encrypted form, so neither the app nor anyone
 * holding the device's stored data can read or send messages in it without the chat password.
 * Changing the password only re-wraps the chat key, so previously sealed data stays readable.
 */
import { concatBytes, utf8ToBytes } from './encoding.js';
import { DecryptionError, aesGcmDecrypt, aesGcmEncrypt, label, pbkdf2Sha256, randomBytes } from './primitives.js';

export const CHAT_PASSWORD_MIN_LENGTH = 6;
const CHAT_PASSWORD_MAX_LENGTH = 1024;
/** OWASP's recommendation for PBKDF2-HMAC-SHA-256. Stored per lock, so it can be raised later. */
const PBKDF2_ITERATIONS = 600_000;
const SALT_LENGTH = 16;

/** Thrown when using a chat that has a chat password and is currently locked. */
export class ChatLockedError extends Error {
  constructor(message = 'This chat is locked. Unlock it with its chat password first.') {
    super(message);
    this.name = 'ChatLockedError';
  }
}

/** Thrown when a chat password is wrong. */
export class WrongPasswordError extends Error {
  constructor(message = 'Wrong chat password') {
    super(message);
    this.name = 'WrongPasswordError';
  }
}

function passwordToBytes(password) {
  if (typeof password !== 'string') throw new TypeError('The chat password must be a string');
  // NFKC: the same password typed on different keyboards or platforms gives the same bytes.
  return utf8ToBytes(password.normalize('NFKC'));
}

/** Throws a RangeError or TypeError with a user-facing message if `password` is not allowed. */
export function validateChatPassword(password) {
  if (typeof password !== 'string') throw new TypeError('The chat password must be a string');
  const length = [...password.normalize('NFKC')].length;
  if (length < CHAT_PASSWORD_MIN_LENGTH) {
    throw new RangeError(`The chat password must be at least ${CHAT_PASSWORD_MIN_LENGTH} characters`);
  }
  if (length > CHAT_PASSWORD_MAX_LENGTH) {
    throw new RangeError(`The chat password must be at most ${CHAT_PASSWORD_MAX_LENGTH} characters`);
  }
}

/** Binds every encrypted item to its purpose and its chat, so items cannot be swapped around. */
function context(purpose, peerKey) {
  return concatBytes(label(`chat-lock/${purpose}`), peerKey);
}

export function generateChatKey() {
  return randomBytes(32);
}

/** Wraps `chatKey` under `password`. Returns { salt, iterations, wrappedKey }. */
export async function createPasswordLock(chatKey, password, peerKey) {
  validateChatPassword(password);
  const passwordBytes = passwordToBytes(password);
  const salt = randomBytes(SALT_LENGTH);
  const passwordKey = await pbkdf2Sha256(passwordBytes, salt, PBKDF2_ITERATIONS, 32);
  try {
    const wrappedKey = await aesGcmEncrypt(passwordKey, chatKey, context('key', peerKey));
    return { salt, iterations: PBKDF2_ITERATIONS, wrappedKey };
  } finally {
    passwordKey.fill(0);
    passwordBytes.fill(0);
  }
}

/** Returns the chat key, or throws WrongPasswordError. */
export async function openPasswordLock(lock, password, peerKey) {
  const passwordBytes = passwordToBytes(password);
  const passwordKey = await pbkdf2Sha256(passwordBytes, lock.salt, lock.iterations, 32);
  try {
    return await aesGcmDecrypt(passwordKey, lock.wrappedKey, context('key', peerKey));
  } catch (error) {
    if (error instanceof DecryptionError) throw new WrongPasswordError();
    throw error;
  } finally {
    passwordKey.fill(0);
    passwordBytes.fill(0);
  }
}

export function sealForChat(chatKey, purpose, peerKey, bytes) {
  return aesGcmEncrypt(chatKey, bytes, context(purpose, peerKey));
}

/** Throws DecryptionError if the data was altered or belongs to another chat. */
export function openForChat(chatKey, purpose, peerKey, bytes) {
  return aesGcmDecrypt(chatKey, bytes, context(purpose, peerKey));
}
