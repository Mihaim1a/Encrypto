/**
 * The Double Ratchet algorithm, as specified by Signal:
 * https://signal.org/docs/specifications/doubleratchet/
 *
 * - Symmetric-key ratchet: every message is encrypted with a new key derived from a chain key
 *   (HMAC-SHA-256), and used keys are deleted. Stealing today's state does not reveal earlier
 *   messages (forward secrecy).
 * - Diffie-Hellman ratchet: every time the conversation changes direction, a new X25519 key
 *   pair is mixed into the root key. A stolen state stops working after the next round trip
 *   (post-compromise security).
 * - Each message key is expanded with HKDF into an AES-256-GCM key. The message header is
 *   authenticated as associated data, together with both parties' identity keys.
 *
 * This class is not safe for concurrent use. Account serializes all access to it.
 */
import { bytesEqual, concatBytes, fromBase64, readU32, toBase64, u32ToBytes } from './encoding.js';
import {
  DecryptionError,
  ZERO_SALT,
  aesGcmDecrypt,
  aesGcmEncrypt,
  generateX25519KeyPair,
  hkdf,
  hmacSha256,
  label,
  x25519,
} from './primitives.js';

/** Most message keys that may be skipped in one chain (limits the work an attacker can cause). */
const MAX_SKIP = 1000;
/** Most skipped-message keys kept per session for late out-of-order messages. Oldest go first. */
const MAX_STORED_SKIPPED_KEYS = 2000;

const HEADER_LENGTH = 40; // ratchet public key (32) || previous chain length (4) || message number (4)

// ---------------------------------------------------------------------------
// KDF chains
// ---------------------------------------------------------------------------

async function kdfRootKey(rootKey, dhOutput) {
  const out = await hkdf(dhOutput, rootKey, label('ratchet/root'), 64);
  return [out.slice(0, 32), out.slice(32)]; // [new root key, new chain key]
}

async function kdfChainKey(chainKey) {
  const messageKey = await hmacSha256(chainKey, Uint8Array.of(0x01));
  const nextChainKey = await hmacSha256(chainKey, Uint8Array.of(0x02));
  return [nextChainKey, messageKey];
}

async function encryptWithMessageKey(messageKey, plaintext, associatedData) {
  const key = await hkdf(messageKey, ZERO_SALT, label('ratchet/message'), 32);
  try {
    return await aesGcmEncrypt(key, plaintext, associatedData);
  } finally {
    key.fill(0);
    messageKey.fill(0);
  }
}

async function decryptWithMessageKey(messageKey, ciphertext, associatedData) {
  const key = await hkdf(messageKey, ZERO_SALT, label('ratchet/message'), 32);
  try {
    return await aesGcmDecrypt(key, ciphertext, associatedData);
  } finally {
    key.fill(0);
    messageKey.fill(0);
  }
}

// ---------------------------------------------------------------------------
// Header
// ---------------------------------------------------------------------------

function encodeHeader(dh, pn, n) {
  return concatBytes(dh, u32ToBytes(pn), u32ToBytes(n));
}

function decodeHeader(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length !== HEADER_LENGTH) {
    throw new DecryptionError('Malformed message header');
  }
  return { dh: bytes.slice(0, 32), pn: readU32(bytes, 32), n: readU32(bytes, 36) };
}

function skippedKeyId(dh, n) {
  return `${toBase64(dh)}:${n}`;
}

// ---------------------------------------------------------------------------
// Ratchet steps (operate on a mutable draft of the state)
// ---------------------------------------------------------------------------

async function skipMessageKeys(s, until) {
  if (s.receivingChainKey === null) return;
  if (until - s.nr > MAX_SKIP) throw new DecryptionError('Too many skipped messages');
  while (s.nr < until) {
    const [nextChainKey, messageKey] = await kdfChainKey(s.receivingChainKey);
    s.receivingChainKey = nextChainKey;
    s.skipped.set(skippedKeyId(s.dhRemote, s.nr), messageKey);
    s.nr += 1;
  }
  while (s.skipped.size > MAX_STORED_SKIPPED_KEYS) {
    s.skipped.delete(s.skipped.keys().next().value);
  }
}

async function dhRatchetStep(s, theirNewRatchetKey) {
  s.pn = s.ns;
  s.ns = 0;
  s.nr = 0;
  s.dhRemote = theirNewRatchetKey;
  [s.rootKey, s.receivingChainKey] = await kdfRootKey(s.rootKey, await x25519(s.dhSelf.privateKey, s.dhRemote));
  s.dhSelf = await generateX25519KeyPair();
  [s.rootKey, s.sendingChainKey] = await kdfRootKey(s.rootKey, await x25519(s.dhSelf.privateKey, s.dhRemote));
}

async function decryptWithState(s, header, headerBytes, ciphertext) {
  const associatedData = concatBytes(s.associatedData, headerBytes);

  // 1. A late message whose key we saved when skipping ahead.
  const id = skippedKeyId(header.dh, header.n);
  const skippedKey = s.skipped.get(id);
  if (skippedKey) {
    s.skipped.delete(id);
    return decryptWithMessageKey(skippedKey, ciphertext, associatedData);
  }

  // 2. The other side has a new ratchet key: finish the current chain, then step the DH ratchet.
  if (s.dhRemote === null || !bytesEqual(header.dh, s.dhRemote)) {
    await skipMessageKeys(s, header.pn);
    await dhRatchetStep(s, header.dh);
  } else if (header.n < s.nr) {
    throw new DecryptionError('Duplicate or replayed message');
  }

  // 3. Advance the receiving chain to this message.
  await skipMessageKeys(s, header.n);
  const [nextChainKey, messageKey] = await kdfChainKey(s.receivingChainKey);
  s.receivingChainKey = nextChainKey;
  s.nr += 1;
  return decryptWithMessageKey(messageKey, ciphertext, associatedData);
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

export class RatchetSession {
  #state;

  constructor(state) {
    this.#state = state;
  }

  /** Alice, right after X3DH. Bob's signed prekey doubles as his first ratchet key. */
  static async createInitiator({ sharedSecret, associatedData, theirRatchetKey, baseKey, pendingPreKey }) {
    const dhSelf = await generateX25519KeyPair();
    const [rootKey, sendingChainKey] = await kdfRootKey(sharedSecret, await x25519(dhSelf.privateKey, theirRatchetKey));
    return new RatchetSession({
      rootKey,
      sendingChainKey,
      receivingChainKey: null,
      dhSelf,
      dhRemote: theirRatchetKey,
      ns: 0,
      nr: 0,
      pn: 0,
      skipped: new Map(),
      associatedData,
      baseKey,
      pendingPreKey,
    });
  }

  /** Bob, when Alice's first message arrives. He can send once that message is decrypted. */
  static createResponder({ sharedSecret, associatedData, ourRatchetKeyPair, baseKey }) {
    return new RatchetSession({
      rootKey: sharedSecret,
      sendingChainKey: null,
      receivingChainKey: null,
      dhSelf: { publicKey: ourRatchetKeyPair.publicKey.slice(), privateKey: ourRatchetKeyPair.privateKey.slice() },
      dhRemote: null,
      ns: 0,
      nr: 0,
      pn: 0,
      skipped: new Map(),
      associatedData,
      baseKey,
      pendingPreKey: null,
    });
  }

  /** The X3DH ephemeral key this session was created from. Identifies the session. */
  get baseKey() {
    return this.#state.baseKey;
  }

  /** X3DH data that must accompany outgoing messages until the other side has replied. */
  get pendingPreKey() {
    return this.#state.pendingPreKey;
  }

  async encrypt(plaintext) {
    const s = this.#state;
    if (s.sendingChainKey === null) throw new Error('This session cannot send messages yet');
    const [nextChainKey, messageKey] = await kdfChainKey(s.sendingChainKey);
    const header = encodeHeader(s.dhSelf.publicKey, s.pn, s.ns);
    const ciphertext = await encryptWithMessageKey(messageKey, plaintext, concatBytes(s.associatedData, header));
    s.sendingChainKey = nextChainKey;
    s.ns += 1;
    return { header, ciphertext };
  }

  /**
   * Decrypts a message. The state is only updated if the message authenticates, so forged,
   * corrupted or replayed messages can never damage the session.
   */
  async decrypt(headerBytes, ciphertext) {
    const header = decodeHeader(headerBytes);
    const draft = structuredClone(this.#state);
    const plaintext = await decryptWithState(draft, header, headerBytes, ciphertext);
    draft.pendingPreKey = null; // The other side clearly has this session now.
    this.#state = draft;
    return plaintext;
  }

  toJSON() {
    const s = this.#state;
    const b64 = (bytes) => (bytes === null ? null : toBase64(bytes));
    return {
      rootKey: b64(s.rootKey),
      sendingChainKey: b64(s.sendingChainKey),
      receivingChainKey: b64(s.receivingChainKey),
      dhSelf: { publicKey: b64(s.dhSelf.publicKey), privateKey: b64(s.dhSelf.privateKey) },
      dhRemote: b64(s.dhRemote),
      ns: s.ns,
      nr: s.nr,
      pn: s.pn,
      skipped: [...s.skipped].map(([id, key]) => [id, b64(key)]),
      associatedData: b64(s.associatedData),
      baseKey: b64(s.baseKey),
      pendingPreKey: s.pendingPreKey,
    };
  }

  static fromJSON(json) {
    const bytes = (value, length) => (value === null ? null : fromBase64(value, length));
    return new RatchetSession({
      rootKey: bytes(json.rootKey, 32),
      sendingChainKey: bytes(json.sendingChainKey, 32),
      receivingChainKey: bytes(json.receivingChainKey, 32),
      dhSelf: { publicKey: bytes(json.dhSelf.publicKey, 32), privateKey: bytes(json.dhSelf.privateKey, 32) },
      dhRemote: bytes(json.dhRemote, 32),
      ns: json.ns,
      nr: json.nr,
      pn: json.pn,
      skipped: new Map(json.skipped.map(([id, key]) => [id, bytes(key, 32)])),
      associatedData: bytes(json.associatedData),
      baseKey: bytes(json.baseKey, 32),
      pendingPreKey: json.pendingPreKey,
    });
  }
}
