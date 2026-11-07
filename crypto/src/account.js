/**
 * High-level, on-device API. One Account per user (per device).
 *
 * Everything that crosses the network (prekey uploads, bundles, message envelopes, challenge
 * signatures) is a plain JSON-safe object of base64 strings and numbers. The server can store
 * and relay them, but cannot read or forge messages.
 *
 * Chats can additionally be protected with a chat password (see chat-lock.js). That is purely
 * local: the server never sees chat passwords and cannot tell whether a chat has one.
 *
 * Persistence: the private state only ever leaves this class encrypted with a storage key (see
 * state.js). With enableAutoSave(), every state change is saved before the call returns, and
 * undone if saving fails.
 */
import { bytesEqual, bytesToUtf8, fromBase64, readU32, toBase64, utf8ToBytes } from './encoding.js';
import {
  ChatLockedError,
  createPasswordLock,
  generateChatKey,
  openForChat,
  openPasswordLock,
  sealForChat,
  validateChatPassword,
} from './chat-lock.js';
import {
  decodeContactCode,
  decodeRecoveryKey,
  deriveIdentity,
  encodeContactCode,
  encodeRecoveryKey,
  generateRecoverySeed,
  signChallenge,
  verifyIdentityBinding,
} from './keys.js';
import {
  DecryptionError,
  ed25519KeyPairFromSeed,
  generateX25519KeyPair,
  randomBytes,
  x25519KeyPairFromSeed,
} from './primitives.js';
import { RatchetSession } from './ratchet.js';
import {
  PersistenceError,
  expectArray,
  expectBytes,
  expectInt,
  expectKeyPair,
  expectNullableBytes,
  expectObject,
  generateStorageKey,
  invalidState,
  openState,
  parseStorageKey,
  sealState,
} from './state.js';
import {
  UntrustedIdentityError,
  createSignedPreKey,
  verifyPreKeyBundle,
  verifySignedPreKey,
  x3dhInitiate,
  x3dhRespond,
} from './x3dh.js';

const STATE_VERSION = 1;
const ENVELOPE_VERSION = 1;
/** Old sessions kept per contact, so messages already in flight still decrypt after a reset. */
const MAX_SESSIONS_PER_CONTACT = 5;
/** Old signed prekeys kept after rotation, for first messages sent with an older bundle. */
const MAX_SIGNED_PREKEYS_KEPT = 4;
/** A signed prekey is due for rotation after this long... */
const SIGNED_PREKEY_ROTATION_INTERVAL_MS = 7 * 24 * 60 * 60 * 1000;
/** ...or after this many new conversations were started with it. */
const SIGNED_PREKEY_ROTATION_AFTER_SESSIONS = 5_000;
/** Hard limit of remembered first messages per signed prekey (replay protection). */
const MAX_BASE_KEYS_PER_SIGNED_PREKEY = 10_000;
const MAX_ONE_TIME_PREKEYS_PER_UPLOAD = 1000;
/** One-time prekey private keys kept on the device. The oldest are dropped beyond this. */
const MAX_ONE_TIME_PREKEYS_HELD = 2000;
const MAX_PREKEY_ID = 0xffffff;
/** Plaintexts are padded to a multiple of this many bytes to hide their exact length. */
const PADDING_BLOCK = 160;
const MIN_PBKDF2_ITERATIONS = 100_000;
const MAX_PBKDF2_ITERATIONS = 10_000_000;

/** Thrown when there is no session with a contact (call startSession first). */
export class NoSessionError extends Error {
  constructor(message) {
    super(message);
    this.name = 'NoSessionError';
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function pad(bytes) {
  const out = new Uint8Array((Math.floor(bytes.length / PADDING_BLOCK) + 1) * PADDING_BLOCK);
  out.set(bytes);
  out[bytes.length] = 0x80;
  return out;
}

function unpad(bytes) {
  let end = bytes.length - 1;
  while (end >= 0 && bytes[end] === 0) end--;
  if (end < 0 || bytes[end] !== 0x80) throw new DecryptionError('Invalid message padding');
  return bytes.subarray(0, end);
}

/** Turns a decrypted message into text. Runs before the session state is committed. */
function decodeMessage(padded) {
  try {
    return bytesToUtf8(unpad(padded));
  } catch (error) {
    throw error instanceof DecryptionError ? error : new DecryptionError('Message is not valid UTF-8 text');
  }
}

function randomId() {
  return (readU32(randomBytes(4), 0) % MAX_PREKEY_ID) + 1;
}

function nextId(id) {
  return (id % MAX_PREKEY_ID) + 1;
}

function parseId(value, what) {
  if (!Number.isInteger(value) || value < 1 || value > 0xffffffff) throw new TypeError(`Invalid ${what}`);
  return value;
}

function keyPairToJSON({ publicKey, privateKey }) {
  return { publicKey: toBase64(publicKey), privateKey: toBase64(privateKey) };
}

/** Converts a prekey bundle from the server into bytes, validating every field. */
function parseBundle(bundle) {
  if (!bundle || typeof bundle !== 'object' || !bundle.signedPreKey) throw new TypeError('Invalid prekey bundle');
  return {
    identityKey: fromBase64(bundle.identityKey, 32),
    identityDHKey: fromBase64(bundle.identityDHKey, 32),
    identityBinding: fromBase64(bundle.identityBinding, 64),
    signedPreKey: {
      id: parseId(bundle.signedPreKey.id, 'signed prekey id'),
      publicKey: fromBase64(bundle.signedPreKey.publicKey, 32),
      signature: fromBase64(bundle.signedPreKey.signature, 64),
    },
    oneTimePreKey: bundle.oneTimePreKey
      ? {
          id: parseId(bundle.oneTimePreKey.id, 'one-time prekey id'),
          publicKey: fromBase64(bundle.oneTimePreKey.publicKey, 32),
        }
      : null,
  };
}

/** Converts a message envelope from the server into bytes, validating every field. */
function parseEnvelope(envelope) {
  if (!envelope || typeof envelope !== 'object') throw new DecryptionError('Invalid message envelope');
  if (envelope.version !== ENVELOPE_VERSION) throw new DecryptionError('Unsupported message version');
  if (envelope.type !== 'prekey' && envelope.type !== 'message') throw new DecryptionError('Unknown message type');
  try {
    const parsed = {
      type: envelope.type,
      header: fromBase64(envelope.header),
      ciphertext: fromBase64(envelope.ciphertext),
      preKey: null,
    };
    if (envelope.type === 'prekey') {
      const p = envelope.preKey ?? {};
      parsed.preKey = {
        identityKey: fromBase64(p.identityKey, 32),
        identityDHKey: fromBase64(p.identityDHKey, 32),
        identityBinding: fromBase64(p.identityBinding, 64),
        ephemeralKey: fromBase64(p.ephemeralKey, 32),
        signedPreKeyId: parseId(p.signedPreKeyId, 'signed prekey id'),
        oneTimePreKeyId: p.oneTimePreKeyId == null ? null : parseId(p.oneTimePreKeyId, 'one-time prekey id'),
      };
    }
    return parsed;
  } catch (error) {
    if (error instanceof TypeError) throw new DecryptionError(`Invalid message envelope: ${error.message}`);
    throw error;
  }
}

// ---------------------------------------------------------------------------
// Account
// ---------------------------------------------------------------------------

export class Account {
  #identity;
  #contactCode;
  /**
   * Map<id, { id, keyPair, signature, createdAt, usedBaseKeys }>, oldest first.
   * usedBaseKeys: Set of the X3DH ephemeral keys (base64) of every conversation started with
   * this signed prekey. A first message is only ever accepted once, even if its session was
   * later deleted and no one-time prekey was involved.
   */
  #signedPreKeys;
  #currentSignedPreKeyId;
  #oneTimePreKeys; // Map<id, keyPair>, oldest first
  #nextPreKeyId;
  #nextSignedPreKeyId;
  #sessions; // Map<peer identity key (base64), RatchetSession[]>, current session first
  /**
   * Map<peer identity key (base64), ChatRecord> for chats that have (or had) a chat password:
   *   passwordLock:   { salt, iterations, wrappedKey } | null (null once the password is removed)
   *   chatKey:        Uint8Array while unlocked; null while locked
   *   sealedSessions: the chat's sessions, encrypted with the chat key, while locked
   * While a chat is locked, its sessions are NOT in #sessions; they only exist in sealedSessions.
   */
  #chats;
  #autoSave = null; // { storageKey, save }
  #queue = Promise.resolve();

  /** @private Use Account.create(), Account.restore() or Account.importState(). */
  constructor(fields) {
    this.#identity = fields.identity;
    this.#contactCode = fields.contactCode;
    this.#signedPreKeys = fields.signedPreKeys;
    this.#currentSignedPreKeyId = fields.currentSignedPreKeyId;
    this.#oneTimePreKeys = fields.oneTimePreKeys;
    this.#nextPreKeyId = fields.nextPreKeyId;
    this.#nextSignedPreKeyId = fields.nextSignedPreKeyId;
    this.#sessions = fields.sessions;
    this.#chats = fields.chats;
  }

  // --- Creating and recovering accounts -------------------------------------

  /**
   * Creates a brand-new identity.
   * Show `recoveryKey` to the user ONCE, have them write it down, and never store or send it.
   */
  static async create() {
    const seed = generateRecoverySeed();
    try {
      const account = await Account.#fromSeed(seed);
      return { account, recoveryKey: await encodeRecoveryKey(seed) };
    } finally {
      seed.fill(0);
    }
  }

  /**
   * Recreates the identity (same contact code) from the recovery key, e.g. on a new phone or
   * after a forgotten password. Old sessions and prekeys are gone: upload new prekeys with
   * createPreKeyUpload(), and conversations are re-established automatically on the next message.
   */
  static async restore(recoveryKey) {
    const seed = await decodeRecoveryKey(recoveryKey);
    try {
      return await Account.#fromSeed(seed);
    } finally {
      seed.fill(0);
    }
  }

  static async #fromSeed(seed) {
    const identity = await deriveIdentity(seed);
    return new Account({
      identity,
      contactCode: await encodeContactCode(identity.signing.publicKey),
      signedPreKeys: new Map(),
      currentSignedPreKeyId: null,
      oneTimePreKeys: new Map(),
      nextPreKeyId: randomId(),
      nextSignedPreKeyId: randomId(),
      sessions: new Map(),
      chats: new Map(),
    });
  }

  /** The public code other people enter to start a conversation with this user. */
  get contactCode() {
    return this.#contactCode;
  }

  // --- Prekeys (uploaded to the server) ---------------------------------------

  /**
   * Generates prekeys and returns the public data to upload to the server. The server always
   * takes the signed prekey in the upload as the current one.
   * - At sign-up / after restore: the server replaces everything it had.
   * - When the server reports few one-time prekeys left: upload more (the server appends them).
   * - rotateSignedPreKey: 'auto' (default) rotates when getPreKeyStatus() says it is due,
   *   true always rotates, false never does.
   * With auto-save on, the new private keys are saved before this returns, so never upload
   * public keys whose private halves could still be lost.
   */
  async createPreKeyUpload({ oneTimePreKeyCount = 100, rotateSignedPreKey = 'auto' } = {}) {
    if (!Number.isInteger(oneTimePreKeyCount) || oneTimePreKeyCount < 0 || oneTimePreKeyCount > MAX_ONE_TIME_PREKEYS_PER_UPLOAD) {
      throw new RangeError(`oneTimePreKeyCount must be an integer from 0 to ${MAX_ONE_TIME_PREKEYS_PER_UPLOAD}`);
    }
    if (rotateSignedPreKey !== 'auto' && typeof rotateSignedPreKey !== 'boolean') {
      throw new TypeError("rotateSignedPreKey must be true, false or 'auto'");
    }
    return this.#mutate(async () => {
      const due = this.#signedPreKeyRotationDue();
      if (this.#currentSignedPreKeyId === null || rotateSignedPreKey === true || (rotateSignedPreKey === 'auto' && due)) {
        const id = this.#nextSignedPreKeyId;
        this.#nextSignedPreKeyId = nextId(id);
        const signedPreKey = await createSignedPreKey(this.#identity, id);
        this.#signedPreKeys.set(id, { ...signedPreKey, usedBaseKeys: new Set() });
        this.#currentSignedPreKeyId = id;
        while (this.#signedPreKeys.size > MAX_SIGNED_PREKEYS_KEPT) {
          this.#signedPreKeys.delete(this.#signedPreKeys.keys().next().value);
        }
      }

      const oneTimePreKeys = [];
      for (let i = 0; i < oneTimePreKeyCount; i++) {
        const id = this.#nextPreKeyId;
        this.#nextPreKeyId = nextId(id);
        const keyPair = await generateX25519KeyPair();
        this.#oneTimePreKeys.delete(id); // only possible after 16 million ids; keeps insertion order right
        this.#oneTimePreKeys.set(id, keyPair);
        oneTimePreKeys.push({ id, publicKey: toBase64(keyPair.publicKey) });
      }
      while (this.#oneTimePreKeys.size > MAX_ONE_TIME_PREKEYS_HELD) {
        this.#oneTimePreKeys.delete(this.#oneTimePreKeys.keys().next().value);
      }

      const spk = this.#signedPreKeys.get(this.#currentSignedPreKeyId);
      return {
        ...this.#publicIdentity(),
        signedPreKey: { id: spk.id, publicKey: toBase64(spk.keyPair.publicKey), signature: toBase64(spk.signature) },
        oneTimePreKeys,
      };
    });
  }

  /**
   * For a periodic maintenance check (e.g. on every app start): if signedPreKeyRotationDue is
   * true, call createPreKeyUpload({ oneTimePreKeyCount: 0 }) and upload the result.
   */
  getPreKeyStatus() {
    const spk = this.#signedPreKeys.get(this.#currentSignedPreKeyId);
    return {
      signedPreKeyId: spk?.id ?? null,
      signedPreKeyCreatedAt: spk?.createdAt ?? null,
      signedPreKeyRotationDue: this.#signedPreKeyRotationDue(),
      oneTimePreKeysHeld: this.#oneTimePreKeys.size,
    };
  }

  // --- Conversations ----------------------------------------------------------

  /**
   * Starts a conversation with the person whose contact code the user entered.
   * `bundle` comes from the server: { identityKey, identityDHKey, identityBinding,
   * signedPreKey: { id, publicKey, signature }, oneTimePreKey: { id, publicKey } | null }.
   * Throws UntrustedIdentityError if the server's keys do not match the contact code.
   */
  async startSession(contactCode, bundle) {
    const { peerId, peerKey } = await this.#peer(contactCode);
    if (bytesEqual(peerKey, this.#identity.signing.publicKey)) {
      throw new Error('You cannot start a conversation with your own contact code');
    }
    const parsed = parseBundle(bundle);
    await verifyPreKeyBundle(parsed, peerKey);

    return this.#mutate(async () => {
      this.#assertUnlocked(peerId);
      const { sharedSecret, associatedData, ephemeralPublicKey } = await x3dhInitiate(this.#identity, parsed);
      const session = await RatchetSession.createInitiator({
        sharedSecret,
        associatedData,
        theirRatchetKey: parsed.signedPreKey.publicKey,
        baseKey: ephemeralPublicKey,
        pendingPreKey: {
          ...this.#publicIdentity(),
          ephemeralKey: toBase64(ephemeralPublicKey),
          signedPreKeyId: parsed.signedPreKey.id,
          oneTimePreKeyId: parsed.oneTimePreKey ? parsed.oneTimePreKey.id : null,
        },
      });
      this.#installSession(peerId, session);
    });
  }

  async hasSession(contactCode) {
    const { peerId } = await this.#peer(contactCode);
    const chat = this.#chats.get(peerId);
    if (chat && chat.chatKey === null) return chat.sealedSessions !== null;
    return (this.#sessions.get(peerId)?.length ?? 0) > 0;
  }

  /**
   * Deletes everything about a chat on this device: its sessions, chat password and chat key.
   * Data sealed with sealChatData for this chat becomes unreadable, so delete it too.
   * This is also the way out of a forgotten chat password: delete the chat and start a new one.
   * Old first messages of the deleted chat can still not be replayed.
   */
  async deleteChat(contactCode) {
    const { peerId } = await this.#peer(contactCode);
    return this.#mutate(async () => {
      this.#sessions.delete(peerId);
      this.#chats.get(peerId)?.chatKey?.fill(0);
      this.#chats.delete(peerId);
    });
  }

  /**
   * Encrypts a text message (use JSON for structured content). Returns the envelope to send.
   * Throws ChatLockedError if the chat has a chat password and is locked.
   */
  async encrypt(contactCode, text) {
    const { peerId } = await this.#peer(contactCode);
    const plaintext = pad(utf8ToBytes(text));
    return this.#mutate(async () => {
      this.#assertUnlocked(peerId);
      const session = this.#sessions.get(peerId)?.[0];
      if (!session) throw new NoSessionError('No conversation with this contact yet. Call startSession() first.');
      const { header, ciphertext } = await session.encrypt(plaintext);
      const envelope = {
        version: ENVELOPE_VERSION,
        type: session.pendingPreKey ? 'prekey' : 'message',
        header: toBase64(header),
        ciphertext: toBase64(ciphertext),
      };
      if (session.pendingPreKey) envelope.preKey = { ...session.pendingPreKey };
      return envelope;
    });
  }

  /**
   * Decrypts an envelope. `senderContactCode` is who the server says sent it; decryption only
   * succeeds if that person really did, so the server cannot fake the sender.
   * Call hasSession(senderContactCode) first if you want to show new conversations as requests.
   *
   * Throws ChatLockedError if the chat has a chat password and is locked. Nothing is changed in
   * that case: keep the envelope (it is still encrypted) and decrypt it after unlockChat().
   */
  async decrypt(senderContactCode, envelope) {
    const { peerId, peerKey: senderKey } = await this.#peer(senderContactCode);
    const message = parseEnvelope(envelope);

    return this.#mutate(async () => {
      this.#assertUnlocked(peerId);
      const sessions = this.#sessions.get(peerId) ?? [];

      if (message.type === 'prekey') {
        if (!bytesEqual(message.preKey.identityKey, senderKey)) {
          throw new UntrustedIdentityError('The message was not sent by the claimed contact');
        }
        // Follow-up messages repeat the X3DH data until we reply; reuse the session they belong to.
        const existing = sessions.find((s) => bytesEqual(s.baseKey, message.preKey.ephemeralKey));
        if (existing) return this.#decryptWith(peerId, existing, message);
        return this.#acceptNewSession(peerId, message);
      }

      if (sessions.length === 0) {
        throw new NoSessionError('No conversation with this contact. Start a new session with them.');
      }
      // Sessions that already know this message's chain go first: they need no DH ratchet step,
      // so the normal case costs one attempt. Each other attempt is capped by MAX_SKIP in the
      // ratchet, which bounds the work a forged message can cause.
      const ordered = [
        ...sessions.filter((s) => s.knowsChainOf(message.header)),
        ...sessions.filter((s) => !s.knowsChainOf(message.header)),
      ];
      let firstError = null; // from the most likely session, so the reason is meaningful
      for (const session of ordered) {
        try {
          return await this.#decryptWith(peerId, session, message);
        } catch (error) {
          if (!(error instanceof DecryptionError)) throw error;
          firstError ??= error;
        }
      }
      throw firstError;
    });
  }

  // --- Chat passwords -----------------------------------------------------------

  /**
   * Protects one chat with a password the user chooses (at least 6 characters). It is
   * independent of the login password and of every other chat's password. The chat stays
   * unlocked until lockChat() / lockAllChats() is called, or the app restarts.
   * Works before or after the conversation has started.
   */
  async setChatPassword(contactCode, password) {
    validateChatPassword(password);
    const { peerId, peerKey } = await this.#peer(contactCode);
    return this.#mutate(async () => {
      const existing = this.#chats.get(peerId);
      if (existing?.passwordLock) throw new Error('This chat already has a password. Use changeChatPassword().');
      // Re-use the key of a chat whose password was removed earlier, so its sealed data stays readable.
      const chatKey = existing?.chatKey ?? generateChatKey();
      const passwordLock = await createPasswordLock(chatKey, password, peerKey);
      this.#chats.set(peerId, { passwordLock, chatKey, sealedSessions: null });
    });
  }

  /** Checks the chat password and unlocks the chat. Throws WrongPasswordError if it is wrong. */
  async unlockChat(contactCode, password) {
    const { peerId, peerKey } = await this.#peer(contactCode);
    return this.#withLock(async () => {
      const chat = this.#requirePasswordChat(peerId);
      // The password is checked even if the chat is already unlocked, so the app can use this
      // as the "enter chat password" check every time the user opens the chat.
      const chatKey = await openPasswordLock(chat.passwordLock, password, peerKey);
      if (chat.chatKey !== null) {
        chatKey.fill(0);
        return;
      }
      await this.#unseal(peerId, peerKey, chat, chatKey);
    });
  }

  /** Locks a chat: its keys are encrypted and wiped from memory until unlockChat(). */
  async lockChat(contactCode) {
    const { peerId, peerKey } = await this.#peer(contactCode);
    return this.#withLock(() => this.#lock(peerId, peerKey, this.#requirePasswordChat(peerId)));
  }

  /** Locks every chat that has a chat password, e.g. when the app goes to the background. */
  async lockAllChats() {
    return this.#withLock(async () => {
      for (const [peerId, chat] of this.#chats) {
        if (chat.passwordLock) await this.#lock(peerId, fromBase64(peerId), chat);
      }
    });
  }

  /** Changes a chat's password. The chat stays locked or unlocked as it was. */
  async changeChatPassword(contactCode, currentPassword, newPassword) {
    validateChatPassword(newPassword);
    const { peerId, peerKey } = await this.#peer(contactCode);
    return this.#mutate(async () => {
      const chat = this.#requirePasswordChat(peerId);
      const chatKey = await openPasswordLock(chat.passwordLock, currentPassword, peerKey);
      try {
        chat.passwordLock = await createPasswordLock(chatKey, newPassword, peerKey);
      } finally {
        chatKey.fill(0);
      }
    });
  }

  /** Removes a chat's password (the current one is required). The chat is left unlocked. */
  async removeChatPassword(contactCode, password) {
    const { peerId, peerKey } = await this.#peer(contactCode);
    return this.#mutate(async () => {
      const chat = this.#requirePasswordChat(peerId);
      const chatKey = await openPasswordLock(chat.passwordLock, password, peerKey);
      if (chat.chatKey === null) await this.#unseal(peerId, peerKey, chat, chatKey);
      else chatKey.fill(0);
      chat.passwordLock = null;
    });
  }

  async hasChatPassword(contactCode) {
    const { peerId } = await this.#peer(contactCode);
    return Boolean(this.#chats.get(peerId)?.passwordLock);
  }

  async isChatLocked(contactCode) {
    const { peerId } = await this.#peer(contactCode);
    return this.#isLocked(peerId);
  }

  /**
   * Encrypts data the app stores locally for a password-protected chat (message history,
   * drafts, contact nickname...) with that chat's key. Returns a base64 string. Only works
   * while the chat is unlocked, and only openChatData for the same chat can read it back.
   */
  async sealChatData(contactCode, text) {
    const { peerId, peerKey } = await this.#peer(contactCode);
    const bytes = utf8ToBytes(text);
    return this.#withLock(async () => toBase64(await sealForChat(this.#requireChatKey(peerId), 'data', peerKey, bytes)));
  }

  /** Reverses sealChatData. Throws ChatLockedError while locked, DecryptionError if altered. */
  async openChatData(contactCode, sealed) {
    const { peerId, peerKey } = await this.#peer(contactCode);
    const bytes = fromBase64(sealed);
    return this.#withLock(async () => bytesToUtf8(await openForChat(this.#requireChatKey(peerId), 'data', peerKey, bytes)));
  }

  // --- Account recovery -------------------------------------------------------

  /**
   * Signs a random challenge from the server, proving this device holds the identity behind
   * the contact code. Used to let a user who forgot their password back into their account.
   */
  async signRecoveryChallenge(challenge) {
    return toBase64(await signChallenge(this.#identity, fromBase64(challenge)));
  }

  // --- Persistence --------------------------------------------------------------

  /**
   * Creates a random 256-bit storage key (base64). Create it once per device and keep it in the
   * platform's secure key store (iOS Keychain, Android Keystore). Never upload it.
   */
  static generateStorageKey() {
    return generateStorageKey();
  }

  /**
   * Turns on automatic saving. From now on, every call that changes the private state
   * (encrypt, decrypt, startSession, createPreKeyUpload, chat password changes, deleteChat)
   * awaits `save(blob)` before it returns. That guarantees:
   *   - an envelope is only handed out for sending after the state that produced it is saved,
   *   - a decrypted message is only returned after the state that consumed its key is saved.
   * If `save` throws, the call is undone in memory and rejects with PersistenceError, so it can
   * simply be retried (for decrypt: with the same envelope). The current state is saved once
   * right away.
   * `blob` is an encrypted base64 string; store it as-is and load it with Account.importState().
   */
  async enableAutoSave({ storageKey, save }) {
    parseStorageKey(storageKey).fill(0);
    if (typeof save !== 'function') throw new TypeError('save must be a function');
    return this.#withLock(async () => {
      await save(await sealState(await this.#snapshot(), storageKey));
      this.#autoSave = { storageKey, save };
    });
  }

  disableAutoSave() {
    this.#autoSave = null;
  }

  /**
   * Returns the full private state encrypted with `storageKey` (a base64 string). Chats with a
   * chat password stay encrypted inside it with their own chat key, even while unlocked.
   */
  async exportState(storageKey) {
    parseStorageKey(storageKey).fill(0);
    return this.#withLock(async () => sealState(await this.#snapshot(), storageKey));
  }

  /**
   * Loads a blob from exportState() or auto-save. Every field is validated (keys must match,
   * signatures must verify, numbers must be in range); anything wrong throws InvalidStateError.
   * Password-protected chats start locked.
   */
  static async importState(blob, storageKey) {
    return Account.#fromSnapshot(await openState(blob, storageKey));
  }

  // --- Internals ----------------------------------------------------------------

  /** Runs operations one at a time, so concurrent calls can never reuse a ratchet step. */
  #withLock(operation) {
    const result = this.#queue.then(operation);
    this.#queue = result.catch(() => {});
    return result;
  }

  /**
   * Runs an operation that changes persisted state. With auto-save on, the state is saved
   * before the result is returned; if the operation or the save fails, all in-memory changes
   * are rolled back.
   */
  #mutate(operation) {
    return this.#withLock(async () => {
      // Read once: disableAutoSave() may run while the operation is awaiting.
      const autoSave = this.#autoSave;
      if (!autoSave) return operation();
      const before = this.#captureMemory();
      let result;
      try {
        result = await operation();
      } catch (error) {
        this.#restoreMemory(before);
        throw error;
      }
      try {
        await autoSave.save(await sealState(await this.#snapshot(), autoSave.storageKey));
      } catch (error) {
        this.#restoreMemory(before);
        throw new PersistenceError('Saving the account state failed, so the operation was undone. It can be retried.', {
          cause: error,
        });
      }
      return result;
    });
  }

  #captureMemory() {
    return {
      signedPreKeys: structuredClone(this.#signedPreKeys),
      currentSignedPreKeyId: this.#currentSignedPreKeyId,
      oneTimePreKeys: structuredClone(this.#oneTimePreKeys),
      nextPreKeyId: this.#nextPreKeyId,
      nextSignedPreKeyId: this.#nextSignedPreKeyId,
      sessions: [...this.#sessions].map(([peerId, list]) => [peerId, list.map((s) => s.toJSON())]),
      chats: structuredClone(this.#chats),
    };
  }

  #restoreMemory(captured) {
    this.#signedPreKeys = captured.signedPreKeys;
    this.#currentSignedPreKeyId = captured.currentSignedPreKeyId;
    this.#oneTimePreKeys = captured.oneTimePreKeys;
    this.#nextPreKeyId = captured.nextPreKeyId;
    this.#nextSignedPreKeyId = captured.nextSignedPreKeyId;
    this.#sessions = new Map(captured.sessions.map(([peerId, list]) => [peerId, list.map((s) => RatchetSession.fromJSON(s))]));
    this.#chats = captured.chats;
  }

  /** The private state as a JSON-safe object. Only ever leaves this class encrypted. */
  async #snapshot() {
    const chats = [];
    for (const [peerId, chat] of this.#chats) {
      if (chat.passwordLock) {
        const sealed = chat.chatKey === null ? chat.sealedSessions : await this.#sealSessions(peerId, fromBase64(peerId), chat.chatKey);
        chats.push({
          peerId,
          passwordLock: {
            salt: toBase64(chat.passwordLock.salt),
            iterations: chat.passwordLock.iterations,
            wrappedKey: toBase64(chat.passwordLock.wrappedKey),
          },
          sealedSessions: sealed === null ? null : toBase64(sealed),
        });
      } else {
        // Password was removed; the key is kept so data sealed earlier stays readable.
        chats.push({ peerId, chatKey: toBase64(chat.chatKey) });
      }
    }
    return {
      version: STATE_VERSION,
      identity: {
        signing: keyPairToJSON(this.#identity.signing),
        dh: keyPairToJSON(this.#identity.dh),
        binding: toBase64(this.#identity.binding),
      },
      signedPreKeys: [...this.#signedPreKeys.values()].map((spk) => ({
        id: spk.id,
        keyPair: keyPairToJSON(spk.keyPair),
        signature: toBase64(spk.signature),
        createdAt: spk.createdAt,
        usedBaseKeys: [...spk.usedBaseKeys],
      })),
      currentSignedPreKeyId: this.#currentSignedPreKeyId,
      oneTimePreKeys: [...this.#oneTimePreKeys].map(([id, keyPair]) => ({ id, keyPair: keyPairToJSON(keyPair) })),
      nextPreKeyId: this.#nextPreKeyId,
      nextSignedPreKeyId: this.#nextSignedPreKeyId,
      sessions: [...this.#sessions]
        .filter(([peerId]) => !this.#chats.get(peerId)?.passwordLock)
        .map(([peerId, list]) => ({ peerId, sessions: list.map((s) => s.toJSON()) })),
      chats,
    };
  }

  /** Builds an Account from a snapshot, validating every field. */
  static async #fromSnapshot(state) {
    expectObject(state, 'state');
    if (state.version !== STATE_VERSION) invalidState('state.version', `unsupported version ${state.version}`);

    // Identity: public keys must match the private keys, and the binding signature must verify.
    expectObject(state.identity, 'identity');
    const identity = {
      signing: expectKeyPair(state.identity.signing, 'identity.signing'),
      dh: expectKeyPair(state.identity.dh, 'identity.dh'),
      binding: expectBytes(state.identity.binding, 'identity.binding', 64),
    };
    const signingCheck = await ed25519KeyPairFromSeed(identity.signing.privateKey);
    if (!bytesEqual(signingCheck.publicKey, identity.signing.publicKey)) invalidState('identity.signing', 'keys do not match');
    const dhCheck = await x25519KeyPairFromSeed(identity.dh.privateKey);
    if (!bytesEqual(dhCheck.publicKey, identity.dh.publicKey)) invalidState('identity.dh', 'keys do not match');
    const bindingOk = await verifyIdentityBinding({
      signingKey: identity.signing.publicKey,
      dhKey: identity.dh.publicKey,
      binding: identity.binding,
    });
    if (!bindingOk) invalidState('identity.binding', 'signature does not verify');

    // Signed prekeys: keys must match and be signed by the identity.
    const signedPreKeys = new Map();
    for (const [i, raw] of expectArray(state.signedPreKeys, 'signedPreKeys', MAX_SIGNED_PREKEYS_KEPT).entries()) {
      const path = `signedPreKeys[${i}]`;
      expectObject(raw, path);
      const id = expectInt(raw.id, `${path}.id`, 1, MAX_PREKEY_ID);
      if (signedPreKeys.has(id)) invalidState(`${path}.id`, 'duplicate id');
      const keyPair = expectKeyPair(raw.keyPair, `${path}.keyPair`);
      const signature = expectBytes(raw.signature, `${path}.signature`, 64);
      if (!bytesEqual((await x25519KeyPairFromSeed(keyPair.privateKey)).publicKey, keyPair.publicKey)) {
        invalidState(`${path}.keyPair`, 'keys do not match');
      }
      if (!(await verifySignedPreKey(identity.signing.publicKey, id, keyPair.publicKey, signature))) {
        invalidState(`${path}.signature`, 'signature does not verify');
      }
      const usedBaseKeys = new Set(
        expectArray(raw.usedBaseKeys, `${path}.usedBaseKeys`, MAX_BASE_KEYS_PER_SIGNED_PREKEY).map((key, j) => {
          expectBytes(key, `${path}.usedBaseKeys[${j}]`, 32);
          return key;
        }),
      );
      const createdAt = expectInt(raw.createdAt, `${path}.createdAt`, 0, Number.MAX_SAFE_INTEGER);
      signedPreKeys.set(id, { id, keyPair, signature, createdAt, usedBaseKeys });
    }
    let currentSignedPreKeyId = null;
    if (state.currentSignedPreKeyId !== null) {
      currentSignedPreKeyId = expectInt(state.currentSignedPreKeyId, 'currentSignedPreKeyId', 1, MAX_PREKEY_ID);
      if (!signedPreKeys.has(currentSignedPreKeyId)) invalidState('currentSignedPreKeyId', 'no such signed prekey');
    }

    const oneTimePreKeys = new Map();
    for (const [i, raw] of expectArray(state.oneTimePreKeys, 'oneTimePreKeys', MAX_ONE_TIME_PREKEYS_HELD).entries()) {
      expectObject(raw, `oneTimePreKeys[${i}]`);
      const id = expectInt(raw.id, `oneTimePreKeys[${i}].id`, 1, MAX_PREKEY_ID);
      if (oneTimePreKeys.has(id)) invalidState(`oneTimePreKeys[${i}].id`, 'duplicate id');
      oneTimePreKeys.set(id, expectKeyPair(raw.keyPair, `oneTimePreKeys[${i}].keyPair`));
    }

    const expectPeerId = (value, path) => {
      expectBytes(value, path, 32);
      return value;
    };

    const chats = new Map();
    for (const [i, raw] of expectArray(state.chats, 'chats').entries()) {
      const path = `chats[${i}]`;
      expectObject(raw, path);
      const peerId = expectPeerId(raw.peerId, `${path}.peerId`);
      if (chats.has(peerId)) invalidState(`${path}.peerId`, 'duplicate chat');
      if (raw.passwordLock) {
        expectObject(raw.passwordLock, `${path}.passwordLock`);
        chats.set(peerId, {
          passwordLock: {
            salt: expectBytes(raw.passwordLock.salt, `${path}.passwordLock.salt`, 16),
            iterations: expectInt(raw.passwordLock.iterations, `${path}.passwordLock.iterations`, MIN_PBKDF2_ITERATIONS, MAX_PBKDF2_ITERATIONS),
            wrappedKey: expectBytes(raw.passwordLock.wrappedKey, `${path}.passwordLock.wrappedKey`, 60),
          },
          chatKey: null, // every password-protected chat starts locked
          sealedSessions: expectNullableBytes(raw.sealedSessions, `${path}.sealedSessions`),
        });
      } else {
        chats.set(peerId, { passwordLock: null, chatKey: expectBytes(raw.chatKey, `${path}.chatKey`, 32), sealedSessions: null });
      }
    }

    const sessions = new Map();
    for (const [i, raw] of expectArray(state.sessions, 'sessions').entries()) {
      const path = `sessions[${i}]`;
      expectObject(raw, path);
      const peerId = expectPeerId(raw.peerId, `${path}.peerId`);
      if (sessions.has(peerId)) invalidState(`${path}.peerId`, 'duplicate contact');
      if (chats.get(peerId)?.passwordLock) invalidState(`${path}.peerId`, 'password-protected chat stored in the clear');
      const list = expectArray(raw.sessions, `${path}.sessions`, MAX_SESSIONS_PER_CONTACT);
      sessions.set(peerId, list.map((s, j) => RatchetSession.fromJSON(s, `${path}.sessions[${j}]`)));
    }

    return new Account({
      identity,
      contactCode: await encodeContactCode(identity.signing.publicKey),
      signedPreKeys,
      currentSignedPreKeyId,
      oneTimePreKeys,
      nextPreKeyId: expectInt(state.nextPreKeyId, 'nextPreKeyId', 1, MAX_PREKEY_ID),
      nextSignedPreKeyId: expectInt(state.nextSignedPreKeyId, 'nextSignedPreKeyId', 1, MAX_PREKEY_ID),
      sessions,
      chats,
    });
  }

  async #peer(contactCode) {
    const peerKey = await decodeContactCode(contactCode);
    return { peerKey, peerId: toBase64(peerKey) };
  }

  #publicIdentity() {
    return {
      identityKey: toBase64(this.#identity.signing.publicKey),
      identityDHKey: toBase64(this.#identity.dh.publicKey),
      identityBinding: toBase64(this.#identity.binding),
    };
  }

  #signedPreKeyRotationDue() {
    const spk = this.#signedPreKeys.get(this.#currentSignedPreKeyId);
    if (!spk) return true;
    return (
      Date.now() - spk.createdAt >= SIGNED_PREKEY_ROTATION_INTERVAL_MS ||
      spk.usedBaseKeys.size >= SIGNED_PREKEY_ROTATION_AFTER_SESSIONS
    );
  }

  #isLocked(peerId) {
    const chat = this.#chats.get(peerId);
    return Boolean(chat?.passwordLock && chat.chatKey === null);
  }

  #assertUnlocked(peerId) {
    if (this.#isLocked(peerId)) throw new ChatLockedError();
  }

  #requirePasswordChat(peerId) {
    const chat = this.#chats.get(peerId);
    if (!chat?.passwordLock) throw new Error('This chat has no chat password');
    return chat;
  }

  #requireChatKey(peerId) {
    const chat = this.#chats.get(peerId);
    if (!chat) throw new Error('This chat has no chat password, so it has no key to seal data with');
    if (chat.chatKey === null) throw new ChatLockedError();
    return chat.chatKey;
  }

  async #sealSessions(peerId, peerKey, chatKey) {
    const sessions = this.#sessions.get(peerId) ?? [];
    if (sessions.length === 0) return null;
    const json = JSON.stringify(sessions.map((s) => s.toJSON()));
    return sealForChat(chatKey, 'sessions', peerKey, utf8ToBytes(json));
  }

  async #lock(peerId, peerKey, chat) {
    if (chat.chatKey === null) return;
    chat.sealedSessions = await this.#sealSessions(peerId, peerKey, chat.chatKey);
    this.#sessions.delete(peerId);
    chat.chatKey.fill(0);
    chat.chatKey = null;
  }

  async #unseal(peerId, peerKey, chat, chatKey) {
    if (chat.sealedSessions !== null) {
      const json = JSON.parse(bytesToUtf8(await openForChat(chatKey, 'sessions', peerKey, chat.sealedSessions)));
      this.#sessions.set(
        peerId,
        json.map((s, i) => RatchetSession.fromJSON(s, `chat sessions[${i}]`)),
      );
    }
    chat.chatKey = chatKey;
    chat.sealedSessions = null;
  }

  /** Makes `session` the current session for this contact, keeping a few older ones. */
  #installSession(peerId, session) {
    const list = (this.#sessions.get(peerId) ?? []).filter((s) => s !== session);
    list.unshift(session);
    this.#sessions.set(peerId, list.slice(0, MAX_SESSIONS_PER_CONTACT));
  }

  async #decryptWith(peerId, session, message) {
    const text = await session.decrypt(message.header, message.ciphertext, decodeMessage);
    this.#installSession(peerId, session);
    return text;
  }

  /** First message from someone: run the responder side of X3DH. */
  async #acceptNewSession(peerId, message) {
    const preKey = message.preKey;
    const bindingOk = await verifyIdentityBinding({
      signingKey: preKey.identityKey,
      dhKey: preKey.identityDHKey,
      binding: preKey.identityBinding,
    });
    if (!bindingOk) throw new UntrustedIdentityError("The sender's identity signature is invalid");

    const signedPreKey = this.#signedPreKeys.get(preKey.signedPreKeyId);
    if (!signedPreKey) throw new DecryptionError('Unknown signed prekey (it may have been rotated out)');

    // Replay protection: each first message (identified by its ephemeral key) is accepted once
    // per signed prekey, for as long as that signed prekey exists.
    const baseKeyId = toBase64(preKey.ephemeralKey);
    if (signedPreKey.usedBaseKeys.has(baseKeyId)) {
      throw new DecryptionError('This first message was already received before (replay)');
    }
    if (signedPreKey.usedBaseKeys.size >= MAX_BASE_KEYS_PER_SIGNED_PREKEY) {
      throw new DecryptionError('Too many new conversations on this signed prekey; rotate it with createPreKeyUpload()');
    }

    let oneTimePreKey = null;
    if (preKey.oneTimePreKeyId !== null) {
      oneTimePreKey = this.#oneTimePreKeys.get(preKey.oneTimePreKeyId);
      if (!oneTimePreKey) throw new DecryptionError('Unknown or already used one-time prekey');
    }

    const { sharedSecret, associatedData } = await x3dhRespond({
      ourIdentity: this.#identity,
      signedPreKey: signedPreKey.keyPair,
      oneTimePreKey,
      theirIdentityKey: preKey.identityKey,
      theirIdentityDHKey: preKey.identityDHKey,
      theirEphemeralKey: preKey.ephemeralKey,
    });
    const session = RatchetSession.createResponder({
      sharedSecret,
      associatedData,
      ourRatchetKeyPair: signedPreKey.keyPair,
      baseKey: preKey.ephemeralKey,
    });

    const text = await session.decrypt(message.header, message.ciphertext, decodeMessage);
    // Only after the message authenticated and decoded: remember it, burn the one-time prekey, keep the session.
    signedPreKey.usedBaseKeys.add(baseKeyId);
    if (oneTimePreKey) {
      oneTimePreKey.privateKey.fill(0);
      this.#oneTimePreKeys.delete(preKey.oneTimePreKeyId);
    }
    this.#installSession(peerId, session);
    return text;
  }
}
