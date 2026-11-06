/**
 * High-level, on-device API. One Account per user (per device).
 *
 * Everything that crosses the network (prekey uploads, bundles, message envelopes, challenge
 * signatures) is a plain JSON-safe object of base64 strings and numbers. The server can store
 * and relay them, but cannot read or forge messages.
 */
import { bytesEqual, bytesToUtf8, fromBase64, readU32, toBase64, utf8ToBytes } from './encoding.js';
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
import { DecryptionError, generateX25519KeyPair, randomBytes } from './primitives.js';
import { RatchetSession } from './ratchet.js';
import { UntrustedIdentityError, createSignedPreKey, verifyPreKeyBundle, x3dhInitiate, x3dhRespond } from './x3dh.js';

const STATE_VERSION = 1;
const ENVELOPE_VERSION = 1;
/** Old sessions kept per contact, so messages already in flight still decrypt after a reset. */
const MAX_SESSIONS_PER_CONTACT = 5;
/** Old signed prekeys kept after rotation, for first messages sent with an older bundle. */
const MAX_SIGNED_PREKEYS_KEPT = 4;
const MAX_ONE_TIME_PREKEYS_PER_UPLOAD = 1000;
/** Plaintexts are padded to a multiple of this many bytes to hide their exact length. */
const PADDING_BLOCK = 160;

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

function randomId() {
  return (readU32(randomBytes(4), 0) % 0xffffff) + 1;
}

function nextId(id) {
  return (id % 0xffffff) + 1;
}

function parseId(value, what) {
  if (!Number.isInteger(value) || value < 1 || value > 0xffffffff) throw new TypeError(`Invalid ${what}`);
  return value;
}

function keyPairToJSON({ publicKey, privateKey }) {
  return { publicKey: toBase64(publicKey), privateKey: toBase64(privateKey) };
}

function keyPairFromJSON({ publicKey, privateKey }) {
  return { publicKey: fromBase64(publicKey, 32), privateKey: fromBase64(privateKey, 32) };
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
  #signedPreKeys; // Map<id, { id, keyPair, signature, createdAt }>, oldest first
  #currentSignedPreKeyId;
  #oneTimePreKeys; // Map<id, keyPair>
  #nextPreKeyId;
  #nextSignedPreKeyId;
  #sessions; // Map<peer identity key (base64), RatchetSession[]>, current session first
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
    });
  }

  /** The public code other people enter to start a conversation with this user. */
  get contactCode() {
    return this.#contactCode;
  }

  // --- Prekeys (uploaded to the server) ---------------------------------------

  /**
   * Generates prekeys and returns the public data to upload to the server.
   * - At sign-up / after restore: call once; the server replaces everything it had.
   * - When the server reports few one-time prekeys left: call again and append them.
   * - About once a week: call with { rotateSignedPreKey: true }.
   */
  async createPreKeyUpload({ oneTimePreKeyCount = 100, rotateSignedPreKey = false } = {}) {
    if (!Number.isInteger(oneTimePreKeyCount) || oneTimePreKeyCount < 0 || oneTimePreKeyCount > MAX_ONE_TIME_PREKEYS_PER_UPLOAD) {
      throw new RangeError(`oneTimePreKeyCount must be an integer from 0 to ${MAX_ONE_TIME_PREKEYS_PER_UPLOAD}`);
    }
    return this.#withLock(async () => {
      if (rotateSignedPreKey || this.#currentSignedPreKeyId === null) {
        const id = this.#nextSignedPreKeyId;
        this.#nextSignedPreKeyId = nextId(id);
        this.#signedPreKeys.set(id, await createSignedPreKey(this.#identity, id));
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
        this.#oneTimePreKeys.set(id, keyPair);
        oneTimePreKeys.push({ id, publicKey: toBase64(keyPair.publicKey) });
      }

      const spk = this.#signedPreKeys.get(this.#currentSignedPreKeyId);
      return {
        ...this.#publicIdentity(),
        signedPreKey: { id: spk.id, publicKey: toBase64(spk.keyPair.publicKey), signature: toBase64(spk.signature) },
        oneTimePreKeys,
      };
    });
  }

  // --- Conversations ----------------------------------------------------------

  /**
   * Starts a conversation with the person whose contact code the user entered.
   * `bundle` comes from the server: { identityKey, identityDHKey, identityBinding,
   * signedPreKey: { id, publicKey, signature }, oneTimePreKey: { id, publicKey } | null }.
   * Throws UntrustedIdentityError if the server's keys do not match the contact code.
   */
  async startSession(contactCode, bundle) {
    const theirIdentityKey = await decodeContactCode(contactCode);
    if (bytesEqual(theirIdentityKey, this.#identity.signing.publicKey)) {
      throw new Error('You cannot start a conversation with your own contact code');
    }
    const parsed = parseBundle(bundle);
    await verifyPreKeyBundle(parsed, theirIdentityKey);

    return this.#withLock(async () => {
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
      this.#installSession(toBase64(theirIdentityKey), session);
    });
  }

  async hasSession(contactCode) {
    const peerId = toBase64(await decodeContactCode(contactCode));
    return (this.#sessions.get(peerId)?.length ?? 0) > 0;
  }

  async deleteSession(contactCode) {
    const peerId = toBase64(await decodeContactCode(contactCode));
    return this.#withLock(async () => {
      this.#sessions.delete(peerId);
    });
  }

  /** Encrypts a text message (use JSON for structured content). Returns the envelope to send. */
  async encrypt(contactCode, text) {
    const peerId = toBase64(await decodeContactCode(contactCode));
    const plaintext = pad(utf8ToBytes(text));
    return this.#withLock(async () => {
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
   */
  async decrypt(senderContactCode, envelope) {
    const senderKey = await decodeContactCode(senderContactCode);
    const peerId = toBase64(senderKey);
    const message = parseEnvelope(envelope);

    return this.#withLock(async () => {
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
      for (const session of sessions) {
        try {
          return await this.#decryptWith(peerId, session, message);
        } catch (error) {
          if (!(error instanceof DecryptionError)) throw error;
        }
      }
      throw new DecryptionError('The message could not be decrypted');
    });
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
   * Returns the full private state as a JSON-safe object. It contains private keys: store it
   * only on the device, encrypted (OS keychain / Keystore, or a key derived from the user's
   * password). Save it after every encrypt/decrypt call, before sending or showing the message.
   */
  async exportState() {
    return this.#withLock(async () => ({
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
      })),
      currentSignedPreKeyId: this.#currentSignedPreKeyId,
      oneTimePreKeys: [...this.#oneTimePreKeys].map(([id, keyPair]) => ({ id, keyPair: keyPairToJSON(keyPair) })),
      nextPreKeyId: this.#nextPreKeyId,
      nextSignedPreKeyId: this.#nextSignedPreKeyId,
      sessions: [...this.#sessions].map(([peerId, list]) => ({ peerId, sessions: list.map((s) => s.toJSON()) })),
    }));
  }

  static async importState(state) {
    if (state?.version !== STATE_VERSION) throw new TypeError('Unsupported account state version');
    const identity = {
      signing: keyPairFromJSON(state.identity.signing),
      dh: keyPairFromJSON(state.identity.dh),
      binding: fromBase64(state.identity.binding, 64),
    };
    const bindingOk = await verifyIdentityBinding({
      signingKey: identity.signing.publicKey,
      dhKey: identity.dh.publicKey,
      binding: identity.binding,
    });
    if (!bindingOk) throw new TypeError('Account state is corrupted (identity binding is invalid)');

    return new Account({
      identity,
      contactCode: await encodeContactCode(identity.signing.publicKey),
      signedPreKeys: new Map(
        state.signedPreKeys.map((spk) => [
          spk.id,
          { id: spk.id, keyPair: keyPairFromJSON(spk.keyPair), signature: fromBase64(spk.signature, 64), createdAt: spk.createdAt },
        ]),
      ),
      currentSignedPreKeyId: state.currentSignedPreKeyId,
      oneTimePreKeys: new Map(state.oneTimePreKeys.map(({ id, keyPair }) => [id, keyPairFromJSON(keyPair)])),
      nextPreKeyId: state.nextPreKeyId,
      nextSignedPreKeyId: state.nextSignedPreKeyId,
      sessions: new Map(state.sessions.map(({ peerId, sessions }) => [peerId, sessions.map((s) => RatchetSession.fromJSON(s))])),
    });
  }

  // --- Internals ----------------------------------------------------------------

  /** Runs operations one at a time, so concurrent calls can never reuse a ratchet step. */
  #withLock(operation) {
    const result = this.#queue.then(operation);
    this.#queue = result.catch(() => {});
    return result;
  }

  #publicIdentity() {
    return {
      identityKey: toBase64(this.#identity.signing.publicKey),
      identityDHKey: toBase64(this.#identity.dh.publicKey),
      identityBinding: toBase64(this.#identity.binding),
    };
  }

  /** Makes `session` the current session for this contact, keeping a few older ones. */
  #installSession(peerId, session) {
    const list = (this.#sessions.get(peerId) ?? []).filter((s) => s !== session);
    list.unshift(session);
    this.#sessions.set(peerId, list.slice(0, MAX_SESSIONS_PER_CONTACT));
  }

  async #decryptWith(peerId, session, message) {
    const padded = await session.decrypt(message.header, message.ciphertext);
    this.#installSession(peerId, session);
    return bytesToUtf8(unpad(padded));
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

    const padded = await session.decrypt(message.header, message.ciphertext);
    // Only after the message authenticated: burn the one-time prekey and keep the session.
    if (oneTimePreKey) {
      oneTimePreKey.privateKey.fill(0);
      this.#oneTimePreKeys.delete(preKey.oneTimePreKeyId);
    }
    this.#installSession(peerId, session);
    return bytesToUtf8(unpad(padded));
  }
}
