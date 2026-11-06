import assert from 'node:assert/strict';
import { test } from 'node:test';

import { fromBase64, readU32, toBase64 } from '../src/encoding.js';
import {
  Account,
  ChatLockedError,
  DecryptionError,
  InvalidCodeError,
  InvalidStateError,
  NoSessionError,
  PersistenceError,
  UntrustedIdentityError,
  WrongPasswordError,
  createRecoveryChallenge,
  decryptAttachment,
  encryptAttachment,
  normalizeContactCode,
  verifyRecoveryChallenge,
} from '../src/index.js';
import { generateX25519KeyPair, x25519 } from '../src/primitives.js';
import { RatchetSession } from '../src/ratchet.js';
import { openState, sealState } from '../src/state.js';

// --- Helpers that play the part of the server ---------------------------------

async function signUp(oneTimePreKeyCount = 5) {
  const { account, recoveryKey } = await Account.create();
  const upload = await account.createPreKeyUpload({ oneTimePreKeyCount });
  return { account, recoveryKey, upload, code: account.contactCode };
}

/** What the server returns when someone asks for this user's keys (and it hands out one OPK). */
function takeBundle(upload, { withOneTimePreKey = true } = {}) {
  const { oneTimePreKeys, ...bundle } = upload;
  return { ...bundle, oneTimePreKey: withOneTimePreKey ? (oneTimePreKeys.shift() ?? null) : null };
}

async function connect() {
  const alice = await signUp();
  const bob = await signUp();
  await alice.account.startSession(bob.code, takeBundle(bob.upload));
  return { alice, bob };
}

async function send(from, to, text) {
  const envelope = await from.account.encrypt(to.code, text);
  // Everything goes through JSON, exactly as it would over the network.
  return to.account.decrypt(from.code, JSON.parse(JSON.stringify(envelope)));
}

/** Saves and loads a user's state, as an app restart would. */
async function reload(party) {
  const storageKey = Account.generateStorageKey();
  return { ...party, account: await Account.importState(await party.account.exportState(storageKey), storageKey) };
}

function flipBit(base64, index) {
  const bytes = fromBase64(base64);
  bytes[index] ^= 1;
  return toBase64(bytes);
}

function messageNumber(envelope) {
  return readU32(fromBase64(envelope.header), 36);
}

// --- Keys ----------------------------------------------------------------------

test('contact codes and recovery keys are checksummed and cannot be mixed up', async () => {
  const { account, recoveryKey } = await Account.create();
  const code = account.contactCode;
  assert.match(code, /^8[0-9A-Z]{4}(-[0-9A-Z]{5}){11}$/);
  assert.match(recoveryKey, /^A[0-9A-Z]{4}(-[0-9A-Z]{5}){11}$/);

  assert.equal(await normalizeContactCode(code.toLowerCase().replace(/-/g, ' ')), code);
  const typo = code.slice(0, 10) + (code[10] === 'X' ? 'Y' : 'X') + code.slice(11);
  await assert.rejects(normalizeContactCode(typo), InvalidCodeError);
  await assert.rejects(normalizeContactCode(recoveryKey), /recovery key/);
  await assert.rejects(Account.restore(code), /contact code/);
});

test('restoring from the recovery key gives back the same identity', async () => {
  const { account, recoveryKey } = await Account.create();
  const restored = await Account.restore(recoveryKey.toLowerCase());
  assert.equal(restored.contactCode, account.contactCode);
});

test('the server can verify account ownership with a recovery challenge', async () => {
  const { account, recoveryKey } = await Account.create();
  const other = (await Account.create()).account;
  const challenge = createRecoveryChallenge();

  const restored = await Account.restore(recoveryKey);
  const signature = await restored.signRecoveryChallenge(challenge);
  assert.equal(await verifyRecoveryChallenge(account.contactCode, challenge, signature), true);
  assert.equal(await verifyRecoveryChallenge(other.contactCode, challenge, signature), false);
  assert.equal(await verifyRecoveryChallenge(account.contactCode, createRecoveryChallenge(), signature), false);
  assert.equal(await verifyRecoveryChallenge(account.contactCode, challenge, 'garbage'), false);
});

test('invalid public keys are rejected', async () => {
  const ours = await generateX25519KeyPair();
  const lowOrderPoints = [new Uint8Array(32), Uint8Array.from({ length: 32 }, (_, i) => (i === 0 ? 1 : 0))];
  for (const point of lowOrderPoints) await assert.rejects(x25519(ours.privateKey, point));
  await assert.rejects(x25519(ours.privateKey, new Uint8Array(31)), TypeError);

  const alice = await signUp();
  const bob = await signUp();
  const malformed = { ...takeBundle(bob.upload), identityDHKey: 'AAAA' };
  await assert.rejects(alice.account.startSession(bob.code, malformed), TypeError);
});

// --- Messaging -------------------------------------------------------------------

test('two users exchange messages and the server only sees padded ciphertext', async () => {
  const { alice, bob } = await connect();

  const first = await alice.account.encrypt(bob.code, 'Hi Bob!');
  assert.equal(first.type, 'prekey');
  assert.ok(!JSON.stringify(first).includes('Hi Bob'));
  assert.equal(await bob.account.hasSession(alice.code), false);
  assert.equal(await bob.account.decrypt(alice.code, first), 'Hi Bob!');
  assert.equal(await bob.account.hasSession(alice.code), true);

  const reply = await bob.account.encrypt(alice.code, 'Hey Alice, this reply is quite a bit longer.');
  assert.equal(reply.type, 'message');
  assert.equal(reply.ciphertext.length, first.ciphertext.length, 'padding hides the length difference');
  assert.equal(await alice.account.decrypt(bob.code, reply), 'Hey Alice, this reply is quite a bit longer.');

  const third = await alice.account.encrypt(bob.code, 'Unicode works too: ✓ 😀');
  assert.equal(third.type, 'message', 'X3DH data stops once Bob has replied');
  assert.equal(await bob.account.decrypt(alice.code, third), 'Unicode works too: ✓ 😀');

  for (let i = 0; i < 25; i++) {
    assert.equal(await send(alice, bob, `ping ${i}`), `ping ${i}`);
    assert.equal(await send(bob, alice, `pong ${i}`), `pong ${i}`);
  }
  assert.equal(await send(alice, bob, ''), '');
  assert.equal(await send(alice, bob, 'x'.repeat(10_000)), 'x'.repeat(10_000));
});

test('out-of-order and late messages still decrypt', async () => {
  const { alice, bob } = await connect();
  await send(alice, bob, 'hello');

  const batch = [];
  for (let i = 0; i < 5; i++) batch.push(await alice.account.encrypt(bob.code, `m${i}`));
  for (const i of [4, 0, 2, 3, 1]) assert.equal(await bob.account.decrypt(alice.code, batch[i]), `m${i}`);

  // A message from an old chain that arrives after the DH ratchet has moved on.
  const late = await alice.account.encrypt(bob.code, 'late');
  await send(bob, alice, 'reply');
  assert.equal(await send(alice, bob, 'new chain'), 'new chain');
  assert.equal(await bob.account.decrypt(alice.code, late), 'late');
});

test('a message that skips too far ahead is rejected without breaking the session', async () => {
  const { alice, bob } = await connect();
  await send(alice, bob, 'hi');
  const sent = [];
  for (let i = 1; i <= 1002; i++) sent.push(await alice.account.encrypt(bob.code, `m${i}`));
  await assert.rejects(bob.account.decrypt(alice.code, sent[1001]), /Too many skipped/);
  assert.equal(await bob.account.decrypt(alice.code, sent[0]), 'm1');
});

test('the skip limit counts old and new chains together, before any key work', async () => {
  const { alice, bob } = await connect();
  await send(alice, bob, 'hi');
  for (let i = 0; i < 600; i++) await alice.account.encrypt(bob.code, `undelivered ${i}`); // old chain
  await send(bob, alice, 'reply'); // Alice starts a new chain
  const newChain = [];
  for (let i = 0; i < 500; i++) newChain.push(await alice.account.encrypt(bob.code, `new ${i}`));

  // 600 left in the old chain + 499 in the new one = 1099 keys to derive: refused up front.
  await assert.rejects(bob.account.decrypt(alice.code, newChain[499]), /Too many skipped/);
  // 600 + 0 is within the limit.
  assert.equal(await bob.account.decrypt(alice.code, newChain[0]), 'new 0');
});

test('a message that authenticates but is malformed inside does not use up its key', async () => {
  const bobRatchetKey = await generateX25519KeyPair();
  const sharedSecret = crypto.getRandomValues(new Uint8Array(32));
  const common = { sharedSecret, associatedData: new Uint8Array(128), baseKey: new Uint8Array(32) };
  const sender = await RatchetSession.createInitiator({ ...common, theirRatchetKey: bobRatchetKey.publicKey, pendingPreKey: null });
  const receiver = RatchetSession.createResponder({ ...common, ourRatchetKeyPair: bobRatchetKey });

  const { header, ciphertext } = await sender.encrypt(Uint8Array.of(1, 2, 3));
  const rejectContent = () => {
    throw new Error('bad padding');
  };
  await assert.rejects(receiver.decrypt(header, ciphertext, rejectContent), DecryptionError);
  // The rejected attempt changed nothing: the same message still decrypts afterwards.
  assert.equal((await receiver.decrypt(header, ciphertext)).join(','), '1,2,3');
});

test('turning auto-save off during a call does not undo that call', async () => {
  const { alice, bob } = await connect();
  await bob.account.enableAutoSave({ storageKey: Account.generateStorageKey(), save: async () => {} });
  const envelope = await alice.account.encrypt(bob.code, 'hello');
  const pending = bob.account.decrypt(alice.code, envelope);
  bob.account.disableAutoSave(); // while the decrypt is still running
  assert.equal(await pending, 'hello');
  assert.equal(await bob.account.hasSession(alice.code), true);
});

test('concurrent calls never reuse a message key', async () => {
  const { alice, bob } = await connect();
  const envelopes = await Promise.all(Array.from({ length: 10 }, (_, i) => alice.account.encrypt(bob.code, `c${i}`)));
  assert.equal(new Set(envelopes.map((e) => e.header)).size, 10);
  const plaintexts = await Promise.all(envelopes.map((e) => bob.account.decrypt(alice.code, e)));
  assert.equal(plaintexts.join(','), Array.from({ length: 10 }, (_, i) => `c${i}`).join(','));
});

test('messages are delivered when both people start a conversation at the same time', async () => {
  const alice = await signUp();
  const bob = await signUp();
  await alice.account.startSession(bob.code, takeBundle(bob.upload));
  await bob.account.startSession(alice.code, takeBundle(alice.upload));

  for (let i = 0; i < 4; i++) {
    const fromAlice = await alice.account.encrypt(bob.code, `a${i}`);
    const fromBob = await bob.account.encrypt(alice.code, `b${i}`);
    assert.equal(await bob.account.decrypt(alice.code, fromAlice), `a${i}`);
    assert.equal(await alice.account.decrypt(bob.code, fromBob), `b${i}`);
  }
});

// --- Attacks ---------------------------------------------------------------------

test('replayed messages are rejected', async () => {
  const { alice, bob } = await connect();
  const first = await alice.account.encrypt(bob.code, 'once');
  assert.equal(await bob.account.decrypt(alice.code, first), 'once');
  await assert.rejects(bob.account.decrypt(alice.code, first), DecryptionError);

  await send(bob, alice, 'reply');
  const normal = await alice.account.encrypt(bob.code, 'also once');
  assert.equal(await bob.account.decrypt(alice.code, normal), 'also once');
  await assert.rejects(bob.account.decrypt(alice.code, normal), DecryptionError);
});

test('a replayed first message is rejected even after its chat was deleted', async () => {
  const alice = await signUp();
  const bob = await signUp();
  // No one-time prekey (the server ran out), so only replay protection can stop the replay.
  await alice.account.startSession(bob.code, takeBundle(bob.upload, { withOneTimePreKey: false }));
  const first = await alice.account.encrypt(bob.code, 'pay Mallory 100 euros');
  assert.equal(await bob.account.decrypt(alice.code, first), 'pay Mallory 100 euros');

  await bob.account.deleteChat(alice.code);
  await assert.rejects(bob.account.decrypt(alice.code, first), /already received/);
  const reloadedBob = await reload(bob);
  await assert.rejects(reloadedBob.account.decrypt(alice.code, first), /already received/);

  // A genuinely new conversation from Alice is still accepted.
  await alice.account.startSession(bob.code, takeBundle(bob.upload, { withOneTimePreKey: false }));
  assert.equal(await send(alice, reloadedBob, 'new conversation'), 'new conversation');
});

test('tampered messages are rejected without damaging the session or burning prekeys', async () => {
  const { alice, bob } = await connect();
  const envelope = await alice.account.encrypt(bob.code, 'secret');

  await assert.rejects(bob.account.decrypt(alice.code, { ...envelope, ciphertext: flipBit(envelope.ciphertext, 20) }), DecryptionError);
  await assert.rejects(bob.account.decrypt(alice.code, { ...envelope, header: flipBit(envelope.header, 39) }), DecryptionError);
  await assert.rejects(bob.account.decrypt(alice.code, { ...envelope, ciphertext: 'AAAA' }), DecryptionError);
  await assert.rejects(bob.account.decrypt(alice.code, { ...envelope, version: 99 }), DecryptionError);
  assert.equal(await bob.account.hasSession(alice.code), false);

  assert.equal(await bob.account.decrypt(alice.code, envelope), 'secret');

  const later = await bob.account.encrypt(alice.code, 'still fine');
  await assert.rejects(alice.account.decrypt(bob.code, { ...later, ciphertext: flipBit(later.ciphertext, 40) }), DecryptionError);
  assert.equal(await alice.account.decrypt(bob.code, later), 'still fine');
});

test('a message bounced back to its own sender is rejected', async () => {
  const { alice, bob } = await connect();
  await send(alice, bob, 'hi');
  await send(bob, alice, 'hi back');

  const envelope = await alice.account.encrypt(bob.code, 'to bob');
  await assert.rejects(alice.account.decrypt(bob.code, envelope), DecryptionError);
  assert.equal(await bob.account.decrypt(alice.code, envelope), 'to bob');
  assert.equal(await send(bob, alice, 'alice is unaffected'), 'alice is unaffected');
});

test('a server that swaps in its own keys is detected (no man-in-the-middle)', async () => {
  const alice = await signUp();
  const bob = await signUp();
  const mallory = await signUp();

  // Asked for Bob's keys, the server returns Mallory's.
  await assert.rejects(alice.account.startSession(bob.code, takeBundle(mallory.upload)), UntrustedIdentityError);

  // Only the signed prekey is replaced.
  const swappedPreKey = takeBundle(bob.upload);
  swappedPreKey.signedPreKey = { ...swappedPreKey.signedPreKey, publicKey: mallory.upload.signedPreKey.publicKey };
  await assert.rejects(alice.account.startSession(bob.code, swappedPreKey), UntrustedIdentityError);

  // Only the identity DH key is replaced.
  const swappedIdentity = { ...takeBundle(bob.upload), identityDHKey: mallory.upload.identityDHKey };
  await assert.rejects(alice.account.startSession(bob.code, swappedIdentity), UntrustedIdentityError);

  assert.equal(await alice.account.hasSession(bob.code), false);
});

test('nobody can send a message pretending to be someone else', async () => {
  const alice = await signUp();
  const bob = await signUp();
  const mallory = await signUp();
  await mallory.account.startSession(bob.code, takeBundle(bob.upload));
  const envelope = await mallory.account.encrypt(bob.code, 'I am Alice, trust me');

  // The server claims the message came from Alice.
  await assert.rejects(bob.account.decrypt(alice.code, envelope), UntrustedIdentityError);

  // Mallory copies Alice's public identity into the message. Without Alice's private key the
  // X3DH secret is wrong and the message does not authenticate.
  const forged = {
    ...envelope,
    preKey: {
      ...envelope.preKey,
      identityKey: alice.upload.identityKey,
      identityDHKey: alice.upload.identityDHKey,
      identityBinding: alice.upload.identityBinding,
    },
  };
  await assert.rejects(bob.account.decrypt(alice.code, forged), DecryptionError);
  assert.equal(await bob.account.hasSession(alice.code), false);
});

test('a one-time prekey can only be used once', async () => {
  const alice = await signUp();
  const carol = await signUp();
  const bob = await signUp();
  const bundle = takeBundle(bob.upload);

  // A misbehaving server hands the same one-time prekey to two people.
  await alice.account.startSession(bob.code, bundle);
  await carol.account.startSession(bob.code, bundle);
  const fromAlice = await alice.account.encrypt(bob.code, 'from alice');
  const fromCarol = await carol.account.encrypt(bob.code, 'from carol');

  assert.equal(await bob.account.decrypt(alice.code, fromAlice), 'from alice');
  await assert.rejects(bob.account.decrypt(carol.code, fromCarol), /already used/);
});

// --- Prekey rotation and recovery ------------------------------------------------

test('signed prekeys rotate automatically when due, and very old ones are refused', async () => {
  const alice = await signUp();
  const bob = await signUp();
  const firstBundle = takeBundle(bob.upload, { withOneTimePreKey: false });
  const firstId = bob.account.getPreKeyStatus().signedPreKeyId;
  assert.equal(bob.account.getPreKeyStatus().signedPreKeyRotationDue, false);
  await bob.account.createPreKeyUpload({ oneTimePreKeyCount: 0 });
  assert.equal(bob.account.getPreKeyStatus().signedPreKeyId, firstId, 'not rotated before it is due');

  const realNow = Date.now;
  Date.now = () => realNow() + 8 * 24 * 60 * 60 * 1000; // eight days later
  try {
    assert.equal(bob.account.getPreKeyStatus().signedPreKeyRotationDue, true);
    const upload = await bob.account.createPreKeyUpload({ oneTimePreKeyCount: 0 });
    assert.ok(upload.signedPreKey.id !== firstId, 'rotated automatically');
    assert.equal(bob.account.getPreKeyStatus().signedPreKeyRotationDue, false);
  } finally {
    Date.now = realNow;
  }

  // A recent older bundle still works...
  const carol = await signUp();
  await carol.account.startSession(bob.code, firstBundle);
  assert.equal(await send(carol, bob, 'sent with the previous bundle'), 'sent with the previous bundle');

  // ...but once it has been rotated out completely, first messages using it are refused.
  for (let i = 0; i < 4; i++) await bob.account.createPreKeyUpload({ oneTimePreKeyCount: 0, rotateSignedPreKey: true });
  await alice.account.startSession(bob.code, firstBundle);
  await assert.rejects(send(alice, bob, 'too old'), /rotated out/);
});

test('prekey storage on the device is bounded', async () => {
  const { account } = await Account.create();
  for (let i = 0; i < 3; i++) await account.createPreKeyUpload({ oneTimePreKeyCount: 1000 });
  assert.equal(account.getPreKeyStatus().oneTimePreKeysHeld, 2000);
  await assert.rejects(account.createPreKeyUpload({ oneTimePreKeyCount: 1001 }), RangeError);
});

test('a restored account can start over with an existing contact', async () => {
  const { alice, bob } = await connect();
  await send(alice, bob, 'hi');
  await send(bob, alice, 'hi back');

  const restoredAlice = {
    account: await Account.restore(alice.recoveryKey),
    code: alice.code,
  };
  restoredAlice.upload = await restoredAlice.account.createPreKeyUpload({ oneTimePreKeyCount: 5 });

  // Bob still uses the old session, whose keys only existed on Alice's old device.
  const lost = await bob.account.encrypt(alice.code, 'sent to the old device');
  await assert.rejects(restoredAlice.account.decrypt(bob.code, lost), NoSessionError);

  await restoredAlice.account.startSession(bob.code, takeBundle(bob.upload));
  assert.equal(await send(restoredAlice, bob, "I'm back"), "I'm back");
  assert.equal(await send(bob, restoredAlice, 'welcome back'), 'welcome back');
});

// --- Saving state ----------------------------------------------------------------

test('state can be saved and loaded mid-conversation', async () => {
  const { alice, bob } = await connect();
  await send(alice, bob, 'before save');
  await send(bob, alice, 'reply before save');
  const pending = await alice.account.encrypt(bob.code, 'in flight during save');

  const bob2 = await reload(bob);
  const alice2 = await reload(alice);
  assert.equal(bob2.account.contactCode, bob.code);

  assert.equal(await bob2.account.decrypt(alice.code, pending), 'in flight during save');
  assert.equal(await send(bob2, alice2, 'after load'), 'after load');
  assert.equal(await send(alice2, bob2, 'after load too'), 'after load too');
});

test('saved state is encrypted, and altered or inconsistent state is refused', async () => {
  const { alice, bob } = await connect();
  await send(alice, bob, 'hello');
  const key = Account.generateStorageKey();
  const blob = await bob.account.exportState(key);

  await assert.rejects(bob.account.exportState('too short'), TypeError);
  await assert.rejects(Account.importState(blob, Account.generateStorageKey()), InvalidStateError);
  await assert.rejects(Account.importState(flipBit(blob, 40), key), InvalidStateError);

  // Even correctly encrypted content is checked field by field.
  const snapshot = await openState(blob, key);
  const other = await openState(await alice.account.exportState(key), key);
  const refuses = async (mutate, where) => {
    const copy = structuredClone(snapshot);
    mutate(copy);
    await assert.rejects(Account.importState(await sealState(copy, key), key), new RegExp(`InvalidStateError: .*${where}`));
  };
  await refuses((s) => (s.identity.signing.publicKey = other.identity.signing.publicKey), 'identity\\.signing: keys do not match');
  await refuses((s) => (s.signedPreKeys[0].signature = other.signedPreKeys[0].signature), 'signature does not verify');
  await refuses((s) => (s.currentSignedPreKeyId = 0), 'currentSignedPreKeyId');
  await refuses((s) => (s.sessions[0].sessions[0].nr = -1), 'sessions\\[0\\]\\.nr');
  await refuses((s) => (s.sessions[0].sessions[0].rootKey = 'AAAA'), 'rootKey');
  await refuses((s) => s.sessions.push(s.sessions[0]), 'duplicate contact');
  await refuses((s) => delete s.oneTimePreKeys, 'oneTimePreKeys');

  assert.equal((await Account.importState(blob, key)).contactCode, bob.code);
});

test('auto-save stores every change before returning, and undoes a call whose save failed', async () => {
  const { alice, bob } = await connect();
  const bobKey = Account.generateStorageKey();
  let saved = null;
  let failNextSave = false;
  const save = async (blob) => {
    if (failNextSave) {
      failNextSave = false;
      throw new Error('disk full');
    }
    saved = blob;
  };
  await bob.account.enableAutoSave({ storageKey: bobKey, save });
  assert.ok(saved, 'the current state is saved right away');

  // Receiving: a failed save undoes the decrypt, so the same envelope can simply be retried.
  const first = await alice.account.encrypt(bob.code, 'first');
  failNextSave = true;
  await assert.rejects(bob.account.decrypt(alice.code, first), PersistenceError);
  assert.equal(await bob.account.hasSession(alice.code), false);
  assert.equal(await bob.account.decrypt(alice.code, first), 'first');

  // What was saved is exactly the state after that call: a fresh load continues seamlessly.
  const loadedBob = { account: await Account.importState(saved, bobKey), code: bob.code };
  assert.equal(await send(alice, loadedBob, 'second'), 'second');

  // Sending: a failed save hands out no envelope and does not use up a message number.
  let aliceFails = false;
  await alice.account.enableAutoSave({
    storageKey: Account.generateStorageKey(),
    save: async () => {
      if (aliceFails) {
        aliceFails = false;
        throw new Error('disk full');
      }
    },
  });
  const third = await alice.account.encrypt(bob.code, 'third');
  aliceFails = true;
  await assert.rejects(alice.account.encrypt(bob.code, 'never sent'), PersistenceError);
  const fourth = await alice.account.encrypt(bob.code, 'fourth');
  assert.equal(messageNumber(fourth), messageNumber(third) + 1);
  assert.equal(await loadedBob.account.decrypt(alice.code, third), 'third');
  assert.equal(await loadedBob.account.decrypt(alice.code, fourth), 'fourth');
});

// --- Chat passwords --------------------------------------------------------------

test('a chat password locks that chat: nothing can be read or sent until it is unlocked', async () => {
  const { alice, bob } = await connect();
  await send(alice, bob, 'hello');
  await bob.account.setChatPassword(alice.code, 'correct horse');
  assert.equal(await bob.account.hasChatPassword(alice.code), true);
  assert.equal(await bob.account.isChatLocked(alice.code), false, 'unlocked right after setting it');

  await bob.account.lockChat(alice.code);
  assert.equal(await bob.account.isChatLocked(alice.code), true);
  assert.equal(await bob.account.hasSession(alice.code), true);

  const queued = await alice.account.encrypt(bob.code, 'sent while locked');
  await assert.rejects(bob.account.decrypt(alice.code, queued), ChatLockedError);
  await assert.rejects(bob.account.encrypt(alice.code, 'not allowed'), ChatLockedError);
  await assert.rejects(bob.account.unlockChat(alice.code, 'wrong horse'), WrongPasswordError);
  await assert.rejects(bob.account.unlockChat(alice.code, 'short'), WrongPasswordError);

  await bob.account.unlockChat(alice.code, 'correct horse');
  assert.equal(await bob.account.decrypt(alice.code, queued), 'sent while locked');
  assert.equal(await send(bob, alice, 'reply after unlock'), 'reply after unlock');
  // Checking the password again while already unlocked still rejects a wrong one.
  await assert.rejects(bob.account.unlockChat(alice.code, 'wrong horse'), WrongPasswordError);
});

test('each chat has its own password, and chats without one are not affected', async () => {
  const bob = await signUp();
  const alice = await signUp();
  const carol = await signUp();
  const dave = await signUp();
  for (const sender of [alice, carol, dave]) {
    await sender.account.startSession(bob.code, takeBundle(bob.upload));
    await send(sender, bob, 'hi');
  }
  await bob.account.setChatPassword(alice.code, 'alice-chat-password');
  await bob.account.setChatPassword(carol.code, 'carol-chat-password');
  await bob.account.lockAllChats();

  await assert.rejects(bob.account.unlockChat(carol.code, 'alice-chat-password'), WrongPasswordError);
  await bob.account.unlockChat(alice.code, 'alice-chat-password');
  assert.equal(await send(alice, bob, 'alice again'), 'alice again');
  await assert.rejects(send(carol, bob, 'carol again'), ChatLockedError);
  assert.equal(await send(dave, bob, 'dave has no chat password'), 'dave has no chat password');
});

test('protected chats are never saved in the clear and are locked again after loading', async () => {
  const { alice, bob } = await connect();
  await send(alice, bob, 'hello');
  await bob.account.setChatPassword(alice.code, 'my chat secret'); // still unlocked when saving

  const key = Account.generateStorageKey();
  const blob = await bob.account.exportState(key);
  const saved = await openState(blob, key);
  assert.equal(saved.sessions.length, 0, 'protected sessions are not in the plain session list');
  assert.equal(saved.chats.length, 1);
  assert.equal(saved.chats[0].chatKey, undefined, 'the chat key is only stored wrapped by the password');
  assert.ok(saved.chats[0].sealedSessions);

  const bob2 = { account: await Account.importState(blob, key), code: bob.code };
  assert.equal(await bob2.account.isChatLocked(alice.code), true);
  const pending = await alice.account.encrypt(bob.code, 'after reload');
  await assert.rejects(bob2.account.decrypt(alice.code, pending), ChatLockedError);
  await bob2.account.unlockChat(alice.code, 'my chat secret');
  assert.equal(await bob2.account.decrypt(alice.code, pending), 'after reload');
  assert.equal(await send(bob2, alice, 'still works'), 'still works');
});

test('changing or removing a chat password keeps the chat and its stored data', async () => {
  const { alice, bob } = await connect();
  await send(alice, bob, 'hello');
  await bob.account.setChatPassword(alice.code, 'first password');
  const history = await bob.account.sealChatData(alice.code, '["hello"]');
  await bob.account.lockChat(alice.code);
  await assert.rejects(bob.account.openChatData(alice.code, history), ChatLockedError);

  await assert.rejects(bob.account.changeChatPassword(alice.code, 'not it at all', 'second password'), WrongPasswordError);
  await bob.account.changeChatPassword(alice.code, 'first password', 'second password');
  assert.equal(await bob.account.isChatLocked(alice.code), true, 'changing the password does not unlock');
  await assert.rejects(bob.account.unlockChat(alice.code, 'first password'), WrongPasswordError);
  await bob.account.unlockChat(alice.code, 'second password');
  assert.equal(await bob.account.openChatData(alice.code, history), '["hello"]');

  await bob.account.lockChat(alice.code);
  await bob.account.removeChatPassword(alice.code, 'second password');
  assert.equal(await bob.account.hasChatPassword(alice.code), false);
  assert.equal(await bob.account.isChatLocked(alice.code), false);
  await assert.rejects(bob.account.lockChat(alice.code), /no chat password/);
  assert.equal(await send(alice, bob, 'no password now'), 'no password now');

  const reloaded = await reload(bob);
  assert.equal(await reloaded.account.openChatData(alice.code, history), '["hello"]');
});

test('sealed chat data is bound to its chat and tampering is detected', async () => {
  const bob = (await Account.create()).account;
  const alice = (await Account.create()).account;
  const carol = (await Account.create()).account;
  const dave = (await Account.create()).account;
  await bob.setChatPassword(alice.contactCode, 'alice chat pw');
  await bob.setChatPassword(carol.contactCode, 'carol chat pw');

  const sealed = await bob.sealChatData(alice.contactCode, 'draft: see you at 8');
  assert.equal(await bob.openChatData(alice.contactCode, sealed), 'draft: see you at 8');
  await assert.rejects(bob.openChatData(carol.contactCode, sealed), DecryptionError);
  await assert.rejects(bob.openChatData(alice.contactCode, flipBit(sealed, 30)), DecryptionError);
  await assert.rejects(bob.sealChatData(dave.contactCode, 'x'), /no chat password/);
});

test('chat passwords are validated', async () => {
  const { alice, bob } = await connect();
  await assert.rejects(bob.account.setChatPassword(alice.code, '12345'), RangeError);
  await assert.rejects(bob.account.setChatPassword(alice.code, 123456), TypeError);
  await bob.account.setChatPassword(alice.code, '123456');
  await assert.rejects(bob.account.setChatPassword(alice.code, 'another one'), /already has a password/);
  await assert.rejects(bob.account.changeChatPassword(alice.code, '123456', 'tiny'), RangeError);
});

test('a forgotten chat password is solved by deleting the chat and starting over', async () => {
  const { alice, bob } = await connect();
  await send(alice, bob, 'hello');
  await bob.account.setChatPassword(alice.code, 'soon forgotten');
  await bob.account.lockChat(alice.code);

  await bob.account.deleteChat(alice.code);
  assert.equal(await bob.account.hasChatPassword(alice.code), false);
  assert.equal(await bob.account.hasSession(alice.code), false);

  await bob.account.startSession(alice.code, takeBundle(alice.upload));
  assert.equal(await send(bob, alice, 'fresh start'), 'fresh start');
  assert.equal(await send(alice, bob, 'got it'), 'got it');
});

// --- Attachments -----------------------------------------------------------------

test('attachments are encrypted with AES-256-GCM and tampering is detected', async () => {
  const file = crypto.getRandomValues(new Uint8Array(50_000));
  const { ciphertext, key } = await encryptAttachment(file);
  assert.equal(toBase64(await decryptAttachment(ciphertext, key)), toBase64(file));

  const tampered = ciphertext.slice();
  tampered[100] ^= 1;
  await assert.rejects(decryptAttachment(tampered, key), DecryptionError);
  await assert.rejects(decryptAttachment(ciphertext, (await encryptAttachment(file)).key), DecryptionError);
});
