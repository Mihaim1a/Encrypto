import assert from 'node:assert/strict';
import { test } from 'node:test';

import { fromBase64, toBase64 } from '../src/encoding.js';
import {
  Account,
  DecryptionError,
  InvalidCodeError,
  NoSessionError,
  UntrustedIdentityError,
  createRecoveryChallenge,
  decryptAttachment,
  encryptAttachment,
  normalizeContactCode,
  verifyRecoveryChallenge,
} from '../src/index.js';

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

function flipBit(base64, index) {
  const bytes = fromBase64(base64);
  bytes[index] ^= 1;
  return toBase64(bytes);
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

test('sessions work without a one-time prekey and after a signed prekey rotation', async () => {
  const alice = await signUp();
  const bob = await signUp();
  const oldBundle = takeBundle(bob.upload, { withOneTimePreKey: false });
  await bob.account.createPreKeyUpload({ oneTimePreKeyCount: 0, rotateSignedPreKey: true });

  await alice.account.startSession(bob.code, oldBundle);
  assert.equal(await send(alice, bob, 'sent with an old bundle'), 'sent with an old bundle');
  assert.equal(await send(bob, alice, 'got it'), 'got it');
});

test('concurrent calls never reuse a message key', async () => {
  const { alice, bob } = await connect();
  const envelopes = await Promise.all(Array.from({ length: 10 }, (_, i) => alice.account.encrypt(bob.code, `c${i}`)));
  assert.equal(new Set(envelopes.map((e) => e.header)).size, 10);
  const plaintexts = await Promise.all(envelopes.map((e) => bob.account.decrypt(alice.code, e)));
  assert.equal(plaintexts.join(','), Array.from({ length: 10 }, (_, i) => `c${i}`).join(','));
});

test('state can be saved and loaded mid-conversation', async () => {
  const { alice, bob } = await connect();
  await send(alice, bob, 'before save');
  await send(bob, alice, 'reply before save');
  const pending = await alice.account.encrypt(bob.code, 'in flight during save');

  const bobState = JSON.parse(JSON.stringify(await bob.account.exportState()));
  const aliceState = JSON.parse(JSON.stringify(await alice.account.exportState()));
  const bob2 = { account: await Account.importState(bobState), code: bob.code };
  const alice2 = { account: await Account.importState(aliceState), code: alice.code };
  assert.equal(bob2.account.contactCode, bob.code);

  assert.equal(await bob2.account.decrypt(alice.code, pending), 'in flight during save');
  assert.equal(await send(bob2, alice2, 'after load'), 'after load');
  assert.equal(await send(alice2, bob2, 'after load too'), 'after load too');
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
