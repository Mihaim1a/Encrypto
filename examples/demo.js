/**
 * End-to-end walkthrough: sign-up, adding a contact by code, messaging, an encrypted
 * attachment, and recovering a forgotten-password account with the recovery key.
 *
 * DemoServer stands in for your backend. Notice that it only ever stores public keys and
 * ciphertext: it has nothing it could decrypt messages with.
 */
import {
  Account,
  createRecoveryChallenge,
  decryptAttachment,
  encryptAttachment,
  normalizeContactCode,
  verifyRecoveryChallenge,
} from '../src/index.js';

class DemoServer {
  #users = new Map(); // contact code -> { bundle, oneTimePreKeys }
  #inboxes = new Map(); // contact code -> [{ from, envelope }]
  #challenges = new Map(); // contact code -> pending challenge

  uploadPreKeys(contactCode, upload, { replace = false } = {}) {
    const { oneTimePreKeys, ...bundle } = upload;
    const existing = this.#users.get(contactCode);
    if (!existing || replace) this.#users.set(contactCode, { bundle, oneTimePreKeys: [...oneTimePreKeys] });
    else existing.oneTimePreKeys.push(...oneTimePreKeys);
  }

  fetchBundle(contactCode) {
    const user = this.#users.get(contactCode);
    if (!user) throw new Error('No such user');
    return { ...user.bundle, oneTimePreKey: user.oneTimePreKeys.shift() ?? null }; // each OPK is handed out once
  }

  send(from, to, envelope) {
    const stored = JSON.stringify(envelope);
    console.log(`  [server] stored ${stored.length} bytes for ${to.slice(0, 11)}…: ${stored.slice(0, 110)}…`);
    if (!this.#inboxes.has(to)) this.#inboxes.set(to, []);
    this.#inboxes.get(to).push({ from, envelope: JSON.parse(stored) });
  }

  receive(contactCode) {
    const messages = this.#inboxes.get(contactCode) ?? [];
    this.#inboxes.set(contactCode, []);
    return messages;
  }

  startRecovery(contactCode) {
    const challenge = createRecoveryChallenge();
    this.#challenges.set(contactCode, challenge);
    return challenge;
  }

  async finishRecovery(contactCode, signature) {
    const challenge = this.#challenges.get(contactCode);
    this.#challenges.delete(contactCode); // single use
    return challenge !== undefined && verifyRecoveryChallenge(contactCode, challenge, signature);
  }
}

async function deliver(server, account) {
  for (const { from, envelope } of server.receive(account.contactCode)) {
    const isNew = !(await account.hasSession(from));
    const text = await account.decrypt(from, envelope);
    console.log(`  ${isNew ? '(new conversation) ' : ''}decrypted on device: "${text}"`);
  }
}

const server = new DemoServer();

console.log('\n1. Alice and Bob sign up');
const { account: alice, recoveryKey: aliceRecoveryKey } = await Account.create();
const { account: bob } = await Account.create();
server.uploadPreKeys(alice.contactCode, await alice.createPreKeyUpload());
server.uploadPreKeys(bob.contactCode, await bob.createPreKeyUpload());
console.log(`  Alice's contact code (share this): ${alice.contactCode}`);
console.log(`  Alice's recovery key (keep secret): ${aliceRecoveryKey}`);
console.log(`  Bob's contact code:                 ${bob.contactCode}`);

console.log('\n2. Alice pastes Bob\'s contact code and sends a message');
const bobCode = await normalizeContactCode(bob.contactCode.toLowerCase()); // users may paste it in any case
await alice.startSession(bobCode, server.fetchBundle(bobCode));
server.send(alice.contactCode, bobCode, await alice.encrypt(bobCode, 'Hi Bob! This is end-to-end encrypted.'));
await deliver(server, bob);

console.log('\n3. Bob replies');
server.send(bob.contactCode, alice.contactCode, await bob.encrypt(alice.contactCode, 'Hi Alice! Nobody else can read this.'));
await deliver(server, alice);

console.log('\n4. Alice sends a photo');
const photo = new TextEncoder().encode('...pretend these are JPEG bytes...');
const { ciphertext, key } = await encryptAttachment(photo);
const blobUrl = 'https://cdn.example/blob/123'; // the server stores only `ciphertext`
const pointer = JSON.stringify({ type: 'image', url: blobUrl, key });
server.send(alice.contactCode, bobCode, await alice.encrypt(bobCode, pointer));
for (const { from, envelope } of server.receive(bobCode)) {
  const message = JSON.parse(await bob.decrypt(from, envelope));
  const bytes = await decryptAttachment(ciphertext, message.key);
  console.log(`  Bob decrypted the attachment: "${new TextDecoder().decode(bytes)}"`);
}

console.log('\n5. Alice forgets her password and recovers with her recovery key');
const restoredAlice = await Account.restore(aliceRecoveryKey);
const challenge = server.startRecovery(restoredAlice.contactCode);
const ok = await server.finishRecovery(restoredAlice.contactCode, await restoredAlice.signRecoveryChallenge(challenge));
console.log(`  Server verified ownership: ${ok}; same contact code: ${restoredAlice.contactCode === alice.contactCode}`);
server.uploadPreKeys(restoredAlice.contactCode, await restoredAlice.createPreKeyUpload(), { replace: true });

await restoredAlice.startSession(bobCode, server.fetchBundle(bobCode));
server.send(restoredAlice.contactCode, bobCode, await restoredAlice.encrypt(bobCode, 'New phone, same me.'));
await deliver(server, bob);
server.send(bob.contactCode, restoredAlice.contactCode, await bob.encrypt(restoredAlice.contactCode, 'Welcome back!'));
await deliver(server, restoredAlice);
console.log('\nDone.');
