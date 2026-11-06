# secure-messaging-crypto

End-to-end encryption for the messenger. It follows the design Signal uses:

| Layer | What it does | Primitive |
|---|---|---|
| **X3DH** key agreement | Starts a conversation with someone who is offline, using prekeys they uploaded earlier | X25519, Ed25519 signatures, HKDF-SHA-256 |
| **Double Ratchet** | Gives every message a new key. Old keys are deleted (forward secrecy), and the conversation heals after a key leak (post-compromise security) | HKDF-SHA-256, HMAC-SHA-256, X25519 |
| **Message encryption** | Encrypts and authenticates each message, its header and both identities | **AES-256-GCM** |

All encryption and decryption happens on the device. The server stores and relays public keys and ciphertext only. It cannot read messages, forge them, or fake who sent them.

The library has no dependencies. It uses the platform's native Web Crypto API (`crypto.subtle`), so it runs in **Node.js 20+, current browsers and Electron**.

```bash
npm test        # node --test
npm run demo    # full walkthrough with a fake server
```

## The two user keys

```
recovery key (PRIVATE)  ──HKDF──►  identity keys  ──►  contact code (PUBLIC)
A8YDF-GWGRS-…-MDCWG                Ed25519 + X25519     8FXZ2-E9AF1-…-BE2XG
```

- **Contact code** (public, starts with `8`). This is the key users share. Paste someone's code into "add contact" and a DM is created. The server looks up that person's keys, and the app checks that they match the pasted code. A compromised server therefore cannot man-in-the-middle the conversation. Codes are shared out of band (QR code, another chat, in person), not through our server.
- **Recovery key** (private, starts with `A`). It is shown once at sign-up and the user writes it down. The identity is *derived* from it, so entering it on a new device recreates exactly the same identity and contact code. No key backup is stored on the server. It also lets a user who forgot their password prove ownership of the account (see below).

Both codes have a checksum, so typos are caught. Each code also has a type marker: if a user pastes their recovery key into the contact field, it is rejected with a warning and never sent anywhere.

## Integration

### Client

```js
import { Account, normalizeContactCode } from './src/index.js';

// Sign-up
const { account, recoveryKey } = await Account.create();
showOnceAndAskUserToWriteDown(recoveryKey);
const storageKey = Account.generateStorageKey();            // keep in iOS Keychain / Android Keystore
await keystore.set('storageKey', storageKey);
await account.enableAutoSave({ storageKey, save: (blob) => files.write('account.bin', blob) });
await api.register(account.contactCode, await account.createPreKeyUpload());

// App start
const account = await Account.importState(await files.read('account.bin'), await keystore.get('storageKey'));
await account.enableAutoSave({ storageKey, save });
if (account.getPreKeyStatus().signedPreKeyRotationDue) {
  await api.uploadPreKeys(await account.createPreKeyUpload({ oneTimePreKeyCount: 0 })); // rotates
}

// Add a contact by code, then send
const code = await normalizeContactCode(userInput);        // throws InvalidCodeError with a user-facing message
await account.startSession(code, await api.fetchBundle(code));
await api.send(code, await account.encrypt(code, 'hello')); // envelope = JSON-safe object

// Receive (`from` is the sender's contact code, as reported by the server)
const isNewConversation = !(await account.hasSession(from));
const text = await account.decrypt(from, envelope);         // fails if `from` didn't really send it
await api.ack(envelope);                                    // only now delete it from the server
```

### Saving state (persistence rules)

- **The private state only leaves the library encrypted.** `exportState(storageKey)` and auto-save produce an AES-256-GCM blob. The 256-bit storage key comes from `Account.generateStorageKey()` and belongs in the platform key store. The blob itself can go in a normal file or database. There is no way to export the keys unencrypted.
- **Auto-save defines the boundary.** With `enableAutoSave`, every call that changes state saves the new state before it returns: `encrypt`, `decrypt`, `startSession`, `createPreKeyUpload`, chat password changes and `deleteChat`. So:
  - an envelope is only handed out after the state that produced it is saved, so it's safe to send;
  - a message is only returned after the state that used up its key is saved, so it's safe to show it and acknowledge it to the server;
  - new prekeys are only returned after their private halves are saved, so they're safe to upload.
- **If saving fails**, the call is undone in memory and throws `PersistenceError`, so just retry it. For `decrypt`, retry with the same envelope, which is why the server copy should only be deleted after a successful decrypt.
- **Loading checks everything.** `importState` verifies that every key pair matches, every signature verifies, every number is in range, and that no password-protected chat is stored in the clear. Anything wrong throws `InvalidStateError`. A wrong storage key or altered blob is refused the same way.
- **Replay protection.** The state remembers every first message accepted on each signed prekey, so an old first message can never be accepted twice, even after the chat was deleted. The list is dropped when the signed prekey is rotated out, and from then on such messages are refused anyway.

Attachments: encrypt the file with `encryptAttachment(bytes)` → `{ ciphertext, key }`, upload `ciphertext`, then send `{ url, key }` inside a normal message. On the receiving side, call `decryptAttachment(ciphertext, key)`.

### Chat passwords (optional, per chat)

Any chat can get its own password, chosen by the user (at least 6 characters). It is independent of the login password and of every other chat's password. It never leaves the device, and the server can't tell which chats have one.

```js
await account.setChatPassword(code, 'pick-anything');   // chat stays unlocked for now
await account.lockChat(code);                           // or lockAllChats() when the app goes to background
await account.unlockChat(code, password);               // WrongPasswordError if wrong; call it every time the chat is opened
await account.changeChatPassword(code, oldPassword, newPassword);
await account.removeChatPassword(code, password);
await account.hasChatPassword(code);  await account.isChatLocked(code);

// Store the chat's history/drafts encrypted with the chat's key (only while unlocked)
const blob = await account.sealChatData(code, JSON.stringify(messages));
const messages = JSON.parse(await account.openChatData(code, blob));
```

How it works: the password goes through PBKDF2-SHA-256 (600,000 rounds, random salt). The result unlocks a random 256-bit chat key, and that key encrypts the chat's ratchet sessions and anything stored with `sealChatData`.
- **While locked**, the chat's keys exist only in encrypted form. `encrypt`/`decrypt` throw `ChatLockedError`, so keep incoming envelopes queued (they're still encrypted) and decrypt them after `unlockChat`.
- **After an app restart**, every password-protected chat starts locked. `exportState()` never contains protected chats in the clear, even while they're unlocked.
- **Changing the password** keeps the same chat key, so previously sealed data stays readable. **Removing it** keeps the key as well.
- **Forgotten chat password**: it can't be recovered, which is the point of the lock. `deleteChat(code)` erases the chat, and a new conversation can then be started with the same contact.
- **Store history with `sealChatData`**. Otherwise the chat password only protects the keys, not the messages already shown. Rate-limit wrong attempts in the UI, too: a short password can be guessed offline by someone who copies the device's storage.

### Server (it only handles public data)

| Endpoint | Stores / does |
|---|---|
| register / upload prekeys | Stores `identityKey`, `identityDHKey`, `identityBinding`, `signedPreKey`, and the list of `oneTimePreKeys`, keyed by contact code. After an account restore, **replace** everything; otherwise append one-time prekeys. |
| fetch bundle for a code | Returns the identity fields + `signedPreKey` + **one** one-time prekey, then **deletes that one-time prekey**. Returns `oneTimePreKey: null` when none are left. |
| prekey count | Lets clients top up when they run low: `createPreKeyUpload({ oneTimePreKeyCount: 100 })`. Each upload's `signedPreKey` becomes the current one. |
| send / receive | Stores and forwards envelopes as opaque JSON; deletes one only when the recipient acknowledges it. |
| signed prekey rotation | Automatic: `createPreKeyUpload` rotates when `getPreKeyStatus().signedPreKeyRotationDue` (after 7 days, or 5,000 new conversations). The last 4 are kept for messages already on their way. |
| rate limiting | Limit how many prekey bundles and first messages one user can request or send. The device remembers every accepted first message for replay protection, so a flood would fill that list. |

### Forgotten password → account recovery

```js
// server                                   // client
const challenge = createRecoveryChallenge();  const account = await Account.restore(recoveryKeyTypedByUser);
                                             const sig = await account.signRecoveryChallenge(challenge);
await verifyRecoveryChallenge(contactCode, challenge, sig); // true → allow password reset
```

Issue a new challenge every time and accept each one once. After restoring, the client uploads fresh prekeys (with replace). Old sessions and message history are not recoverable from the key alone. Conversations restart automatically when the restored user sends a message.

## Things the app must handle

- **Keep the storage key in the platform key store** and never upload it or the state blob. Losing the storage key means losing the local state (identity can still be restored with the recovery key).
- **Turn on auto-save** right after creating or loading the account (see "Saving state"). If an older state is ever reloaded, messages can fail to decrypt. Security still holds: AES-GCM uses a fresh random IV every time.
- **`NoSessionError` on receive** usually means the sender's device was restored or reinstalled. Fetch their bundle, call `startSession`, and send a message: that resets the conversation on both sides.
- **Errors to show the user**: `InvalidCodeError` (bad code), `UntrustedIdentityError` (keys don't match the code: possible attack, do not continue), `DecryptionError` (corrupted, forged or duplicate message), `ChatLockedError` (chat needs its password first), `WrongPasswordError` (wrong chat password), `PersistenceError` (saving failed, call was undone, retry), `InvalidStateError` (saved state can't be loaded).

## Not covered yet (worth planning for)

- **Independent security review.** This follows the published Signal specifications and is tested, but has not been audited. Get it reviewed before launch.
- **Post-quantum protection.** Signal now adds ML-KEM to the key agreement (PQXDH) and to the ratchet. Web Crypto doesn't ship ML-KEM widely yet.
- **Metadata.** The server still sees who talks to whom, and when (Signal hides senders with "sealed sender").
- **Multi-device and group chats.** One account = one device here. Groups would need sender keys or one-to-one fan-out.
- **React Native** has no built-in Web Crypto. It needs a polyfill with X25519 and Ed25519 support.

## Files

| File | Contents |
|---|---|
| `src/account.js` | `Account`: the on-device API (keys, prekeys, sessions, encrypt/decrypt, chat passwords, persistence) |
| `src/chat-lock.js` | Per-chat passwords: PBKDF2 key derivation and chat-key wrapping |
| `src/state.js` | Encrypted state blobs, storage keys, and validation of loaded state |
| `src/ratchet.js` | Double Ratchet session |
| `src/x3dh.js` | X3DH key agreement and prekey bundle verification |
| `src/keys.js` | Recovery key, identity derivation, contact codes, recovery challenge |
| `src/attachments.js` | Attachment encryption |
| `src/primitives.js` | Web Crypto wrappers (X25519, Ed25519, HKDF, HMAC, PBKDF2, AES-256-GCM) |
| `src/encoding.js` | base64 / base32 / UTF-8 helpers |
| `test/protocol.test.js` | 30 tests: replay (incl. first messages), tampering, MITM, spoofing, reflection, invalid keys, skip limits, out-of-order, rotation, recovery, encrypted persistence and rollback, chat passwords |
| `examples/demo.js` | Walkthrough with a fake server |
