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
await api.register(account.contactCode, await account.createPreKeyUpload());

// Add a contact by code, then send
const code = await normalizeContactCode(userInput);        // throws InvalidCodeError with a user-facing message
await account.startSession(code, await api.fetchBundle(code));
await api.send(code, await account.encrypt(code, 'hello')); // envelope = JSON-safe object

// Receive (`from` is the sender's contact code, as reported by the server)
const isNewConversation = !(await account.hasSession(from));
const text = await account.decrypt(from, envelope);         // fails if `from` didn't really send it

// Persist after EVERY encrypt/decrypt, before sending or displaying
await secureStorage.save(JSON.stringify(await account.exportState()));
const restored = await Account.importState(JSON.parse(await secureStorage.load()));
```

Attachments: encrypt the file with `encryptAttachment(bytes)` → `{ ciphertext, key }`, upload `ciphertext`, then send `{ url, key }` inside a normal message. On the receiving side, call `decryptAttachment(ciphertext, key)`.

### Server (it only handles public data)

| Endpoint | Stores / does |
|---|---|
| register / upload prekeys | Stores `identityKey`, `identityDHKey`, `identityBinding`, `signedPreKey`, and the list of `oneTimePreKeys`, keyed by contact code. After an account restore, **replace** everything; otherwise append one-time prekeys. |
| fetch bundle for a code | Returns the identity fields + `signedPreKey` + **one** one-time prekey, then **deletes that one-time prekey**. Returns `oneTimePreKey: null` when none are left. |
| prekey count | Lets clients top up when they run low: `createPreKeyUpload({ oneTimePreKeyCount: 100 })`. |
| send / receive | Stores and forwards envelopes as opaque JSON. |
| weekly | Clients call `createPreKeyUpload({ oneTimePreKeyCount: 0, rotateSignedPreKey: true })`. |

### Forgotten password → account recovery

```js
// server                                   // client
const challenge = createRecoveryChallenge();  const account = await Account.restore(recoveryKeyTypedByUser);
                                             const sig = await account.signRecoveryChallenge(challenge);
await verifyRecoveryChallenge(contactCode, challenge, sig); // true → allow password reset
```

Issue a new challenge every time and accept each one once. After restoring, the client uploads fresh prekeys (with replace). Old sessions and message history are not recoverable from the key alone. Conversations restart automatically when the restored user sends a message.

## Things the app must handle

- **Protect the stored state.** `exportState()` contains private keys. Store it encrypted (iOS Keychain / Android Keystore, or a key derived from the user's password) and never upload it.
- **Save the state after every `encrypt`/`decrypt`.** If an older state is reloaded, messages can fail to decrypt. Security still holds: AES-GCM uses a fresh random IV every time, so a key used twice is not catastrophic.
- **`NoSessionError` on receive** usually means the sender's device was restored or reinstalled. Fetch their bundle, call `startSession`, and send a message: that resets the conversation on both sides.
- **Errors to show the user**: `InvalidCodeError` (bad code), `UntrustedIdentityError` (keys don't match the code: possible attack, do not continue), `DecryptionError` (corrupted, forged or duplicate message).

## Not covered yet (worth planning for)

- **Independent security review.** This follows the published Signal specifications and is tested, but has not been audited. Get it reviewed before launch.
- **Post-quantum protection.** Signal now adds ML-KEM to the key agreement (PQXDH) and to the ratchet. Web Crypto doesn't ship ML-KEM widely yet.
- **Metadata.** The server still sees who talks to whom, and when (Signal hides senders with "sealed sender").
- **Multi-device and group chats.** One account = one device here. Groups would need sender keys or one-to-one fan-out.
- **React Native** has no built-in Web Crypto. It needs a polyfill with X25519 and Ed25519 support.

## Files

| File | Contents |
|---|---|
| `src/account.js` | `Account`: the on-device API (keys, prekeys, sessions, encrypt/decrypt, persistence) |
| `src/ratchet.js` | Double Ratchet session |
| `src/x3dh.js` | X3DH key agreement and prekey bundle verification |
| `src/keys.js` | Recovery key, identity derivation, contact codes, recovery challenge |
| `src/attachments.js` | Attachment encryption |
| `src/primitives.js` | Web Crypto wrappers (X25519, Ed25519, HKDF, HMAC, AES-256-GCM) |
| `src/encoding.js` | base64 / base32 / UTF-8 helpers |
| `test/protocol.test.js` | 16 tests: replay, tampering, MITM, spoofing, out-of-order, recovery, persistence |
| `examples/demo.js` | Walkthrough with a fake server |
