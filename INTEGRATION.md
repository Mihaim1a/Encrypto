# Encrypto — frontend integration contract

This project is wired to the **actual server and cryptographic modules** from the uploaded `Encrypto-feature-prekey-rollback-hardening.zip`. The separate `doubleCheck(1).zip` has equivalent `crypto/src` files. This is a local-development integration build, not a security audit.

## Launch

```bash
npm run setup
npm start
# http://localhost:3000
```

The server binds `127.0.0.1` (loopback only). Node >=22 is required for `node:sqlite`. A browser with Web Crypto and Web Locks support is required for real mode. The browser must use `localhost` or another secure context to access crypto APIs. The UI mock is available through **Explore interactive demo**, with a conspicuous DEMO MODE warning.

## Paths

| Path | Meaning | Source of contract |
| --- | --- | --- |
| `POST /api/auth/register` | Register `{username,email,password,publicKey}` | `server/src/routes/auth.js` |
| `POST /api/auth/login` | Email/password session login | `server/src/routes/auth.js` |
| `POST /api/auth/logout` | End server session | `server/src/routes/auth.js` |
| `GET /api/me` | Current authenticated account | `server/src/server.js` |
| `GET /api/users/:username/public-key` | Public contact information | `server/src/routes/users.js` |
| `GET/POST /api/chats` | Get chats / create invitation | `server/src/routes/chats.js` |
| `POST /api/chats/:id/accept` | Accept invitation | `server/src/routes/chats.js` |
| `POST /api/chats/:id/decline` | Decline invitation | `server/src/routes/chats.js` |
| `GET /api/keys/status` | Current key enrollment | `server/src/routes/keys.js` |
| `POST /api/keys/challenge` | One-time signing challenge | `server/src/routes/keys.js` |
| `POST /api/keys/upload` | Enroll signed prekeys | `server/src/routes/keys.js` |
| `POST /api/keys/bundle` | Request peer key bundle | `server/src/routes/keys.js` |
| `GET /api/secure-messages/inbox` | Fetch encrypted envelopes | `server/src/routes/secure-messages.js` |
| `POST /api/secure-messages` | Send encrypted envelope | `server/src/routes/secure-messages.js` |
| `POST /api/secure-messages/:id/ack` | Acknowledge a locally captured ciphertext | `server/src/routes/secure-messages.js` |
| `WS /ws` | Message-available notifications | `server/src/realtime.js` |

The UI is served from `/`, frontend assets from `/app/*`, and the exact provided browser-compatible crypto module from `/client-crypto/*`. These are the only server changes needed to serve the rebuilt client. They use same-origin HTTP session cookies and a restrictive Helmet CSP.

## Browser crypto and lifecycle

- `Account.create()` creates a new client-side identity and recovery key.
- Registration sends only the **public** identity key, then logs in and posts an enrollment bundle with signed proof.
- `Account.enableAutoSave(...)` exports encrypted account/ratchet state to the device vault on each committed protocol operation.
- Browser vault passphrase is separate from account password and chat password; it wraps a randomly generated storage key using PBKDF2-SHA256 (600k iterations) + AES-256-GCM. Neither passphrase nor raw key is persisted as plaintext.
- A browser Web Lock disallows concurrent access to the same account across tabs to reduce ratchet state rollback risk.
- Local message history is stored in IndexedDB with encryption and additional conversation sealing through the provided `Account.sealChatData`.
- Incoming ciphertext is stored durably in encrypted IndexedDB before the server ACK. Pending messages remain encrypted while their chat is locked.
- Identity pinning rejects unexpected changes; users must compare contact codes through an external trusted channel before marking contacts verified.
- Backend retains unacknowledged ciphertext for up to 7 days and removes acknowledged message payloads from its active records.

### Known reliability caveat requiring further engineering

Incoming message decryption advances ratchet state. The crypto package auto-saves that state; chat-history persistence is a separate IndexedDB transaction. A crash or storage failure **between ratchet autosave and encrypted history save** can leave a local ciphertext that cannot be decrypted a second time. This is not a verified lossless exactly-once implementation. Before production, the team must design a transactional or recoverable receipt/history persistence protocol and test crash recovery, retry, and browser storage failures. Similarly, browser-based deletion cannot guarantee physical erasure of secrets or remote recipients' copies.

## Feature boundaries

- The **four-digit common chat code** was a planning feature, but the supplied crypto API does not enforce it. It is *not* part of live chat unlocking or encryption in this build.
- **Groups**, group key exchange, **P2P**, screenshot blocking, and customizable disappearing-message expiry are not implemented by the uploaded backend/crypto API. They must not be advertised as live features.
- **Account email**, not username, is used for sign-in; username is used for finding contacts. This reflects the supplied backend.
- The server does not provide a public user directory, password recovery via email, presence statuses, read receipts, or attachments through application endpoints; corresponding fake controls are absent or clearly disabled.
- UI-only demo accounts/messages are in memory, reset on refresh and **not encrypted**.

## Team handoff

- **Frontend**: `client/src/app.js`, `client/src/styles.css`, `client/src/encrypto-overrides.css`, `client/src/services/`
- **Cryptography**: `crypto/src/` (preserved, independent module and unit tests)
- **Backend**: `server/src/routes/`, `server/src/realtime.js`, authentication/session/cookie policies.
- **Integration/testing**: Add full two-account browser E2E tests against a disposable local SQLite database, verify recipient enrollment, first-contact key pinning, permissions, reconnect/recovery, storage-quota failures, CSP/XSS, multi-tab locking, and server restarts.

## Validation in this delivery

- Node syntax checks for JS sources.
- Six standalone frontend source/interface tests.
- All 33 tests provided with the crypto module.
- Chromium desktop/mobile UI simulation (the demo uses a mock API and does not exercise the Express backend).
- **Not tested**: Complete backend integration in this execution environment, because npm package registry access is blocked. Run `npm run setup`, start the server, and run `npm run test:integration` on your development machine. The latter starts with clean disposable test accounts and should never be directed at production data.
