# Encrypto

End-to-end encrypted messaging website. Messages are encrypted and decrypted in the browser; the server only stores public keys and ciphertext.

## Repository layout

| Folder / file | Contents |
|---|---|
| `crypto/` | The encryption library (X3DH, Double Ratchet, AES-256-GCM). This is the **only** copy: the server and the browser both use it from here. See `crypto/README.md`. |
| `server/` | Node.js / Express backend with SQLite: accounts, key management, chats, encrypted message delivery, WebSocket notifications. Serves `crypto/src/` to the browser at `/client-crypto`. |
| `tests/` | Backend integration tests. They run against a local server. |
| `frontend.html` | The website (currently a visual demo, not yet connected to the API). |

## Running the tests

Requires Node.js 22.13 or newer.

```bash
# Crypto library
cd crypto
npm test

# Backend (from the repository root)
npm --prefix server ci
npm --prefix server start          # terminal 1
node tests/key-enrollment.mjs      # terminal 2
node tests/e2ee-integration.mjs
node tests/prekey-rollback.mjs
```

The API is rate-limited, so running all suites back to back can return HTTP 429. Restart the server between suites if that happens.
