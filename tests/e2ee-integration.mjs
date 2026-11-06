
import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";
import { Account } from "../crypto/src/index.js";
import { createRequire } from "node:module";

const requireFromServer = createRequire(
    new URL("../server/package.json", import.meta.url)
);

const WebSocket = requireFromServer("ws");

const BASE_URL = "http://localhost:3000";
const PASSWORD = "TemporaryTestPassword123!";

async function api(method, endpoint, body, cookie) {
    const response = await fetch(BASE_URL + endpoint, {
        method,
        headers: {
            ...(body !== undefined
                ? { "Content-Type": "application/json" }
                : {}),
            ...(cookie ? { Cookie: cookie } : {})
        },
        body: body === undefined
            ? undefined
            : JSON.stringify(body)
    });

    const data = await response.json();

    if (!response.ok) {
        throw new Error(
            `${method} ${endpoint}: HTTP ${response.status} ` +
            JSON.stringify(data)
        );
    }

    return { data, response };
}

async function createTestUser(label, suffix) {
    const username = `e2ee_${label}_${suffix}`;
    const email = `${username}@example.test`;

    const { account } = await Account.create();

    const bundle = await account.createPreKeyUpload({
        oneTimePreKeyCount: 4
    });

    await api("POST", "/api/auth/register", {
        username,
        email,
        password: PASSWORD,
        publicKey: bundle.identityKey
    });

    const login = await api("POST", "/api/auth/login", {
        email,
        password: PASSWORD
    });

    const cookie = login.response.headers
        .get("set-cookie")?.split(";")[0];

    assert.ok(cookie, "Missing authentication cookie");

    const ticket = await api(
        "POST",
        "/api/keys/challenge",
        {},
        cookie
    );

    const proof = await account.signRecoveryChallenge(
        ticket.data.challenge
    );

    await api("POST", "/api/keys/upload", {
        bundle,
        contactCode: account.contactCode,
        challenge: ticket.data.challenge,
        proof
    }, cookie);

    const status = await api(
        "GET",
        "/api/keys/status",
        undefined,
        cookie
    );

    assert.equal(status.data.enrolled, true);
    assert.equal(status.data.oneTimePreKeys, 4);

    return {
        username,
        account,
        cookie,
        userId: login.data.user.id
    };
}

async function main() {
    const suffix = randomBytes(4).toString("hex");

    console.log("1. Creating Alice's real cryptographic identity...");
    const alice = await createTestUser("a", suffix);

    console.log("2. Creating Bob's real cryptographic identity...");
    const bob = await createTestUser("b", suffix);

    console.log("3. Creating chat invitation...");

    const invitation = await api(
        "POST",
        "/api/chats",
        { recipientUsername: bob.username },
        alice.cookie
    );

    const chatId = invitation.data.chatId;

    assert.equal(invitation.data.status, "pending");

    console.log("4. Bob accepts the invitation...");

    const accepted = await api(
        "POST",
        `/api/chats/${chatId}/accept`,
        {},
        bob.cookie
    );

    assert.equal(accepted.data.status, "active");

    console.log("5. Alice retrieves Bob's real X3DH bundle...");

    const bundleResponse = await api(
        "POST",
        "/api/keys/bundle",
        { contactCode: bob.account.contactCode },
        alice.cookie
    );

    const bobBundle = bundleResponse.data;

    assert.ok(bobBundle.identityKey);
    assert.ok(bobBundle.signedPreKey);
    assert.ok(bobBundle.oneTimePreKey);

    console.log("6. Alice starts a real X3DH session...");

    await alice.account.startSession(
        bob.account.contactCode,
        bobBundle
    );

    assert.equal(
        await alice.account.hasSession(bob.account.contactCode),
        true
    );

    console.log("7. Alice encrypts Hello Bob...");

    const originalMessage = "Hello Bob";

    const envelope = await alice.account.encrypt(
        bob.account.contactCode,
        originalMessage
    );

    assert.equal(envelope.version, 1);
    assert.equal(envelope.type, "prekey");

    const messageBody = {
        chatId,
        clientMessageId: randomUUID(),
        envelope
    };

    assert.equal(
        JSON.stringify(messageBody).includes(originalMessage),
        false
    );

    console.log("8. Sending ciphertext through the server...");

    const sent = await api(
        "POST",
        "/api/secure-messages",
        messageBody,
        alice.cookie
    );

    assert.equal(
        sent.data.message,
        "Encrypted message stored"
    );

    console.log("9. Bob retrieves the encrypted message...");

    const inbox = await api(
        "GET",
        "/api/secure-messages/inbox",
        undefined,
        bob.cookie
    );

    const received = inbox.data.messages.find(
        m => m.id === sent.data.messageId
    );

    assert.ok(received, "Bob did not receive the message");

    assert.equal(received.senderId, alice.userId);
    assert.equal(received.recipientId, bob.userId);
    assert.equal(received.chatId, chatId);

    console.log("10. Bob decrypts using his PRIVATE keys...");

    const decryptedMessage = await bob.account.decrypt(
        alice.account.contactCode,
        received.envelope
    );

    assert.equal(decryptedMessage, originalMessage);

    console.log("11. Exporting Alice and Bob's cryptographic states...");

    const aliceState = await alice.account.exportState();
    const bobState = await bob.account.exportState();

    console.log("12. Restoring both accounts...");

    const aliceRestored = await Account.importState(aliceState);
    const bobRestored = await Account.importState(bobState);

    assert.equal(
        aliceRestored.contactCode,
        alice.account.contactCode
    );

    assert.equal(
        bobRestored.contactCode,
        bob.account.contactCode
    );

    console.log("13. Bob encrypts a reply...");

    const replyText = "Hey Alice!";

    const replyEnvelope = await bobRestored.encrypt(
        aliceRestored.contactCode,
        replyText
    );

    assert.equal(replyEnvelope.version, 1);
    assert.equal(replyEnvelope.type, "message");

    console.log("14. Bob sends his encrypted reply...");

    const reply = await api(
        "POST",
        "/api/secure-messages",
        {
            chatId,
            clientMessageId: randomUUID(),
            envelope: replyEnvelope
        },
        bob.cookie
    );

    assert.equal(
        reply.data.message,
        "Encrypted message stored"
    );

    console.log("15. Alice retrieves Bob's reply...");

    const aliceInbox = await api(
        "GET",
        "/api/secure-messages/inbox",
        undefined,
        alice.cookie
    );

    const receivedReply = aliceInbox.data.messages.find(
        m => m.id === reply.data.messageId
    );

    assert.ok(
        receivedReply,
        "Alice did not receive Bob's reply"
    );

    assert.equal(receivedReply.senderId, bob.userId);

    console.log("16. Alice decrypts Bob's reply...");

    const decryptedReply = await aliceRestored.decrypt(
        bobRestored.contactCode,
        receivedReply.envelope
    );

    assert.equal(decryptedReply, replyText);

    // =====================================================
    // TEST 16A - ENCRYPTED MESSAGE DELETION
    // =====================================================

    console.log("16A. Testing encrypted-message deletion...");

    const retentionInbox = await api(
        "GET",
        "/api/secure-messages/inbox",
        undefined,
        bob.cookie
    );

    const retentionMessage = retentionInbox.data.messages.find(
        message => message.senderId === alice.userId
    );

    assert.ok(
        retentionMessage,
        "Expected Alice's pending encrypted message"
    );

    const retentionAck = await api(
        "POST",
        `/api/secure-messages/${retentionMessage.id}/ack`,
        {},
        bob.cookie
    );

    assert.equal(
        retentionAck.data.ciphertextDeleted,
        true
    );

    console.log("Message acknowledgement: PASSED");

    const retentionDb = requireFromServer("./src/database");

    const storedMessage = retentionDb.prepare(`
        SELECT
            envelope_json,
            envelope_hash,
            acknowledged_at,
            purged_at
        FROM secure_messages
        WHERE id = ?
    `).get(retentionMessage.id);

    assert.ok(storedMessage);
    assert.equal(storedMessage.envelope_json, "");
    assert.ok(storedMessage.envelope_hash);
    assert.ok(storedMessage.acknowledged_at);
    assert.ok(storedMessage.purged_at);

    console.log(
        "Ciphertext cleared from active database row: PASSED"
    );

    const inboxAfterAck = await api(
        "GET",
        "/api/secure-messages/inbox",
        undefined,
        bob.cookie
    );

    assert.equal(
        inboxAfterAck.data.messages.some(
            message => message.id === retentionMessage.id
        ),
        false
    );

    console.log(
        "Acknowledged message removed from inbox: PASSED"
    );

    const secondAck = await api(
        "POST",
        `/api/secure-messages/${retentionMessage.id}/ack`,
        {},
        bob.cookie
    );

    assert.equal(
        secondAck.data.message,
        "Already acknowledged"
    );

    console.log("Repeated acknowledgement: PASSED");

    const duplicateAfterAck = await api(
        "POST",
        "/api/secure-messages",
        {
            chatId: retentionMessage.chatId,
            clientMessageId: retentionMessage.clientMessageId,
            envelope: retentionMessage.envelope
        },
        alice.cookie
    );

    assert.equal(duplicateAfterAck.data.duplicate, true);

    assert.equal(
        duplicateAfterAck.data.messageId,
        retentionMessage.id
    );

    console.log("Duplicate retry after deletion: PASSED");
    console.log("MESSAGE DELETION TESTS PASSED!");

    // =====================================================
    // TEST 16B - UNAUTHORIZED ACKNOWLEDGEMENT
    // =====================================================

    console.log(
        "16B. Testing unauthorized message acknowledgement..."
    );

    await assert.rejects(
        () => api(
            "POST",
            `/api/secure-messages/${receivedReply.id}/ack`,
            {},
            bob.cookie
        ),
        /HTTP 404/
    );

    console.log("Unauthorized acknowledgement: BLOCKED");

    const protectedMessage = retentionDb.prepare(`
        SELECT envelope_json, acknowledged_at
        FROM secure_messages
        WHERE id = ?
    `).get(receivedReply.id);

    assert.ok(protectedMessage);
    assert.ok(protectedMessage.envelope_json.length > 0);
    assert.equal(protectedMessage.acknowledged_at, null);

    console.log("Ciphertext remained intact: PASSED");
    console.log("UNAUTHORIZED ACK SECURITY TEST PASSED!");

    // =====================================================
    // TEST 16C - MESSAGE EXPIRATION
    // =====================================================

    console.log("16C. Testing message expiration...");

    const expiredMessageId = receivedReply.id;
    const expiredAt = Date.now() - 1000;

    const expirationUpdate = retentionDb.prepare(`
        UPDATE secure_messages
        SET expires_at = ?
        WHERE id = ?
          AND recipient_id = ?
          AND acknowledged_at IS NULL
    `).run(
        expiredAt,
        expiredMessageId,
        alice.userId
    );

    assert.equal(expirationUpdate.changes, 1);

    console.log("Message expiration simulated: PASSED");

    const expiredInbox = await api(
        "GET",
        "/api/secure-messages/inbox",
        undefined,
        alice.cookie
    );

    assert.equal(
        expiredInbox.data.messages.some(
            message => message.id === expiredMessageId
        ),
        false
    );

    console.log("Expired message hidden from inbox: PASSED");

    await assert.rejects(
        () => api(
            "POST",
            `/api/secure-messages/${expiredMessageId}/ack`,
            {},
            alice.cookie
        ),
        /HTTP 410/
    );

    console.log("Expired message acknowledgement: BLOCKED");

    // The scheduler may already have removed the ciphertext.
    const expiredRecord = retentionDb.prepare(`
        SELECT
            envelope_json,
            expires_at,
            acknowledged_at,
            purged_at
        FROM secure_messages
        WHERE id = ?
    `).get(expiredMessageId);

    assert.ok(expiredRecord);
    assert.ok(expiredRecord.expires_at <= Date.now());
    assert.equal(expiredRecord.acknowledged_at, null);

    if (expiredRecord.envelope_json === "") {
        assert.ok(expiredRecord.purged_at);

        console.log(
            "Expired ciphertext cleared by cleanup: PASSED"
        );
    } else {
        assert.equal(expiredRecord.purged_at, null);

        console.log(
            "Expired ciphertext awaiting cleanup: CONFIRMED"
        );
    }

    console.log("MESSAGE EXPIRATION TESTS PASSED!");

    // =====================================================
    // TEST 17 - REPLAY ATTACK
    // =====================================================

    console.log("17. Testing replay attack protection...");

    await assert.rejects(
        () => aliceRestored.decrypt(
            bobRestored.contactCode,
            receivedReply.envelope
        ),
        { name: "DecryptionError" }
    );

    console.log("Replay attack: BLOCKED");

    // =====================================================
    // TEST 18 - CIPHERTEXT TAMPERING
    // =====================================================

    console.log("18. Testing ciphertext tampering...");

    const genuine = await bobRestored.encrypt(
        aliceRestored.contactCode,
        "Integrity test"
    );

    const tampered = structuredClone(genuine);

    const bytes = Buffer.from(
        tampered.ciphertext,
        "base64"
    );

    bytes[bytes.length - 1] ^= 1;

    tampered.ciphertext = bytes.toString("base64");

    await assert.rejects(
        () => aliceRestored.decrypt(
            bobRestored.contactCode,
            tampered
        ),
        { name: "DecryptionError" }
    );

    console.log("Ciphertext tampering: BLOCKED");

    const verified = await aliceRestored.decrypt(
        bobRestored.contactCode,
        genuine
    );

    assert.equal(verified, "Integrity test");

    console.log("Valid message after tampering: DECRYPTED");
    console.log("REPLAY AND TAMPERING TESTS PASSED!");

    // =====================================================
    // TEST 19 - MALICIOUS ORIGIN
    // =====================================================

    console.log(
        "19. Testing authenticated cross-origin protection..."
    );

    const maliciousResponse = await fetch(
        "http://localhost:3000/api/keys/challenge",
        {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Origin": "https://evil.example",
                "Cookie": alice.cookie
            },
            body: "{}"
        }
    );

    assert.equal(maliciousResponse.status, 403);

    console.log(
        "Authenticated malicious-origin request: BLOCKED"
    );

    // =====================================================
    // TEST 20 - TRUSTED ORIGIN
    // =====================================================

    console.log(
        "20. Testing authenticated trusted-origin request..."
    );

    const trustedResponse = await fetch(
        "http://localhost:3000/api/keys/challenge",
        {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Origin": "http://localhost:3000",
                "Cookie": alice.cookie
            },
            body: "{}"
        }
    );

    assert.equal(trustedResponse.status, 200);

    console.log(
        "Authenticated trusted-origin request: ALLOWED"
    );

    console.log("HTTP ORIGIN SECURITY TESTS PASSED!");

    // =====================================================
    // TEST 23 - OPEN WEBSOCKET BEFORE LOGOUT
    // =====================================================

    console.log(
        "23. Opening Alice's WebSocket before logout..."
    );

    const aliceSocket = new WebSocket(
        "ws://127.0.0.1:3000/ws",
        {
            headers: {
                Origin: "http://localhost:3000",
                Cookie: alice.cookie
            }
        }
    );

    await new Promise((resolve, reject) => {
        const timeout = setTimeout(() => {
            aliceSocket.terminate();

            reject(new Error(
                "WebSocket connection timed out"
            ));
        }, 10000);

        aliceSocket.once("open", () => {
            clearTimeout(timeout);
            resolve();
        });

        aliceSocket.once("error", error => {
            clearTimeout(timeout);
            reject(error);
        });
    });

    console.log("Alice's WebSocket connected.");

    let unexpectedNotification = false;

    const socketClosed = new Promise((resolve, reject) => {
        const timeout = setTimeout(() => {
            aliceSocket.terminate();

            reject(new Error(
                "Revoked WebSocket remained open too long"
            ));
        }, 40000);

        aliceSocket.on("message", data => {
            try {
                const event = JSON.parse(
                    data.toString()
                );

                if (event.type === "message_available") {
                    unexpectedNotification = true;
                }
            } catch {
                // Ignore unrelated messages.
            }
        });

        aliceSocket.once("close", code => {
            clearTimeout(timeout);
            resolve(code);
        });

        aliceSocket.once("error", error => {
            clearTimeout(timeout);
            reject(error);
        });
    });

    // =====================================================
    // TEST 21 - SESSION REVOCATION
    // =====================================================

    console.log(
        "21. Testing session revocation after logout..."
    );

    const logoutResponse = await fetch(
        "http://localhost:3000/api/auth/logout",
        {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Origin": "http://localhost:3000",
                "Cookie": alice.cookie
            },
            body: "{}"
        }
    );

    assert.ok(
        [200, 204].includes(logoutResponse.status),
        `Logout failed: ${logoutResponse.status}`
    );

    console.log("Alice logged out successfully.");

    const revokedResponse = await fetch(
        "http://localhost:3000/api/me",
        {
            headers: {
                "Cookie": alice.cookie
            }
        }
    );

    assert.equal(revokedResponse.status, 401);

    console.log("Old session cookie: REJECTED");
    console.log("SESSION REVOCATION TEST PASSED!");

    // =====================================================
    // TEST 22 - REVOKED WEBSOCKET
    // =====================================================

    console.log(
        "22. Testing WebSocket access after logout..."
    );

    await new Promise((resolve, reject) => {
        const ws = new WebSocket(
            "ws://127.0.0.1:3000/ws",
            {
                headers: {
                    Origin: "http://localhost:3000",
                    Cookie: alice.cookie
                }
            }
        );

        ws.once("open", () => {
            ws.close();

            reject(new Error(
                "SECURITY FAILURE: Revoked session accepted!"
            ));
        });

        ws.once("error", error => {
            if (error.message.includes("401")) {
                resolve();
            } else {
                reject(error);
            }
        });
    });

    console.log("Revoked WebSocket session: BLOCKED");

    console.log(
        "WEBSOCKET SESSION SECURITY TEST PASSED!"
    );

    // =====================================================
    // TEST 24 - WEBSOCKET LOGOUT SECURITY
    // =====================================================

    console.log(
        "24. Bob sends a message after Alice's logout..."
    );

    const postLogoutEnvelope = await bobRestored.encrypt(
        aliceRestored.contactCode,
        "Message sent while Alice is logged out"
    );

    const postLogoutMessage = await api(
        "POST",
        "/api/secure-messages",
        {
            chatId,
            clientMessageId: randomUUID(),
            envelope: postLogoutEnvelope
        },
        bob.cookie
    );

    assert.equal(
        postLogoutMessage.data.message,
        "Encrypted message stored"
    );

    console.log(
        "Encrypted message stored for offline delivery."
    );

    const closeCode = await socketClosed;

    assert.equal(closeCode, 1008);
    assert.equal(unexpectedNotification, false);

    console.log("Already-open WebSocket: REVOKED");

    console.log(
        "Unauthorized notification: NOT DELIVERED"
    );

    console.log(
        "WEBSOCKET LOGOUT SECURITY TEST PASSED!"
    );

    // =====================================================
    // FINAL RESULTS
    // =====================================================

    console.log("\n--- ADDITIONAL TEST RESULTS ---");
    console.log("Account state restoration: PASSED");
    console.log("Bob encrypted reply: PASSED");
    console.log("Alice decrypted:", decryptedReply);
    console.log("Bidirectional E2EE: PASSED");

    console.log("\n----- E2EE INTEGRATION RESULTS -----");
    console.log("Alice:", alice.username);
    console.log("Bob:", bob.username);
    console.log("X3DH session: ESTABLISHED");
    console.log("Encrypted envelope: ACCEPTED");
    console.log("Server delivery: SUCCESS");
    console.log("Bob decrypted:", decryptedMessage);
    console.log("Plaintext round-trip: PASSED");

    console.log("\nALL E2EE INTEGRATION TESTS PASSED!");
}

main().catch(error => {
    console.error("\nTEST FAILED:", error);
    process.exitCode = 1;
});
