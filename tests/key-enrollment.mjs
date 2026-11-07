
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { Account } from "../crypto/src/index.js";

const BASE_URL = "http://localhost:3000";
const PASSWORD = "TemporaryTestPassword123!";

async function request(method, endpoint, body, cookie, expectedStatus = 200) {
    const response = await fetch(BASE_URL + endpoint, {
        method,
        headers: {
            ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
            ...(cookie ? { Cookie: cookie } : {})
        },
        body: body === undefined ? undefined : JSON.stringify(body)
    });

    const data = await response.json();

    assert.equal(
        response.status,
        expectedStatus,
        `${method} ${endpoint}: expected HTTP ${expectedStatus}, got HTTP ${response.status}: ${JSON.stringify(data)}`
    );

    return { data, response };
}

async function keyStatus(cookie) {
    return (await request("GET", "/api/keys/status", undefined, cookie)).data;
}

async function uploadKeys(account, bundle, cookie, options = {}) {
    const { resetPreKeys, expectedStatus = 200 } = options;

    const ticket = await request("POST", "/api/keys/challenge", {}, cookie);
    const proof = await account.signRecoveryChallenge(ticket.data.challenge);

    return request("POST", "/api/keys/upload", {
        bundle,
        contactCode: account.contactCode,
        challenge: ticket.data.challenge,
        proof,
        ...(resetPreKeys === undefined ? {} : { resetPreKeys })
    }, cookie, expectedStatus);
}

async function main() {
    const username = "keytest_" + randomBytes(4).toString("hex");
    const email = `${username}@example.test`;

    console.log("1. Generating real cryptographic identity...");
    const { account, recoveryKey } = await Account.create();
    const initialBundle = await account.createPreKeyUpload({ oneTimePreKeyCount: 4 });

    console.log("2. Registering disposable test account...");
    await request("POST", "/api/auth/register", {
        username,
        email,
        password: PASSWORD,
        publicKey: initialBundle.identityKey
    }, undefined, 201);

    console.log("3. Logging in...");
    const login = await request("POST", "/api/auth/login", {
        email,
        password: PASSWORD
    });
    const cookie = login.response.headers.get("set-cookie")?.split(";")[0];
    assert.ok(cookie, "Login session cookie missing");

    console.log("4. Enrolling original identity and prekeys...");
    const enrolled = await uploadKeys(account, initialBundle, cookie);
    assert.equal(enrolled.data.message, "Public keys uploaded");
    assert.equal(enrolled.data.oneTimePreKeysAdded, 4);

    const originalStatus = await keyStatus(cookie);
    assert.equal(originalStatus.enrolled, true);
    assert.equal(originalStatus.contactCode, account.contactCode);
    assert.equal(originalStatus.signedPreKeyId, initialBundle.signedPreKey.id);
    assert.equal(originalStatus.oneTimePreKeys, 4);
    console.log("Original key enrollment: PASSED");

    console.log("5. Re-uploading the existing signed prekey without rotation...");
    const unchangedBundle = await account.createPreKeyUpload({
        oneTimePreKeyCount: 0,
        rotateSignedPreKey: false
    });
    assert.equal(unchangedBundle.signedPreKey.id, initialBundle.signedPreKey.id);
    await uploadKeys(account, unchangedBundle, cookie);
    const unchangedStatus = await keyStatus(cookie);
    assert.equal(unchangedStatus.signedPreKeyId, originalStatus.signedPreKeyId);
    assert.equal(unchangedStatus.oneTimePreKeys, 4);
    console.log("Same-key upload: PASSED");

    console.log("6. Rotating the signed prekey and replenishing one-time prekeys...");
    const rotatedBundle = await account.createPreKeyUpload({
        oneTimePreKeyCount: 2,
        rotateSignedPreKey: true
    });
    assert.notEqual(rotatedBundle.signedPreKey.id, initialBundle.signedPreKey.id);
    const rotation = await uploadKeys(account, rotatedBundle, cookie);
    assert.equal(rotation.data.oneTimePreKeysAdded, 2);

    const rotatedStatus = await keyStatus(cookie);
    assert.equal(rotatedStatus.contactCode, originalStatus.contactCode);
    assert.equal(rotatedStatus.signedPreKeyId, rotatedBundle.signedPreKey.id);
    assert.equal(rotatedStatus.oneTimePreKeys, 6);
    console.log("Signed-prekey rotation and replenishment: PASSED");

    console.log("7. Rejecting a tampered signed-prekey signature...");
    const tamperedBundle = structuredClone(rotatedBundle);
    const badSignature = Buffer.from(tamperedBundle.signedPreKey.signature, "base64");
    badSignature[0] ^= 1;
    tamperedBundle.signedPreKey.signature = badSignature.toString("base64");
    await uploadKeys(account, tamperedBundle, cookie, { expectedStatus: 400 });
    const afterTampering = await keyStatus(cookie);
    assert.equal(afterTampering.signedPreKeyId, rotatedStatus.signedPreKeyId);
    assert.equal(afterTampering.oneTimePreKeys, rotatedStatus.oneTimePreKeys);
    console.log("Invalid signature rejected without state changes: PASSED");

    console.log("8. Rejecting a different identity for the registered user...");
    const { account: outsider } = await Account.create();
    const outsiderBundle = await outsider.createPreKeyUpload({ oneTimePreKeyCount: 0 });
    await uploadKeys(outsider, outsiderBundle, cookie, { expectedStatus: 409 });
    const afterIdentityAttempt = await keyStatus(cookie);
    assert.equal(afterIdentityAttempt.contactCode, originalStatus.contactCode);
    assert.equal(afterIdentityAttempt.signedPreKeyId, rotatedStatus.signedPreKeyId);
    assert.equal(afterIdentityAttempt.oneTimePreKeys, rotatedStatus.oneTimePreKeys);
    console.log("Identity change rejected: PASSED");

    console.log("9. Restoring identity with recovery key and replacing obsolete prekeys...");
    const recovered = await Account.restore(recoveryKey);
    assert.equal(recovered.contactCode, account.contactCode);
    const recoveredBundle = await recovered.createPreKeyUpload({ oneTimePreKeyCount: 3 });
    assert.equal(recoveredBundle.identityKey, initialBundle.identityKey);
    const recoveryUpload = await uploadKeys(recovered, recoveredBundle, cookie, {
        resetPreKeys: true
    });
    assert.equal(recoveryUpload.data.oneTimePreKeysAdded, 3);
    const recoveredStatus = await keyStatus(cookie);
    assert.equal(recoveredStatus.contactCode, account.contactCode);
    assert.equal(recoveredStatus.signedPreKeyId, recoveredBundle.signedPreKey.id);
    assert.equal(recoveredStatus.oneTimePreKeys, 3);
    console.log("Recovery prekey replacement: PASSED");

    console.log("10. Rejecting unauthenticated key-management access...");
    await request("GET", "/api/keys/status", undefined, undefined, 401);
    await request("POST", "/api/keys/challenge", {}, undefined, 401);
    console.log("Unauthenticated access: BLOCKED");

    console.log("\n--- KEY MANAGEMENT TEST RESULTS ---");
    console.log("Enrollment: PASSED");
    console.log("Signed-prekey rotation: PASSED");
    console.log("One-time prekey replenishment: PASSED");
    console.log("Tampered signature: REJECTED");
    console.log("Identity change: REJECTED");
    console.log("Recovery reset: PASSED");
    console.log("Unauthorized access: BLOCKED");
    console.log("Test account:", username);
    console.log("\nALL KEY ENROLLMENT TESTS PASSED!");
}

main().catch(error => {
    console.error("\nTEST FAILED:", error);
    process.exitCode = 1;
});
