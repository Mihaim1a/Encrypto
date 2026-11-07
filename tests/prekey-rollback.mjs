
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { Account } from "../crypto/src/index.js";

const BASE_URL = "http://localhost:3000";
const PASSWORD = "TemporaryTestPassword123!";

async function request(method, endpoint, body, cookie) {
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

    return {
        status: response.status,
        data,
        response
    };
}

async function uploadKeys(account, bundle, cookie) {
    const ticket = await request(
        "POST",
        "/api/keys/challenge",
        {},
        cookie
    );

    assert.equal(ticket.status, 200);

    const proof = await account.signRecoveryChallenge(
        ticket.data.challenge
    );

    return request(
        "POST",
        "/api/keys/upload",
        {
            bundle,
            contactCode: account.contactCode,
            challenge: ticket.data.challenge,
            proof
        },
        cookie
    );
}

async function main() {
    const username = "rollback_" + randomBytes(4).toString("hex");
    const email = `${username}@example.test`;

    console.log("1. Creating test identity...");

    const { account } = await Account.create();

    const originalBundle = await account.createPreKeyUpload({
        oneTimePreKeyCount: 2
    });

    console.log("2. Registering test account...");

    const registration = await request(
        "POST",
        "/api/auth/register",
        {
            username,
            email,
            password: PASSWORD,
            publicKey: originalBundle.identityKey
        }
    );

    assert.equal(registration.status, 201);

    console.log("3. Logging in...");

    const login = await request(
        "POST",
        "/api/auth/login",
        { email, password: PASSWORD }
    );

    assert.equal(login.status, 200);

    const cookie = login.response.headers
        .get("set-cookie")?.split(";")[0];

    assert.ok(cookie, "Missing authentication cookie");

    console.log("4. Uploading original signed prekey...");

    const firstUpload = await uploadKeys(
        account,
        originalBundle,
        cookie
    );

    assert.equal(firstUpload.status, 200);

    const originalId = originalBundle.signedPreKey.id;

    console.log("5. Rotating to a newer signed prekey...");

    const rotatedBundle = await account.createPreKeyUpload({
        oneTimePreKeyCount: 0,
        rotateSignedPreKey: true
    });

    const newId = rotatedBundle.signedPreKey.id;

    assert.notEqual(originalId, newId);

    const rotation = await uploadKeys(
        account,
        rotatedBundle,
        cookie
    );

    assert.equal(rotation.status, 200);

    const statusAfterRotation = await request(
        "GET",
        "/api/keys/status",
        undefined,
        cookie
    );

    assert.equal(statusAfterRotation.status, 200);
    assert.equal(statusAfterRotation.data.signedPreKeyId, newId);

    console.log("New signed prekey ID:", newId);
    console.log("Rotation successful.");

    console.log("6. Attempting to reintroduce the older signed prekey...");

    // Reuse the previously valid signature and public key.
    // Remove old one-time prekeys so duplicate IDs do not
    // interfere with the signed-prekey rollback check.
    const oldBundle = structuredClone(originalBundle);
    oldBundle.oneTimePreKeys = [];

    const rollback = await uploadKeys(
        account,
        oldBundle,
        cookie
    );

    console.log("Rollback upload HTTP status:", rollback.status);

    const finalStatus = await request(
        "GET",
        "/api/keys/status",
        undefined,
        cookie
    );

    assert.equal(finalStatus.status, 200);

    // Expected secure behavior: a normal upload must not
    // replace the currently published key with an older one.
    assert.equal(
        rollback.status,
        409,
        "ROLLBACK NOT BLOCKED: old signed prekey was accepted"
    );

    assert.equal(
        finalStatus.data.signedPreKeyId,
        newId,
        "ROLLBACK NOT BLOCKED: server changed its active signed prekey"
    );

    console.log("\nSIGNED-PREKEY ROLLBACK PROTECTION: PASSED!");
}

main().catch(error => {
    console.error("\nROLLBACK TEST FAILED:", error.message);
    process.exitCode = 1;
});
