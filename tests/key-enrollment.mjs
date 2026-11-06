
import { Account } from "../crypto/src/index.js";
import { randomBytes } from "node:crypto";

const BASE_URL = "http://localhost:3000";

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

    if (!response.ok) {
        throw new Error(
            `${endpoint}: HTTP ${response.status} - ${JSON.stringify(data)}`
        );
    }

    return { data, response };
}

async function main() {
    const username = "keytest_" + randomBytes(4).toString("hex");
    const email = `${username}@example.test`;
    const password = "TemporaryTestPassword123!";

    console.log("1. Generating real cryptographic identity...");

    const { account } = await Account.create();

    const bundle = await account.createPreKeyUpload({
        oneTimePreKeyCount: 4
    });

    console.log("2. Registering disposable test account...");

    await request("POST", "/api/auth/register", {
        username,
        email,
        password,
        publicKey: bundle.identityKey
    });

    console.log("3. Logging in...");

    const login = await request("POST", "/api/auth/login", {
        email,
        password
    });

    const setCookie = login.response.headers.get("set-cookie");

    if (!setCookie) {
        throw new Error("Login session cookie missing");
    }

    const cookie = setCookie.split(";")[0];

    console.log("4. Requesting enrollment challenge...");

    const ticket = await request(
        "POST",
        "/api/keys/challenge",
        {},
        cookie
    );

    console.log("5. Signing challenge locally...");

    const proof = await account.signRecoveryChallenge(
        ticket.data.challenge
    );

    console.log("6. Uploading public keys to SQLite...");

    const uploaded = await request(
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

    console.log("7. Checking key enrollment status...");

    const status = await request(
        "GET",
        "/api/keys/status",
        undefined,
        cookie
    );

    console.log("\n--- TEST RESULTS ---");
    console.log("Upload:", uploaded.data.message);
    console.log("Username:", username);
    console.log("Enrolled:", status.data.enrolled);
    console.log("One-time prekeys:", status.data.oneTimePreKeys);
    console.log(
        "Contact code matches:",
        status.data.contactCode === account.contactCode
    );

    if (
        !status.data.enrolled ||
        status.data.oneTimePreKeys !== 4 ||
        status.data.contactCode !== account.contactCode
    ) {
        throw new Error("Key enrollment verification failed");
    }

    console.log("\nALL KEY ENROLLMENT TESTS PASSED!");
}

main().catch(error => {
    console.error("\nTEST FAILED:", error.message);
    process.exitCode = 1;
});
