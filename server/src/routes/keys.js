
"use strict";

const express = require("express");
const { randomBytes } = require("node:crypto");
const { rateLimit } = require("express-rate-limit");
const db = require("../database");
const { requireAuth } = require("../session");

const router = express.Router();

router.use(requireAuth);

router.use(rateLimit({
    windowMs: 60 * 1000,
    limit: 30,
    standardHeaders: "draft-7",
    legacyHeaders: false
}));

// Check the user's public key registration status
router.get("/status", (req, res) => {
    const identity = db.prepare(`
        SELECT contact_code, signed_prekey_id
        FROM user_crypto
        WHERE user_id = ?
    `).get(req.user.id);

    const result = db.prepare(`
        SELECT COUNT(*) AS count
        FROM one_time_prekeys
        WHERE user_id = ?
    `).get(req.user.id);

    res.set("Cache-Control", "no-store");

    return res.json({
        enrolled: Boolean(identity),
        contactCode: identity?.contact_code ?? null,
        signedPreKeyId: identity?.signed_prekey_id ?? null,
        oneTimePreKeys: result.count
    });
});

// Generate a challenge for future identity verification
router.post("/challenge", (req, res) => {
    const challenge = randomBytes(32).toString("base64");

    db.prepare(`
        INSERT INTO key_enrollment_challenges
            (user_id, challenge, expires_at)
        VALUES (?, ?, ?)
        ON CONFLICT(user_id) DO UPDATE SET
            challenge = excluded.challenge,
            expires_at = excluded.expires_at
    `).run(
        req.user.id,
        challenge,
        Date.now() + 300000
    );

    res.set("Cache-Control", "no-store");

    return res.json({
        challenge,
        expiresInSeconds: 300
    });
});


const path = require("node:path");
const { pathToFileURL } = require("node:url");

const cryptoDir = path.resolve(__dirname, "../../../crypto/src");

const cryptoPromise = Promise.all([
    import(pathToFileURL(path.join(cryptoDir, "index.js")).href),
    import(pathToFileURL(path.join(cryptoDir, "keys.js")).href),
    import(pathToFileURL(path.join(cryptoDir, "x3dh.js")).href),
    import(pathToFileURL(path.join(cryptoDir, "encoding.js")).href)
]);

const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

function isB64(value, bytes) {
    if (typeof value !== "string" || !value || !BASE64.test(value))
        return false;

    const decoded = Buffer.from(value, "base64");

    return decoded.length === bytes &&
        decoded.toString("base64") === value;
}

function isKeyId(id) {
    return Number.isInteger(id) &&
        id >= 1 &&
        id <= 0xffffffff;
}

function validUpload(b) {
    if (!b || typeof b !== "object" || Array.isArray(b) ||
        !b.signedPreKey ||
        typeof b.signedPreKey !== "object" ||
        !Array.isArray(b.oneTimePreKeys) ||
        b.oneTimePreKeys.length > 100)
        return false;

    const s = b.signedPreKey;

    if (!isB64(b.identityKey, 32) ||
        !isB64(b.identityDHKey, 32) ||
        !isB64(b.identityBinding, 64) ||
        !isKeyId(s.id) ||
        !isB64(s.publicKey, 32) ||
        !isB64(s.signature, 64))
        return false;

    const ids = new Set();

    for (const p of b.oneTimePreKeys) {
        if (!p ||
            !isKeyId(p.id) ||
            !isB64(p.publicKey, 32) ||
            ids.has(p.id))
            return false;

        ids.add(p.id);
    }

    return true;
}

// Upload verified public keys, never private keys.
router.post("/upload", async (req, res) => {
    const {
        bundle,
        contactCode,
        challenge,
        proof
    } = req.body || {};

    if (!validUpload(bundle) ||
        typeof contactCode !== "string" ||
        contactCode.length > 100 ||
        !isB64(challenge, 32) ||
        !isB64(proof, 64)) {
        return res.status(400).json({
            error: "Invalid public key upload"
        });
    }

    let inTransaction = false;

    try {
        const [api, keys, x3dh, encoding] = await cryptoPromise;

        const normalized = await api.normalizeContactCode(contactCode);
        const identity = encoding.fromBase64(bundle.identityKey, 32);

        if (normalized !== await keys.encodeContactCode(identity)) {
            return res.status(400).json({
                error: "Contact code does not match the identity key"
            });
        }

        await x3dh.verifyPreKeyBundle({
            identityKey: identity,
            identityDHKey: encoding.fromBase64(bundle.identityDHKey, 32),
            identityBinding: encoding.fromBase64(bundle.identityBinding, 64),
            signedPreKey: {
                id: bundle.signedPreKey.id,
                publicKey: encoding.fromBase64(
                    bundle.signedPreKey.publicKey, 32
                ),
                signature: encoding.fromBase64(
                    bundle.signedPreKey.signature, 64
                )
            }
        }, identity);

        if (!await api.verifyRecoveryChallenge(
            normalized, challenge, proof
        )) {
            return res.status(403).json({
                error: "Invalid identity proof"
            });
        }

        db.exec("BEGIN IMMEDIATE");
        inTransaction = true;

        const ticket = db.prepare(`
            SELECT challenge
            FROM key_enrollment_challenges
            WHERE user_id = ? AND expires_at > ?
        `).get(req.user.id, Date.now());

        if (!ticket || ticket.challenge !== challenge) {
            const err = new Error("Challenge expired or already used");
            err.httpStatus = 409;
            throw err;
        }

        const existing = db.prepare(`
            SELECT contact_code, identity_key, identity_dh_key,
                   identity_binding, signed_prekey_id,
                   signed_prekey_public, signed_prekey_signature
            FROM user_crypto
            WHERE user_id = ?
        `).get(req.user.id);

        if (existing) {
            if (existing.contact_code !== normalized ||
                existing.identity_key !== bundle.identityKey ||
                existing.identity_dh_key !== bundle.identityDHKey ||
                existing.identity_binding !== bundle.identityBinding ||
                existing.signed_prekey_id !== bundle.signedPreKey.id ||
                existing.signed_prekey_public !== bundle.signedPreKey.publicKey ||
                existing.signed_prekey_signature !== bundle.signedPreKey.signature) {
                const err = new Error(
                    "Identity or signed-prekey change needs a separate rotation process"
                );
                err.httpStatus = 409;
                throw err;
            }
        } else {
            db.prepare(`
                INSERT INTO user_crypto (
                    user_id, contact_code, identity_key,
                    identity_dh_key, identity_binding,
                    signed_prekey_id, signed_prekey_public,
                    signed_prekey_signature
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            `).run(
                req.user.id,
                normalized,
                bundle.identityKey,
                bundle.identityDHKey,
                bundle.identityBinding,
                bundle.signedPreKey.id,
                bundle.signedPreKey.publicKey,
                bundle.signedPreKey.signature
            );
        }

        const insert = db.prepare(`
            INSERT INTO one_time_prekeys
            (user_id, key_id, public_key)
            VALUES (?, ?, ?)
        `);

        for (const p of bundle.oneTimePreKeys) {
            insert.run(req.user.id, p.id, p.publicKey);
        }

        db.prepare(`
            DELETE FROM key_enrollment_challenges
            WHERE user_id = ?
        `).run(req.user.id);

        db.exec("COMMIT");
        inTransaction = false;

        res.set("Cache-Control", "no-store");

        return res.json({
            message: "Public keys uploaded",
            contactCode: normalized,
            oneTimePreKeysAdded: bundle.oneTimePreKeys.length
        });

    } catch (error) {
        if (inTransaction) db.exec("ROLLBACK");

        if (error.httpStatus) {
            return res.status(error.httpStatus).json({
                error: error.message
            });
        }

        if (/UNIQUE constraint/.test(String(error.message))) {
            return res.status(409).json({
                error: "Public key or prekey already registered"
            });
        }

        if (error.name === "InvalidCodeError" ||
            error.name === "UntrustedIdentityError" ||
            error instanceof TypeError) {
            return res.status(400).json({
                error: "Invalid public keys or signatures"
            });
        }

        console.error("Key enrollment failed:", error.message);

        return res.status(500).json({
            error: "Key enrollment failed"
        });
    }
});


router.post("/bundle", async (req, res) => {
    const { contactCode } = req.body || {};

    if (
        typeof contactCode !== "string" ||
        contactCode.length > 100
    ) {
        return res.status(400).json({
            error: "Invalid contact code"
        });
    }

    let normalized;

    try {
        const [api] = await cryptoPromise;
        normalized = await api.normalizeContactCode(contactCode);
    } catch {
        return res.status(400).json({
            error: "Invalid contact code"
        });
    }

    let inTransaction = false;

    try {
        db.exec("BEGIN IMMEDIATE");
        inTransaction = true;

        const identity = db.prepare(`
            SELECT
                user_id,
                identity_key,
                identity_dh_key,
                identity_binding,
                signed_prekey_id,
                signed_prekey_public,
                signed_prekey_signature
            FROM user_crypto
            WHERE contact_code = ?
        `).get(normalized);

        if (!identity) {
            db.exec("ROLLBACK");
            inTransaction = false;

            return res.status(404).json({
                error: "Public identity not found"
            });
        }

        // Only active chat participants may retrieve a user's prekeys.
        const authorizedChat = db.prepare(`
            SELECT 1 AS allowed
            FROM direct_chats
            WHERE status = 'active'
              AND (
                  (user_a = ? AND user_b = ?)
                  OR
                  (user_a = ? AND user_b = ?)
              )
            LIMIT 1
        `).get(
            req.user.id,
            identity.user_id,
            identity.user_id,
            req.user.id
        );

        if (!authorizedChat) {
            db.exec("ROLLBACK");
            inTransaction = false;

            return res.status(404).json({
                error: "Public identity not found or unavailable"
            });
        }

        const prekey = db.prepare(`
            SELECT key_id, public_key
            FROM one_time_prekeys
            WHERE user_id = ?
            ORDER BY rowid
            LIMIT 1
        `).get(identity.user_id);

        if (prekey) {
            const result = db.prepare(`
                DELETE FROM one_time_prekeys
                WHERE user_id = ? AND key_id = ?
            `).run(identity.user_id, prekey.key_id);

            if (result.changes !== 1) {
                throw new Error("Prekey allocation failed");
            }
        }

        db.exec("COMMIT");
        inTransaction = false;

        res.set("Cache-Control", "no-store");

        return res.json({
            identityKey: identity.identity_key,
            identityDHKey: identity.identity_dh_key,
            identityBinding: identity.identity_binding,

            signedPreKey: {
                id: identity.signed_prekey_id,
                publicKey: identity.signed_prekey_public,
                signature: identity.signed_prekey_signature
            },

            oneTimePreKey: prekey ? {
                id: prekey.key_id,
                publicKey: prekey.public_key
            } : null
        });

    } catch (error) {
        if (inTransaction) {
            try {
                db.exec("ROLLBACK");
            } catch {}
        }

        console.error("Prekey distribution error:", error.message);

        return res.status(500).json({
            error: "Failed to retrieve public keys"
        });
    }
});

module.exports = router;