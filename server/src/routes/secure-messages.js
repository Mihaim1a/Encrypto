
"use strict";

const express = require("express");
const { randomUUID, createHash } = require("node:crypto");
const { rateLimit } = require("express-rate-limit");
const { notifyMessageAvailable } = require("../realtime");

const db = require("../database");
const { requireAuth } = require("../session");

const router = express.Router();

const MESSAGE_RETENTION_MS = 7 * 24 * 60 * 60 * 1000;

const UUID_PATTERN =
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const BASE64_PATTERN =
    /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

// Authentication required for all secure message routes.
router.use(requireAuth);

// Limit requests to reduce API abuse.
router.use(rateLimit({
    windowMs: 60 * 1000,
    limit: 60,
    standardHeaders: "draft-7",
    legacyHeaders: false
}));

// Prevent private API responses from being cached.
router.use((req, res, next) => {
    res.set("Cache-Control", "no-store");
    next();
});

function isBase64(value, minimumBytes, maximumBytes) {
    if (
        typeof value !== "string" ||
        !BASE64_PATTERN.test(value)
    ) {
        return false;
    }

    const decoded = Buffer.from(value, "base64");

    return (
        decoded.length >= minimumBytes &&
        decoded.length <= maximumBytes &&
        decoded.toString("base64") === value
    );
}

function isValidEnvelope(envelope) {
    if (
        !envelope ||
        typeof envelope !== "object" ||
        Array.isArray(envelope)
    ) {
        return false;
    }

    if (
        envelope.version !== 1 ||
        !["prekey", "message"].includes(envelope.type) ||
        !isBase64(envelope.header, 1, 2048) ||
        !isBase64(envelope.ciphertext, 16, 10000)
    ) {
        return false;
    }

    if (
        envelope.type === "prekey" &&
        (
            !envelope.preKey ||
            typeof envelope.preKey !== "object" ||
            Array.isArray(envelope.preKey)
        )
    ) {
        return false;
    }

    // Reject obvious plaintext or private-key fields.
    const forbidden = [
        "plaintext",
        "messageText",
        "privateKey",
        "secretKey",
        "rootKey",
        "chainKey"
    ];

    if (forbidden.some(key =>
        Object.prototype.hasOwnProperty.call(envelope, key)
    )) {
        return false;
    }

    return Buffer.byteLength(
        JSON.stringify(envelope),
        "utf8"
    ) <= 12000;
}

// Calculate a fingerprint for duplicate-message detection.
function hashEnvelope(serializedEnvelope) {
    return createHash("sha256")
        .update(serializedEnvelope, "utf8")
        .digest("hex");
}

// Send an encrypted envelope to an active chat.
router.post("/", (req, res) => {
    const {
        chatId,
        clientMessageId,
        envelope
    } = req.body || {};

    if (
        !UUID_PATTERN.test(chatId || "") ||
        !UUID_PATTERN.test(clientMessageId || "") ||
        !isValidEnvelope(envelope)
    ) {
        return res.status(400).json({
            error: "Invalid encrypted message"
        });
    }

    // Verify the sender belongs to this active chat.
    const chat = db.prepare(`
        SELECT user_a, user_b
        FROM direct_chats
        WHERE id = ?
          AND status = 'active'
          AND (user_a = ? OR user_b = ?)
    `).get(chatId, req.user.id, req.user.id);

    if (!chat) {
        return res.status(404).json({
            error: "Active chat not found"
        });
    }

    const recipientId =
        chat.user_a === req.user.id
            ? chat.user_b
            : chat.user_a;

    const serializedEnvelope = JSON.stringify(envelope);
    const envelopeHash = hashEnvelope(serializedEnvelope);

    // Detect duplicate submissions, including after deletion.
    const existing = db.prepare(`
        SELECT
            id,
            recipient_id,
            envelope_hash,
            envelope_json
        FROM secure_messages
        WHERE sender_id = ?
          AND client_message_id = ?
    `).get(req.user.id, clientMessageId);

    if (existing) {
        const storedHash = existing.envelope_hash ||
            (
                existing.envelope_json
                    ? hashEnvelope(existing.envelope_json)
                    : null
            );

        if (
            existing.recipient_id !== recipientId ||
            storedHash !== envelopeHash
        ) {
            return res.status(409).json({
                error: "Client message ID already used"
            });
        }

        return res.json({
            message: "Encrypted message already stored",
            messageId: existing.id,
            duplicate: true
        });
    }

    const messageId = randomUUID();

    const createdAtMs = Date.now();
    const createdAt = new Date(createdAtMs).toISOString();

    const expiresAt = createdAtMs + MESSAGE_RETENTION_MS;

    try {
        // Store ciphertext and retention metadata.
        db.prepare(`
            INSERT INTO secure_messages (
                id,
                sender_id,
                recipient_id,
                client_message_id,
                envelope_json,
                created_at,
                expires_at,
                envelope_hash
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `).run(
            messageId,
            req.user.id,
            recipientId,
            clientMessageId,
            serializedEnvelope,
            createdAt,
            expiresAt,
            envelopeHash
        );

        // Notify online recipients without sending plaintext.
        try {
            notifyMessageAvailable(recipientId, messageId);
        } catch (error) {
            console.error(
                "WebSocket notification failed:",
                error.message
            );
        }

        return res.status(201).json({
            message: "Encrypted message stored",
            messageId,
            createdAt
        });

    } catch (error) {
        if (error.code?.startsWith("SQLITE_CONSTRAINT")) {
            return res.status(409).json({
                error: "Duplicate message identifier"
            });
        }

        console.error("Secure message storage failed");

        return res.status(500).json({
            error: "Unable to store message"
        });
    }
});

// Retrieve the authenticated recipient's unexpired messages.
router.get("/inbox", (req, res) => {
    const limit = req.query.limit === undefined
        ? 50
        : Number(req.query.limit);

    if (
        !Number.isInteger(limit) ||
        limit < 1 ||
        limit > 100
    ) {
        return res.status(400).json({
            error: "Invalid inbox limit"
        });
    }

    try {
        const rows = db.prepare(`
            SELECT
                m.id,
                m.sender_id AS senderId,
                m.recipient_id AS recipientId,
                m.client_message_id AS clientMessageId,
                m.envelope_json AS envelopeJson,
                m.created_at AS createdAt,
                c.id AS chatId
            FROM secure_messages m
            JOIN direct_chats c
              ON (
                (
                    c.user_a = m.sender_id
                    AND c.user_b = m.recipient_id
                )
                OR
                (
                    c.user_b = m.sender_id
                    AND c.user_a = m.recipient_id
                )
              )
            WHERE m.recipient_id = ?
              AND m.acknowledged_at IS NULL
              AND m.envelope_json <> ''
              AND m.expires_at > ?
            ORDER BY m.created_at ASC, m.id ASC
            LIMIT ?
        `).all(
            req.user.id,
            Date.now(),
            limit
        );

        const messages = rows.map(row => ({
            id: row.id,
            chatId: row.chatId,
            senderId: row.senderId,
            recipientId: row.recipientId,
            clientMessageId: row.clientMessageId,
            envelope: JSON.parse(row.envelopeJson),
            createdAt: row.createdAt
        }));

        return res.json({ messages });

    } catch (error) {
        console.error("Secure inbox retrieval failed");

        return res.status(500).json({
            error: "Unable to retrieve inbox"
        });
    }
});

// Acknowledge receipt and clear ciphertext from the active row.
router.post("/:id/ack", (req, res) => {
    const messageId = req.params.id;

    if (!UUID_PATTERN.test(messageId)) {
        return res.status(400).json({
            error: "Invalid message identifier"
        });
    }

    // Only the intended recipient can acknowledge.
    const message = db.prepare(`
        SELECT
            id,
            acknowledged_at,
            expires_at,
            envelope_json
        FROM secure_messages
        WHERE id = ?
          AND recipient_id = ?
    `).get(messageId, req.user.id);

    if (!message) {
        return res.status(404).json({
            error: "Message not found"
        });
    }

    // Repeated ACK requests are safe.
    if (message.acknowledged_at) {
        return res.json({
            message: "Already acknowledged",
            messageId
        });
    }

    const nowMs = Date.now();

    // Expired or already-purged messages cannot be acknowledged.
    if (
        !Number.isSafeInteger(message.expires_at) ||
        message.expires_at <= nowMs ||
        !message.envelope_json
    ) {
        return res.status(410).json({
            error: "Message no longer available"
        });
    }

    // Atomically mark delivery and clear the encrypted payload.
    const result = db.prepare(`
        UPDATE secure_messages
        SET
            acknowledged_at = ?,
            envelope_json = '',
            purged_at = ?
        WHERE id = ?
          AND recipient_id = ?
          AND acknowledged_at IS NULL
          AND envelope_json <> ''
          AND expires_at > ?
    `).run(
        new Date(nowMs).toISOString(),
        nowMs,
        messageId,
        req.user.id,
        nowMs
    );

    if (result.changes !== 1) {
        return res.status(409).json({
            error: "Message state changed"
        });
    }

    return res.json({
        message: "Message acknowledged",
        messageId,
        ciphertextDeleted: true
    });
});

module.exports = router;
