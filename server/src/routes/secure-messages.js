
"use strict";

const express = require("express");
const { randomUUID } = require("node:crypto");
const { rateLimit } = require("express-rate-limit");
const { notifyMessageAvailable } = require("../realtime");

const db = require("../database");
const { requireAuth } = require("../session");

const router = express.Router();

const UUID_PATTERN =
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const BASE64_PATTERN =
    /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

router.use(requireAuth);

router.use(rateLimit({
    windowMs: 60 * 1000,
    limit: 60,
    standardHeaders: "draft-7",
    legacyHeaders: false
}));

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

    // Encrypted envelope only.
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
        (!envelope.preKey ||
            typeof envelope.preKey !== "object" ||
            Array.isArray(envelope.preKey))
    ) {
        return false;
    }

    // Never accept obvious plaintext/private-key fields.
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
        JSON.stringify(envelope), "utf8"
    ) <= 12000;
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

    // Support safe retries without creating duplicate messages.
    const existing = db.prepare(`
        SELECT id, recipient_id, envelope_json
        FROM secure_messages
        WHERE sender_id = ? AND client_message_id = ?
    `).get(req.user.id, clientMessageId);

    if (existing) {
        if (
            existing.recipient_id !== recipientId ||
            existing.envelope_json !== serializedEnvelope
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
    const createdAt = new Date().toISOString();

    try {
        db.prepare(`
            INSERT INTO secure_messages (
                id,
                sender_id,
                recipient_id,
                client_message_id,
                envelope_json,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
        `).run(
            messageId,
            req.user.id,
            recipientId,
            clientMessageId,
            serializedEnvelope,
            createdAt
        );

        try {
    notifyMessageAvailable(recipientId, messageId);
} catch (error) {
    console.error("WebSocket notification failed:", error.message);
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

// Retrieve only the authenticated recipient's pending messages.
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
                (c.user_a = m.sender_id
                 AND c.user_b = m.recipient_id)
                OR
                (c.user_b = m.sender_id
                 AND c.user_a = m.recipient_id)
              )
            WHERE m.recipient_id = ?
              AND m.acknowledged_at IS NULL
            ORDER BY m.created_at ASC, m.id ASC
            LIMIT ?
        `).all(req.user.id, limit);

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

// Acknowledge receipt of an encrypted message.
router.post("/:id/ack", (req, res) => {
    const messageId = req.params.id;

    if (!UUID_PATTERN.test(messageId)) {
        return res.status(400).json({
            error: "Invalid message identifier"
        });
    }

    const message = db.prepare(`
        SELECT id, acknowledged_at
        FROM secure_messages
        WHERE id = ? AND recipient_id = ?
    `).get(messageId, req.user.id);

    if (!message) {
        return res.status(404).json({
            error: "Message not found"
        });
    }

    if (message.acknowledged_at) {
        return res.json({
            message: "Already acknowledged",
            messageId
        });
    }

    const result = db.prepare(`
        UPDATE secure_messages
        SET acknowledged_at = ?
        WHERE id = ?
          AND recipient_id = ?
          AND acknowledged_at IS NULL
    `).run(
        new Date().toISOString(),
        messageId,
        req.user.id
    );

    return res.json({
        message: result.changes === 1
            ? "Message acknowledged"
            : "Already acknowledged",
        messageId
    });
});

module.exports = router;
