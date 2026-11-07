
const express = require("express");
const { randomUUID } = require("node:crypto");
const db = require("../database");
const { requireAuth } = require("../session");

const router = express.Router();

// Toate endpoint-urile necesita autentificare
router.use(requireAuth);

function validUserId(id) {
    return typeof id === "string" &&
        /^[0-9a-f-]{36}$/i.test(id);
}

function validEnvelope(value) {
    return typeof value === "string" &&
        value.length >= 32 &&
        value.length <= 12000 &&
        /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value);
}

// Trimiterea unui mesaj criptat
router.post("/", (req, res) => {
    const {
        recipientId,
        encryptedEnvelope,
        envelopeVersion
    } = req.body || {};

    if (
        !validUserId(recipientId) ||
        !validEnvelope(encryptedEnvelope) ||
        envelopeVersion !== 1
    ) {
        return res.status(400).json({
            error: "Invalid encrypted message data"
        });
    }

    const senderId = req.user.id;

    if (senderId === recipientId) {
        return res.status(400).json({
            error: "Cannot send message to yourself"
        });
    }

    try {
        const recipient = db.prepare(
            "SELECT id FROM users WHERE id = ?"
        ).get(recipientId);

        if (!recipient) {
            return res.status(404).json({
                error: "Recipient not found"
            });
        }

        const id = randomUUID();
        const createdAt = new Date().toISOString();

        db.prepare(`
            INSERT INTO direct_messages
            (id, sender_id, recipient_id,
             encrypted_envelope, envelope_version, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        `).run(
            id,
            senderId,
            recipientId,
            encryptedEnvelope,
            envelopeVersion,
            createdAt
        );

        res.set("Cache-Control", "no-store");

        return res.status(201).json({
            message: "Encrypted message stored",
            messageId: id,
            createdAt
        });

    } catch (error) {
        console.error("Message storage error:", error);

        return res.status(500).json({
            error: "Internal server error"
        });
    }
});

// Recuperarea mesajelor dintre doi utilizatori
router.get("/with/:userId", (req, res) => {
    const otherUserId = req.params.userId;

    if (!validUserId(otherUserId)) {
        return res.status(400).json({
            error: "Invalid user ID"
        });
    }

    const requestedLimit = req.query.limit ?? "50";

    if (
        typeof requestedLimit !== "string" ||
        !/^\d{1,3}$/.test(requestedLimit)
    ) {
        return res.status(400).json({
            error: "Invalid limit"
        });
    }

    const limit = Number(requestedLimit);

    if (limit < 1 || limit > 100) {
        return res.status(400).json({
            error: "Limit must be between 1 and 100"
        });
    }

    try {
        const messages = db.prepare(`
            SELECT
                id,
                sender_id AS senderId,
                recipient_id AS recipientId,
                encrypted_envelope AS encryptedEnvelope,
                envelope_version AS envelopeVersion,
                created_at AS createdAt
            FROM direct_messages
            WHERE
                (sender_id = ? AND recipient_id = ?)
                OR
                (sender_id = ? AND recipient_id = ?)
            ORDER BY created_at DESC, id DESC
            LIMIT ?
        `).all(
            req.user.id,
            otherUserId,
            otherUserId,
            req.user.id,
            limit
        );

        res.set("Cache-Control", "no-store");

        return res.json({
            messages: messages.reverse()
        });

    } catch (error) {
        console.error("Message retrieval error:", error);

        return res.status(500).json({
            error: "Internal server error"
        });
    }
});

module.exports = router;
