
"use strict";

const express = require("express");
const { randomUUID } = require("node:crypto");
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

// Create a chat invitation
router.post("/", (req, res) => {
    const { recipientUsername } = req.body || {};

    if (
        typeof recipientUsername !== "string" ||
        !/^[a-z0-9_]{3,30}$/.test(recipientUsername.toLowerCase())
    ) {
        return res.status(400).json({
            error: "Invalid recipient username"
        });
    }

    const recipient = db.prepare(`
        SELECT id, username
        FROM users
        WHERE username = ?
    `).get(recipientUsername.toLowerCase());

    if (!recipient) {
        return res.status(404).json({
            error: "Recipient not found"
        });
    }

    const senderId = req.user.id;
    const recipientId = recipient.id;

    if (senderId === recipientId) {
        return res.status(400).json({
            error: "Cannot create a chat with yourself"
        });
    }

    // Sort IDs so Alice/Bob and Bob/Alice are the same chat.
    const [userA, userB] = [senderId, recipientId].sort();

    const existing = db.prepare(`
        SELECT id, status
        FROM direct_chats
        WHERE user_a = ? AND user_b = ?
    `).get(userA, userB);

    if (existing) {
        return res.status(409).json({
            error: "Chat already exists",
            chatId: existing.id,
            status: existing.status
        });
    }

    const chatId = randomUUID();
    const createdAt = new Date().toISOString();

    try {
        db.prepare(`
            INSERT INTO direct_chats (
                id, user_a, user_b,
                requested_by, status, created_at
            )
            VALUES (?, ?, ?, ?, 'pending', ?)
        `).run(
            chatId,
            userA,
            userB,
            senderId,
            createdAt
        );

        res.set("Cache-Control", "no-store");

        return res.status(201).json({
            message: "Chat invitation created",
            chatId,
            status: "pending",
            recipientUsername: recipient.username
        });
    } catch (error) {
        if (error.code?.startsWith("SQLITE_CONSTRAINT")) {
            return res.status(409).json({
                error: "Chat already exists"
            });
        }

        console.error("Chat creation error:", error);
        return res.status(500).json({
            error: "Failed to create chat"
        });
    }
});

// List only chats involving the authenticated user
router.get("/", (req, res) => {
    try {
        const chats = db.prepare(`
            SELECT
                c.id,
                c.status,
                c.requested_by AS requestedBy,
                c.created_at AS createdAt,
                CASE
                    WHEN c.user_a = ? THEN ub.id
                    ELSE ua.id
                END AS contactId,
                CASE
                    WHEN c.user_a = ? THEN ub.username
                    ELSE ua.username
                END AS contactUsername
            FROM direct_chats c
            JOIN users ua ON ua.id = c.user_a
            JOIN users ub ON ub.id = c.user_b
            WHERE c.user_a = ? OR c.user_b = ?
            ORDER BY c.created_at DESC
        `).all(
            req.user.id,
            req.user.id,
            req.user.id,
            req.user.id
        );

        res.set("Cache-Control", "no-store");
        return res.json({ chats });
    } catch (error) {
        console.error("Chat listing error:", error);
        return res.status(500).json({
            error: "Failed to retrieve chats"
        });
    }
});

// Only the recipient can accept an invitation
router.post("/:chatId/accept", (req, res) => {
    const chatId = req.params.chatId;

    const chat = db.prepare(`
        SELECT *
        FROM direct_chats
        WHERE id = ?
          AND (user_a = ? OR user_b = ?)
    `).get(chatId, req.user.id, req.user.id);

    if (!chat) {
        return res.status(404).json({
            error: "Chat invitation not found"
        });
    }

    if (chat.requested_by === req.user.id) {
        return res.status(403).json({
            error: "Cannot accept your own invitation"
        });
    }

    if (chat.status !== "pending") {
        return res.status(409).json({
            error: "Invitation is no longer pending"
        });
    }

    const result = db.prepare(`
        UPDATE direct_chats
        SET status = 'active'
        WHERE id = ? AND status = 'pending'
    `).run(chatId);

    if (result.changes !== 1) {
        return res.status(409).json({
            error: "Invitation state changed"
        });
    }

    res.set("Cache-Control", "no-store");

    return res.json({
        message: "Chat invitation accepted",
        chatId,
        status: "active"
    });
});

// Only the recipient can decline an invitation
router.post("/:chatId/decline", (req, res) => {
    const chatId = req.params.chatId;

    const chat = db.prepare(`
        SELECT *
        FROM direct_chats
        WHERE id = ?
          AND (user_a = ? OR user_b = ?)
    `).get(chatId, req.user.id, req.user.id);

    if (!chat) {
        return res.status(404).json({
            error: "Chat invitation not found"
        });
    }

    if (chat.requested_by === req.user.id) {
        return res.status(403).json({
            error: "Cannot decline your own invitation"
        });
    }

    if (chat.status !== "pending") {
        return res.status(409).json({
            error: "Invitation is no longer pending"
        });
    }

    const result = db.prepare(`
        UPDATE direct_chats
        SET status = 'declined'
        WHERE id = ? AND status = 'pending'
    `).run(chatId);

    if (result.changes !== 1) {
        return res.status(409).json({
            error: "Invitation state changed"
        });
    }

    return res.json({
        message: "Chat invitation declined",
        chatId,
        status: "declined"
    });
});

module.exports = router;
