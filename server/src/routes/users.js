
"use strict";

const express = require("express");
const db = require("../database");
const { requireAuth } = require("../session");

const router = express.Router();

// Retrieve a user's public identity information.
router.get("/:username/public-key", requireAuth, (req, res) => {
    const username = req.params.username.toLowerCase();

    if (!/^[a-z0-9_]{3,30}$/.test(username)) {
        return res.status(400).json({
            error: "Invalid username"
        });
    }

    try {
        const user = db.prepare(`
            SELECT
                u.id,
                u.username,
                u.public_key,
                uc.contact_code
            FROM users u
            LEFT JOIN user_crypto uc
                ON uc.user_id = u.id
            WHERE u.username = ?
        `).get(username);

        if (!user) {
            return res.status(404).json({
                error: "User not found"
            });
        }

        res.set("Cache-Control", "no-store");

        return res.json({
            userId: user.id,
            username: user.username,
            publicKey: user.public_key,
            contactCode: user.contact_code || null,
            cryptoEnrolled: Boolean(user.contact_code)
        });

    } catch (error) {
        console.error("Public user lookup failed:", error.message);

        return res.status(500).json({
            error: "Failed to retrieve public identity"
        });
    }
});

module.exports = router;
