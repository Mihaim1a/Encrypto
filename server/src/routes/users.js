
const express = require("express");
const db = require("../database");
const { requireAuth } = require("../session");

const router = express.Router();

// Returnam cheia publica a unui utilizator
router.get("/:username/public-key", requireAuth, (req, res) => {
    const username = req.params.username.toLowerCase();

    // Validam username-ul
    if (!/^[a-z0-9_]{3,30}$/.test(username)) {
        return res.status(400).json({
            error: "Invalid username"
        });
    }

    // Cautam utilizatorul in baza de date
    const user = db.prepare(`
        SELECT id, username, public_key
        FROM users
        WHERE username = ?
    `).get(username);

    if (!user) {
        return res.status(404).json({
            error: "User not found"
        });
    }

    res.set("Cache-Control", "no-store");

    // Returnam doar informatiile necesare
    return res.json({
        userId: user.id,
        username: user.username,
        publicKey: user.public_key
    });
});

module.exports = router;
