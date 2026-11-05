
const express = require("express");
const { randomUUID, randomBytes, scrypt } = require("node:crypto");
const { promisify } = require("node:util");
const db = require("../database");

const router = express.Router();
const scryptAsync = promisify(scrypt);

router.post("/register", async (req, res) => {
    const { username, email, password, publicKey } = req.body || {};

    // Validam datele primite
    if (
        typeof username !== "string" ||
        !/^[a-zA-Z0-9_]{3,30}$/.test(username) ||
        typeof email !== "string" ||
        email.length > 254 ||
        !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
        typeof password !== "string" ||
        password.length < 12 ||
        password.length > 128 ||
        typeof publicKey !== "string" ||
        !publicKey.trim() ||
        publicKey.length > 8192
    ) {
        return res.status(400).json({
            error: "Invalid registration data"
        });
    }

    const cleanEmail = email.trim().toLowerCase();
    const cleanUsername = username.toLowerCase();

    try {
        // Verificam daca utilizatorul exista
        const existing = db.prepare(
            "SELECT id FROM users WHERE email = ? OR username = ?"
        ).get(cleanEmail, cleanUsername);

        if (existing) {
            return res.status(409).json({
                error: "Username or email already exists"
            });
        }

        // Generam un salt unic si hash-uim parola
        const salt = randomBytes(16).toString("hex");

        const hash = await scryptAsync(password, salt, 64, {
            N: 131072,
            r: 8,
            p: 1,
            maxmem: 256 * 1024 * 1024
        });

        const passwordHash =
            `scrypt$131072$8$1$${salt}$${hash.toString("hex")}`;

        // Cream si salvam utilizatorul
        const id = randomUUID();

        db.prepare(`
            INSERT INTO users
            (id, username, email, password_hash, public_key)
            VALUES (?, ?, ?, ?, ?)
        `).run(id, cleanUsername, cleanEmail, passwordHash, publicKey);

        return res.status(201).json({
            message: "User registered successfully",
            user: {
                id,
                username: cleanUsername,
                email: cleanEmail
            }
        });

    } catch (error) {
        if (String(error.message).includes("UNIQUE constraint failed")) {
            return res.status(409).json({
                error: "Username or email already exists"
            });
        }

        console.error("Registration error:", error);

        return res.status(500).json({
            error: "Internal server error"
        });
    }
});

module.exports = router;
