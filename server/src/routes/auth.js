
"use strict";

const express = require("express");
const {
    randomUUID,
    randomBytes,
    scrypt,
    timingSafeEqual
} = require("node:crypto");

const { promisify } = require("node:util");
const { rateLimit } = require("express-rate-limit");

const db = require("../database");

const {
    createSession,
    requireAuth,
    destroySession
} = require("../session");

const router = express.Router();
const scryptAsync = promisify(scrypt);

// Limit login attempts.
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 10,
    standardHeaders: "draft-7",
    legacyHeaders: false,
    skipSuccessfulRequests: true,
    message: {
        error: "Too many login attempts"
    }
});

// Limit registration attempts.
const registerLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 20,
    standardHeaders: "draft-7",
    legacyHeaders: false,
    message: {
        error: "Too many registration attempts"
    }
});

// REGISTER
router.post("/register", registerLimiter, async (req, res) => {
    const { username, email, password, publicKey } = req.body || {};

    // Validate registration data.
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
        // Check whether username or email already exists.
        const existing = db.prepare(
            "SELECT id FROM users WHERE email = ? OR username = ?"
        ).get(cleanEmail, cleanUsername);

        if (existing) {
            return res.status(409).json({
                error: "Username or email already exists"
            });
        }

        // Generate a unique salt and hash the password.
        const salt = randomBytes(16).toString("hex");

        const hash = await scryptAsync(password, salt, 64, {
            N: 131072,
            r: 8,
            p: 1,
            maxmem: 256 * 1024 * 1024
        });

        const passwordHash =
            `scrypt$131072$8$1$${salt}$${hash.toString("hex")}`;

        // Store the user.
        const id = randomUUID();

        db.prepare(`
            INSERT INTO users
            (id, username, email, password_hash, public_key)
            VALUES (?, ?, ?, ?, ?)
        `).run(
            id,
            cleanUsername,
            cleanEmail,
            passwordHash,
            publicKey
        );

        return res.status(201).json({
            message: "User registered successfully",
            user: {
                id,
                username: cleanUsername,
                email: cleanEmail
            }
        });

    } catch (error) {
        if (
            String(error.message).includes(
                "UNIQUE constraint failed"
            )
        ) {
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

// Verify a password using the stored scrypt hash.
async function verifyPassword(password, savedHash) {
    if (typeof savedHash !== "string") {
        return false;
    }

    const parts = savedHash.split("$");

    if (parts.length !== 6) {
        return false;
    }

    const [algorithm, N, r, p, salt, expectedHex] = parts;

    if (
        algorithm !== "scrypt" ||
        N !== "131072" ||
        r !== "8" ||
        p !== "1" ||
        !/^[0-9a-f]{32}$/.test(salt) ||
        !/^[0-9a-f]{128}$/.test(expectedHex)
    ) {
        return false;
    }

    const calculated = await scryptAsync(password, salt, 64, {
        N: 131072,
        r: 8,
        p: 1,
        maxmem: 256 * 1024 * 1024
    });

    return timingSafeEqual(
        calculated,
        Buffer.from(expectedHex, "hex")
    );
}

// LOGIN
router.post("/login", loginLimiter, async (req, res) => {
    const { email, password } = req.body || {};

    // Validate login data.
    if (
        typeof email !== "string" ||
        typeof password !== "string" ||
        !email.trim() ||
        !password ||
        email.length > 254 ||
        password.length > 128
    ) {
        return res.status(400).json({
            error: "Invalid login data"
        });
    }

    try {
        // Find the user by email.
        const user = db.prepare(`
            SELECT
                id,
                username,
                email,
                password_hash
            FROM users
            WHERE email = ?
        `).get(email.trim().toLowerCase());

        // Use a dummy hash for nonexistent accounts
        // to reduce timing differences.
        const dummyHash =
            "scrypt$131072$8$1$" +
            "0".repeat(32) + "$" +
            "0".repeat(128);

        const validPassword = await verifyPassword(
            password,
            user ? user.password_hash : dummyHash
        );

        if (!user || !validPassword) {
            return res.status(401).json({
                error: "Invalid email or password"
            });
        }

        // Create the authenticated session.
        createSession(user.id, res);

        res.set("Cache-Control", "no-store");

        return res.json({
            message: "Login successful",
            user: {
                id: user.id,
                username: user.username,
                email: user.email
            }
        });

    } catch (error) {
        console.error("Login error:", error);

        return res.status(500).json({
            error: "Internal server error"
        });
    }
});

// LOGOUT
router.post("/logout", requireAuth, (req, res) => {
    destroySession(req, res);

    return res.json({
        message: "Logout successful"
    });
});

module.exports = router;
