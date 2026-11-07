
"use strict";

const { randomBytes, createHash } = require("node:crypto");
const db = require("./database");

const isProduction = process.env.NODE_ENV === "production";

const COOKIE_NAME = isProduction
    ? "__Host-encrypto_session"
    : "encrypto_session";

const SESSION_DURATION = 24 * 60 * 60 * 1000;

const cookieOptions = {
    httpOnly: true,
    secure: isProduction,
    sameSite: "strict",
    path: "/"
};

function hashToken(token) {
    return createHash("sha256")
        .update(token)
        .digest("hex");
}

function createSession(userId, res) {
    const token = randomBytes(32).toString("hex");
    const tokenHash = hashToken(token);
    const expiresAt = Date.now() + SESSION_DURATION;

    db.prepare(`
        INSERT INTO sessions (token_hash, user_id, expires_at)
        VALUES (?, ?, ?)
    `).run(tokenHash, userId, expiresAt);

    res.cookie(COOKIE_NAME, token, {
        ...cookieOptions,
        maxAge: SESSION_DURATION
    });
}

// Shared session validation for HTTP and WebSocket.
function authenticateToken(token) {
    if (
        typeof token !== "string" ||
        !/^[a-f0-9]{64}$/.test(token)
    ) {
        return null;
    }

    const tokenHash = hashToken(token);

    const user = db.prepare(`
        SELECT u.id, u.username, u.email
        FROM sessions s
        JOIN users u ON u.id = s.user_id
        WHERE s.token_hash = ?
          AND s.expires_at > ?
    `).get(tokenHash, Date.now());

    if (!user) {
        return null;
    }

    return { user, tokenHash };
}

function requireAuth(req, res, next) {
    const session = authenticateToken(
        req.cookies?.[COOKIE_NAME]
    );

    if (!session) {
        return res.status(401).json({
            error: "Authentication required"
        });
    }

    req.user = session.user;
    req.sessionTokenHash = session.tokenHash;

    next();
}

// Read the existing session cookie from a WebSocket handshake.
function authenticateCookieHeader(cookieHeader) {
    if (
        typeof cookieHeader !== "string" ||
        cookieHeader.length > 8192
    ) {
        return null;
    }

    const prefix = COOKIE_NAME + "=";

    const tokens = cookieHeader
        .split(";")
        .map(part => part.trim())
        .filter(part => part.startsWith(prefix))
        .map(part => part.slice(prefix.length));

    // Reject ambiguous duplicate session cookies.
    if (tokens.length !== 1) {
        return null;
    }

    return authenticateToken(tokens[0]);
}

// Recheck sessions after WebSocket authentication.
// Logout or expiry invalidates further notifications.
function isSessionActive(userId, tokenHash) {
    const row = db.prepare(`
        SELECT 1 AS valid
        FROM sessions
        WHERE token_hash = ?
          AND user_id = ?
          AND expires_at > ?
    `).get(tokenHash, userId, Date.now());

    return Boolean(row);
}

function destroySession(req, res) {
    db.prepare(`
        DELETE FROM sessions
        WHERE token_hash = ?
    `).run(req.sessionTokenHash);

    res.clearCookie(COOKIE_NAME, cookieOptions);
}

module.exports = {
    createSession,
    requireAuth,
    destroySession,
    authenticateCookieHeader,
    isSessionActive
};
