
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

// Transformam tokenul intr-un hash
function hashToken(token) {
    return createHash("sha256")
        .update(token)
        .digest("hex");
}

// Cream o sesiune dupa login
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

// Verificam daca utilizatorul este autentificat
function requireAuth(req, res, next) {
    const token = req.cookies?.[COOKIE_NAME];

    if (typeof token !== "string" ||
        !/^[a-f0-9]{64}$/.test(token)) {
        return res.status(401).json({
            error: "Authentication required"
        });
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
        return res.status(401).json({
            error: "Invalid or expired session"
        });
    }

    req.user = user;
    req.sessionTokenHash = tokenHash;

    next();
}

// Inchidem sesiunea la logout
function destroySession(req, res) {
    db.prepare(
        "DELETE FROM sessions WHERE token_hash = ?"
    ).run(req.sessionTokenHash);

    res.clearCookie(COOKIE_NAME, cookieOptions);
}

module.exports = {
    createSession,
    requireAuth,
    destroySession
};
