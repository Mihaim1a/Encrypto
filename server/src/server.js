
"use strict";

const express = require("express");
const cookieParser = require("cookie-parser");
const helmet = require("helmet");
const http = require("node:http");

const { setupRealtime } = require("./realtime");
const { enforceOrigin } = require("./security");
const { purgeEligibleMessages } = require("./message-retention");

const db = require("./database");

const usersRoutes = require("./routes/users");
const authRoutes = require("./routes/auth");
const keysRoutes = require("./routes/keys");
const chatsRoutes = require("./routes/chats");
const secureMessagesRoutes = require("./routes/secure-messages");

const { requireAuth } = require("./session");

const app = express();
const PORT = 3000;

const isProduction = process.env.NODE_ENV === "production";
const CLEANUP_INTERVAL_MS = 60 * 1000;

let cleanupTimer = null;

// Reduce unnecessary framework information.
app.disable("x-powered-by");

// Apply browser security headers.
app.use(helmet({
    // Configure CSP after the frontend architecture is finalized.
    contentSecurityPolicy: false,

    // Avoid blocking resources needed during frontend integration.
    crossOriginEmbedderPolicy: false,

    // Enable HSTS in production, not for local HTTP development.
    strictTransportSecurity: isProduction
}));

// Parse incoming requests.
app.use(express.json({ limit: "16kb" }));
app.use(cookieParser());

// Protect against untrusted request origins.
app.use(enforceOrigin);

// Prevent caching API responses.
app.use("/api", (req, res, next) => {
    res.set("Cache-Control", "no-store");
    next();
});

// Authentication and application routes.
app.use("/api/auth", authRoutes);
app.use("/api/users", usersRoutes);
app.use("/api/keys", keysRoutes);
app.use("/api/chats", chatsRoutes);
app.use("/api/secure-messages", secureMessagesRoutes);

// Return the authenticated user.
app.get("/api/me", requireAuth, (req, res) => {
    res.json({
        user: req.user
    });
});

// Check backend health.
app.get("/api/health", (req, res) => {
    const result = db.prepare("SELECT 1 AS ok").get();

    res.json({
        status: "online",
        database: result.ok === 1 ? "connected" : "error",
        message: "Encrypto backend is running!"
    });
});

// Remove expired ciphertext and sessions.
function runMaintenance() {
    try {
        const cleared = purgeEligibleMessages();

        if (cleared > 0) {
            console.log(
                `[Retention] Cleared ${cleared} encrypted payload(s)`
            );
        }
    } catch (error) {
        console.error(
            "[Retention] Cleanup failed:",
            error.message
        );
    }

    try {
        const result = db.prepare(`
            DELETE FROM sessions
            WHERE expires_at <= ?
        `).run(Date.now());

        if (result.changes > 0) {
            console.log(
                `[Sessions] Removed ${result.changes} expired session(s)`
            );
        }
    } catch (error) {
        console.error(
            "[Sessions] Cleanup failed:",
            error.message
        );
    }
}

// Create the HTTP server.
const server = http.createServer(app);

// Attach authenticated WebSocket notifications.
setupRealtime(server);

// Stop the maintenance timer when the server closes.
server.on("close", () => {
    if (cleanupTimer !== null) {
        clearInterval(cleanupTimer);
        cleanupTimer = null;
    }

    console.log("[Maintenance] Cleanup scheduler stopped");
});

// Start Encrypto.
server.listen(PORT, "127.0.0.1", () => {
    console.log(`Server running on http://localhost:${PORT}`);

    runMaintenance();

    cleanupTimer = setInterval(
        runMaintenance,
        CLEANUP_INTERVAL_MS
    );

    cleanupTimer.unref();

    console.log(
        "[Maintenance] Automatic cleanup enabled (every 60 seconds)"
    );
});
