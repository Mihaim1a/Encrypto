
"use strict";

const express = require("express");
const cookieParser = require("cookie-parser");
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

const CLEANUP_INTERVAL_MS = 60 * 1000;

let cleanupTimer = null;

// Middleware.
app.use(express.json({ limit: "16kb" }));
app.use(cookieParser());
app.use(enforceOrigin);

// API routes.
app.use("/api/auth", authRoutes);
app.use("/api/users", usersRoutes);
app.use("/api/keys", keysRoutes);
app.use("/api/chats", chatsRoutes);
app.use("/api/secure-messages", secureMessagesRoutes);

// Current authenticated user.
app.get("/api/me", requireAuth, (req, res) => {
    res.set("Cache-Control", "no-store");

    res.json({
        user: req.user
    });
});

// Health check.
app.get("/api/health", (req, res) => {
    const result = db.prepare("SELECT 1 AS ok").get();

    res.json({
        status: "online",
        database: result.ok === 1 ? "connected" : "error",
        message: "Encrypto backend is running!"
    });
});

// Remove expired ciphertext and expired sessions.
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

// HTTP server.
const server = http.createServer(app);

// Authenticated WebSocket notifications.
setupRealtime(server);

// Stop maintenance when the server closes.
server.on("close", () => {
    if (cleanupTimer !== null) {
        clearInterval(cleanupTimer);
        cleanupTimer = null;
    }

    console.log("[Maintenance] Cleanup scheduler stopped");
});

// Start the backend.
server.listen(PORT, "127.0.0.1", () => {
    console.log(`Server running on http://localhost:${PORT}`);

    // Run immediately on startup.
    runMaintenance();

    // Run again every 60 seconds.
    cleanupTimer = setInterval(
        runMaintenance,
        CLEANUP_INTERVAL_MS
    );

    cleanupTimer.unref();

    console.log(
        "[Maintenance] Automatic cleanup enabled (every 60 seconds)"
    );
});
