
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

// Run message cleanup every 60 seconds.
const CLEANUP_INTERVAL_MS = 60 * 1000;

let cleanupTimer = null;

// Parse JSON and cookies.
app.use(express.json({ limit: "16kb" }));
app.use(cookieParser());

// Protect requests against untrusted origins.
app.use(enforceOrigin);

// API routes.
app.use("/api/auth", authRoutes);
app.use("/api/users", usersRoutes);
app.use("/api/keys", keysRoutes);
app.use("/api/chats", chatsRoutes);
app.use("/api/secure-messages", secureMessagesRoutes);

// Return the authenticated user.
app.get("/api/me", requireAuth, (req, res) => {
    res.set("Cache-Control", "no-store");

    res.json({
        user: req.user
    });
});

// Check server and database status.
app.get("/api/health", (req, res) => {
    const result = db.prepare("SELECT 1 AS ok").get();

    res.json({
        status: "online",
        database: result.ok === 1 ? "connected" : "error",
        message: "Encrypto backend is running!"
    });
});

// Safely clear expired and previously acknowledged ciphertext.
function runMessageCleanup() {
    try {
        const cleared = purgeEligibleMessages();

        if (cleared > 0) {
            console.log(
                `[Retention] Cleared ${cleared} encrypted payload(s)`
            );
        }

        return cleared;
    } catch (error) {
        console.error(
            "[Retention] Cleanup failed:",
            error.message
        );

        return 0;
    }
}

// Create the HTTP server.
const server = http.createServer(app);

// Attach authenticated WebSocket support.
setupRealtime(server);

// Stop the cleanup timer when the HTTP server closes.
server.on("close", () => {
    if (cleanupTimer !== null) {
        clearInterval(cleanupTimer);
        cleanupTimer = null;
    }

    console.log("[Retention] Cleanup scheduler stopped");
});

// Start the backend.
server.listen(PORT, "127.0.0.1", () => {
    console.log(`Server running on http://localhost:${PORT}`);

    // Initial cleanup on startup.
    runMessageCleanup();

    // Repeat cleanup automatically.
    cleanupTimer = setInterval(
        runMessageCleanup,
        CLEANUP_INTERVAL_MS
    );

    // Do not keep Node.js alive solely for this timer.
    cleanupTimer.unref();

    console.log(
        "[Retention] Automatic cleanup enabled (every 60 seconds)"
    );
});
