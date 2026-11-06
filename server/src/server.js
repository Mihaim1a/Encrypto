
const express = require("express");
const cookieParser = require("cookie-parser");
const http = require("node:http");
const { setupRealtime } = require("./realtime");
const { enforceOrigin } = require("./security");

const db = require("./database");
const usersRoutes = require("./routes/users");
const authRoutes = require("./routes/auth");
const keysRoutes = require("./routes/keys");
const chatsRoutes = require("./routes/chats");
const secureMessagesRoutes = require("./routes/secure-messages");
const { requireAuth } = require("./session");

const app = express();
const PORT = 3000;

// Permitem primirea datelor JSON
app.use(express.json({ limit: "16kb" }));
app.use(cookieParser());
app.use(enforceOrigin);

// Rutele de autentificare
app.use("/api/auth", authRoutes);
app.use("/api/users", usersRoutes);
app.use("/api/keys", keysRoutes);
app.use("/api/chats", chatsRoutes);
app.use("/api/secure-messages", secureMessagesRoutes);

// Returnam utilizatorul autentificat
app.get("/api/me", requireAuth, (req, res) => {
    res.set("Cache-Control", "no-store");

    res.json({
        user: req.user
    });
});

// Verificam serverul si baza de date
app.get("/api/health", (req, res) => {
    const result = db.prepare("SELECT 1 AS ok").get();

    res.json({
        status: "online",
        database: result.ok === 1 ? "connected" : "error",
        message: "Encrypto backend is running!"
    });
});

// Pornim serverul
const server = http.createServer(app);

setupRealtime(server);

server.listen(PORT, "127.0.0.1", () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
