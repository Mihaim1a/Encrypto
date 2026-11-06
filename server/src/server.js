
const express = require("express");
const cookieParser = require("cookie-parser");

const db = require("./database");
const usersRoutes = require("./routes/users");
const authRoutes = require("./routes/auth");
const messagesRoutes = require("./routes/messages");
const { requireAuth } = require("./session");

const app = express();
const PORT = 3000;

// Permitem primirea datelor JSON
app.use(express.json({ limit: "16kb" }));
app.use(cookieParser());

// Rutele de autentificare
app.use("/api/auth", authRoutes);
app.use("/api/users", usersRoutes);
app.use("/api/messages", messagesRoutes);

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
app.listen(PORT, "127.0.0.1", () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
