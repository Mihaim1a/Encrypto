const express = require("express");
const db = require("./database");
const authRoutes = require("./routes/auth");

const app = express();
const PORT = 3000;

// Permite serverului sa primeasca date JSON
app.use(express.json());

// Conectam rutele pentru autentificare
app.use("/api/auth", authRoutes);

// Verificam daca serverul functioneaza
app.get("/api/health", (req, res) => {
    const result = db.prepare("SELECT 1 AS ok").get();

    res.json({
        status: "online",
        database: result.ok === 1 ? "connected" : "error",
        message: "Encrypto backend is running!"
    });
});

// Pornim serverul local
app.listen(PORT, "127.0.0.1", () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
