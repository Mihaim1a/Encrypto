
const { DatabaseSync } = require("node:sqlite");
const fs = require("node:fs");
const path = require("node:path");

// Cream folderul unde vom salva baza de date
const dataFolder = path.join(__dirname, "../data");

fs.mkdirSync(dataFolder, { recursive: true });

// Deschidem baza de date SQLite
const databasePath = path.join(dataFolder, "encrypto.db");
const db = new DatabaseSync(databasePath);

// Activam verificarea legaturilor dintre tabele
db.exec("PRAGMA foreign_keys = ON");

// Cream tabelele daca nu exista deja
db.exec(`
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        public_key TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS groups (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        created_by TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (created_by) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS group_members (
        group_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        joined_at TEXT DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (group_id, user_id),
        FOREIGN KEY (group_id) REFERENCES groups(id)
            ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users(id)
            ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS group_keys (
        group_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        key_version INTEGER NOT NULL,
        encrypted_key TEXT NOT NULL,
        PRIMARY KEY (group_id, user_id, key_version),
        FOREIGN KEY (group_id, user_id)
            REFERENCES group_members(group_id, user_id)
            ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS messages (
        id TEXT PRIMARY KEY,
        group_id TEXT NOT NULL,
        sender_id TEXT NOT NULL,
        ciphertext TEXT NOT NULL,
        nonce TEXT NOT NULL,
        key_version INTEGER NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (group_id) REFERENCES groups(id)
            ON DELETE CASCADE,
        FOREIGN KEY (sender_id) REFERENCES users(id)
    );
`);

console.log("Encrypto database initialized!");


db.exec(`
    CREATE TABLE IF NOT EXISTS sessions (
        token_hash TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
            ON DELETE CASCADE
    );
`);

// Stergem sesiunile deja expirate la pornire
db.prepare(
    "DELETE FROM sessions WHERE expires_at <= ?"
).run(Date.now());

db.exec(`
    CREATE TABLE IF NOT EXISTS direct_messages (
        id TEXT PRIMARY KEY,
        sender_id TEXT NOT NULL,
        recipient_id TEXT NOT NULL,
        encrypted_envelope TEXT NOT NULL,
        envelope_version INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (sender_id) REFERENCES users(id),
        FOREIGN KEY (recipient_id) REFERENCES users(id)
    );

    CREATE INDEX IF NOT EXISTS idx_direct_messages_users
    ON direct_messages(sender_id, recipient_id, created_at);
`);

module.exports = db;
