
const { DatabaseSync } = require("node:sqlite");
const { createHash } = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

// Cream folderul unde vom salva baza de date
const dataFolder = path.join(__dirname, "../data");

fs.mkdirSync(dataFolder, { recursive: true });

// Deschidem baza de date SQLite
const databasePath = process.env.ENCRYPTO_DB_PATH || path.join(dataFolder, "encrypto.db");
const db = new DatabaseSync(databasePath);

// Activam verificarea legaturilor dintre tabele
db.exec("PRAGMA busy_timeout = 5000");

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


db.exec(`
    CREATE TABLE IF NOT EXISTS user_crypto (
        user_id TEXT PRIMARY KEY
            REFERENCES users(id) ON DELETE CASCADE,

        contact_code TEXT NOT NULL UNIQUE,
        identity_key TEXT NOT NULL,
        identity_dh_key TEXT NOT NULL,
        identity_binding TEXT NOT NULL,

        signed_prekey_id INTEGER NOT NULL,
        signed_prekey_public TEXT NOT NULL,
        signed_prekey_signature TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS one_time_prekeys (
        user_id TEXT NOT NULL
            REFERENCES users(id) ON DELETE CASCADE,

        key_id INTEGER NOT NULL,
        public_key TEXT NOT NULL,

        PRIMARY KEY (user_id, key_id)
    );

    CREATE TABLE IF NOT EXISTS key_enrollment_challenges (
        user_id TEXT PRIMARY KEY
            REFERENCES users(id) ON DELETE CASCADE,

        challenge TEXT NOT NULL,
        expires_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS direct_chats (
        id TEXT PRIMARY KEY,

        user_a TEXT NOT NULL REFERENCES users(id),
        user_b TEXT NOT NULL REFERENCES users(id),

        requested_by TEXT NOT NULL REFERENCES users(id),

        status TEXT NOT NULL
            CHECK(status IN ('pending', 'active', 'declined')),

        created_at TEXT NOT NULL,

        UNIQUE(user_a, user_b)
    );

    CREATE TABLE IF NOT EXISTS secure_messages (
        id TEXT PRIMARY KEY,

        sender_id TEXT NOT NULL REFERENCES users(id),
        recipient_id TEXT NOT NULL REFERENCES users(id),

        client_message_id TEXT NOT NULL,
        envelope_json TEXT NOT NULL,

        created_at TEXT NOT NULL,
        acknowledged_at TEXT,

        UNIQUE(sender_id, client_message_id)
    );

    CREATE INDEX IF NOT EXISTS idx_secure_inbox
    ON secure_messages(
        recipient_id,
        acknowledged_at,
        created_at
    );
`);

const MESSAGE_RETENTION_MS = 7 * 24 * 60 * 60 * 1000;

// Add retention fields without deleting existing messages.
const secureMessageColumns = new Set(
    db.prepare("PRAGMA table_info(secure_messages)")
        .all()
        .map(column => column.name)
);

if (!secureMessageColumns.has("expires_at")) {
    db.exec(`
        ALTER TABLE secure_messages
        ADD COLUMN expires_at INTEGER
    `);
}

if (!secureMessageColumns.has("envelope_hash")) {
    db.exec(`
        ALTER TABLE secure_messages
        ADD COLUMN envelope_hash TEXT
    `);
}

if (!secureMessageColumns.has("purged_at")) {
    db.exec(`
        ALTER TABLE secure_messages
        ADD COLUMN purged_at INTEGER
    `);
}

db.exec(`
    CREATE INDEX IF NOT EXISTS idx_secure_messages_expiry
    ON secure_messages(expires_at)
`);

// Populate retention metadata for previously stored messages.
const oldMessages = db.prepare(`
    SELECT
        id,
        envelope_json,
        created_at,
        expires_at,
        envelope_hash
    FROM secure_messages
    WHERE expires_at IS NULL
       OR envelope_hash IS NULL
`).all();

const updateOldMessage = db.prepare(`
    UPDATE secure_messages
    SET
        expires_at = COALESCE(expires_at, ?),
        envelope_hash = COALESCE(envelope_hash, ?)
    WHERE id = ?
`);

for (const message of oldMessages) {
    const created = Date.parse(message.created_at);

    const expiresAt = (
        Number.isFinite(created) ? created : Date.now()
    ) + MESSAGE_RETENTION_MS;

    const envelopeHash = createHash("sha256")
        .update(message.envelope_json, "utf8")
        .digest("hex");

    updateOldMessage.run(
        expiresAt,
        envelopeHash,
        message.id
    );
}

console.log("Encrypto message retention schema ready!");

// Keep a permanent record of published signed-prekey IDs.
db.exec(`
    CREATE TABLE IF NOT EXISTS signed_prekey_history (
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        key_id INTEGER NOT NULL,
        published_at INTEGER NOT NULL,
        PRIMARY KEY (user_id, key_id)
    );
`);

// Preserve the active key IDs from before this migration.
db.prepare(`
    INSERT OR IGNORE INTO signed_prekey_history
        (user_id, key_id, published_at)
    SELECT user_id, signed_prekey_id, ?
    FROM user_crypto
`).run(Date.now());
module.exports = db;
