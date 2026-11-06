
"use strict";

const db = require("./database");

const CLEANUP_BATCH_SIZE = 500;

const cleanupStatement = db.prepare(`
    UPDATE secure_messages
    SET
        envelope_json = '',
        purged_at = ?
    WHERE id IN (
        SELECT id
        FROM secure_messages
        WHERE envelope_json <> ''
          AND (
              acknowledged_at IS NOT NULL
              OR (
                  expires_at IS NOT NULL
                  AND expires_at <= ?
              )
          )
        ORDER BY created_at ASC, id ASC
        LIMIT ?
    )
`);

function purgeEligibleMessages(now = Date.now()) {
    if (!Number.isSafeInteger(now) || now < 0) {
        throw new TypeError("Invalid cleanup timestamp");
    }

    const result = cleanupStatement.run(
        now,
        now,
        CLEANUP_BATCH_SIZE
    );

    return result.changes;
}

module.exports = {
    purgeEligibleMessages
};
