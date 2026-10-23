
const { pool } = require('../config/database');
const { publicKeys } = require('../state/runtimeState');

async function loadPersistedPublicKeys() {
    const result = await pool.query(`
        SELECT user_id, public_key
        FROM users
    `);

    publicKeys.clear();

    for (const row of result.rows) {
        publicKeys.set(row.user_id, row.public_key);
    }

    console.log(`Chaves públicas carregadas: ${result.rowCount}`);
}

async function persistUserPublicKey(userID, publicKey) {
    const result = await pool.query(
        `
        INSERT INTO users (
            user_id, public_key, created_at, updated_at
        )
        VALUES ($1, $2, NOW(), NOW())
        ON CONFLICT (user_id)
        DO UPDATE SET updated_at = NOW()
        WHERE users.public_key = EXCLUDED.public_key
        RETURNING user_id, public_key
        `,
        [userID, publicKey]
    );

    return result.rows[0] || null;
}

async function getPersistedPublicKey(userID) {
    const result = await pool.query(
        `
        SELECT public_key
        FROM users
        WHERE user_id = $1
        `,
        [userID]
    );

    return result.rows[0]?.public_key || null;
}

module.exports = {
    loadPersistedPublicKeys,
    persistUserPublicKey,
    getPersistedPublicKey,
};
