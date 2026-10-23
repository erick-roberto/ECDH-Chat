
const { pool } = require('../config/database');
const { publicKeys } = require('../state/runtimeState');
const { logEvent, logError } = require('../utils/logger');

async function loadPersistedPublicKeys() {
    logEvent('DATABASE', 'Carregando chaves públicas persistidas');
    const result = await pool.query(`
        SELECT user_id, public_key
        FROM users
    `);

    publicKeys.clear();

    for (const row of result.rows) {
        publicKeys.set(row.user_id, row.public_key);
    }

    logEvent('DATABASE', 'Chaves públicas carregadas para memória', { count: result.rowCount, users: result.rows.map(row => ({ userID: row.user_id, publicKey: row.public_key })) });
}

async function persistUserPublicKey(userID, publicKey) {
    logEvent('DATABASE', 'Persistindo/validando chave pública do usuário', { userID, publicKey });
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

    logEvent('DATABASE', 'Resultado da persistência da chave pública', { userID, success: Boolean(result.rows[0]), row: result.rows[0] || null });
    return result.rows[0] || null;
}

async function getPersistedPublicKey(userID) {
    logEvent('DATABASE', 'Consultando chave pública', { userID });
    const result = await pool.query(
        `
        SELECT public_key
        FROM users
        WHERE user_id = $1
        `,
        [userID]
    );

    const publicKey = result.rows[0]?.public_key || null;
    logEvent('DATABASE', 'Consulta de chave pública concluída', { userID, found: Boolean(publicKey), publicKey });
    return publicKey;
}

module.exports = {
    loadPersistedPublicKeys,
    persistUserPublicKey,
    getPersistedPublicKey,
};
