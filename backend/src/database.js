
require('dotenv').config();

const { Pool } = require('pg');

const users = new Map();       // Sockets conectados; temporário
const publicKeys = new Map();  // Cache de chaves públicas
const messageQueue = new Map(); // Será migrado na etapa de mensagens
const groups = new Map();       // Será migrado na etapa de grupos

const pool = new Pool({
    host: process.env.DB_HOST,
    port: Number(process.env.DB_PORT || 5432),
    database: process.env.DB_NAME,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,

    ssl: process.env.DB_SSL === 'true'
        ? { rejectUnauthorized: true }
        : false,

    connectionTimeoutMillis: 10000,
    idleTimeoutMillis: 30000,
    max: 10,
});

pool.on('error', error => {
    console.error(
        'Erro inesperado no pool PostgreSQL:',
        error.message
    );
});

async function testDatabaseConnection() {
    const result = await pool.query(`
        SELECT
            current_database() AS database,
            current_user AS username,
            NOW() AS server_time
    `);

    console.log('Conexão PostgreSQL estabelecida.');
    console.log('Banco:', result.rows[0].database);
    console.log('Usuário:', result.rows[0].username);
    console.log('Horário do servidor:', result.rows[0].server_time);
}

/**
 * Carrega as chaves públicas persistidas no PostgreSQL
 * para o cache usado pelas funcionalidades atuais do Socket.IO.
 */
async function loadPersistedPublicKeys() {
    const result = await pool.query(`
        SELECT user_id, public_key
        FROM users
    `);

    publicKeys.clear();

    for (const row of result.rows) {
        publicKeys.set(row.user_id, row.public_key);
    }

    console.log(
        `Chaves públicas carregadas: ${result.rowCount}`
    );
}

/**
 * Registra um usuário ou confirma a chave já cadastrada.
 *
 * A chave pública existente nunca é substituída por outra.
 * Retorna os dados do usuário se a chave for compatível;
 * retorna null se o mesmo user_id já possuir outra chave.
 */
async function persistUserPublicKey(userID, publicKey) {
    const result = await pool.query(
        `
        INSERT INTO users (
            user_id,
            public_key,
            created_at,
            updated_at
        )
        VALUES ($1, $2, NOW(), NOW())
        ON CONFLICT (user_id)
        DO UPDATE SET
            updated_at = NOW()
        WHERE users.public_key = EXCLUDED.public_key
        RETURNING user_id, public_key
        `,
        [userID, publicKey]
    );

    return result.rows[0] || null;
}

/**
 * Consulta a chave pública persistida no banco.
 */
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
    users,
    publicKeys,
    messageQueue,
    groups,
    pool,
    testDatabaseConnection,
    loadPersistedPublicKeys,
    persistUserPublicKey,
    getPersistedPublicKey,
};
