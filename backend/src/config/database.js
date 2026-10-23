
require('dotenv').config();

const { Pool } = require('pg');

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

module.exports = { pool, testDatabaseConnection };
