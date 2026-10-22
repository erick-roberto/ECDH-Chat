
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


function compactHexToUuid(value) {
    if (typeof value !== 'string' || !/^[0-9a-f]{32}$/i.test(value)) {
        throw new Error('Identificador hexadecimal inválido.');
    }

    return [
        value.slice(0, 8),
        value.slice(8, 12),
        value.slice(12, 16),
        value.slice(16, 20),
        value.slice(20, 32),
    ].join('-');
}

function uuidToCompactHex(value) {
    return value.replace(/-/g, '');
}

async function persistDirectMessage(packet) {
    const result = await pool.query(
        `
        INSERT INTO messages (
            message_id,
            message_type,
            sender_id,
            receiver_id,
            group_id,
            algorithm,
            version,
            c1,
            c2,
            signature,
            encrypted_payload,
            delivery_status
        )
        VALUES (
            $1::uuid,
            'direct',
            $2,
            $3,
            NULL,
            $4,
            $5,
            $6,
            $7,
            $8,
            $9::jsonb,
            'pending'
        )
        RETURNING id
        `,
        [
            compactHexToUuid(packet.messageId),
            packet.senderID,
            packet.receiverID,
            packet.algorithm,
            packet.version,
            packet.c1,
            packet.c2,
            packet.signature,
            JSON.stringify({
                sentAt: packet.sentAt,
                timestamp: packet.timestamp,
            }),
        ]
    );

    return result.rows[0].id;
}

async function persistGroupMessages(packets) {
    if (!Array.isArray(packets) || packets.length === 0) {
        return [];
    }

    const client = await pool.connect();

    try {
        await client.query('BEGIN');

        const savedMessages = [];

        for (const packet of packets) {
            const result = await client.query(
                `INSERT INTO messages (
                    message_id,
                    message_type,
                    sender_id,
                    receiver_id,
                    group_id,
                    algorithm,
                    version,
                    c1,
                    c2,
                    signature,
                    encrypted_payload,
                    created_at,
                    delivery_status
                )
                VALUES (
                    $1::uuid,
                    'group',
                    $2,
                    $3,
                    $4::uuid,
                    $5,
                    $6,
                    $7,
                    $8,
                    $9,
                    $10::jsonb,
                    NOW(),
                    'pending'
                )
                RETURNING id`,
                [
                    compactHexToUuid(packet.messageId),
                    packet.senderID,
                    packet.receiverID,
                    compactHexToUuid(packet.groupID),
                    packet.algorithm,
                    packet.version,
                    packet.c1,
                    packet.c2,
                    packet.signature,
                    JSON.stringify(packet),
                ]
            );

            savedMessages.push({
                dbId: result.rows[0].id,
                packet,
            });
        }

        await client.query('COMMIT');

        return savedMessages;
    } catch (error) {
        await client.query('ROLLBACK');
        throw error;
    } finally {
        client.release();
    }
}


async function getPendingMessages(userID) {
    const result = await pool.query(
        `
        SELECT
            id,
            message_type,
            message_id,
            sender_id,
            receiver_id,
            group_id,
            encrypted_payload,
            created_at
        FROM messages
        WHERE receiver_id = $1
          AND delivery_status = 'pending'
        ORDER BY created_at ASC, id ASC
        `,
        [userID]
    );

    return result.rows.map(row => {
        const payload = row.encrypted_payload ?? {};

        const packet = {
            ...payload,
            type: row.message_type,
            senderID: row.sender_id,
            receiverID: row.receiver_id,
            messageId: uuidToCompactHex(row.message_id),
            timestamp: payload.timestamp
                ?? new Date(row.created_at).getTime(),
        };

        if (row.group_id) {
            packet.groupID = uuidToCompactHex(row.group_id);
        }

        return {
            dbId: row.id,
            packet,
        };
    });
}


async function markMessagesDelivered(messageIDs, receiverID) {
    if (!Array.isArray(messageIDs) || messageIDs.length === 0) {
        return;
    }

    await pool.query(
        `
        UPDATE messages
        SET delivery_status = 'delivered',
            delivered_at = NOW()
        WHERE id = ANY($1::bigint[])
          AND receiver_id = $2
          AND delivery_status = 'pending'
        `,
        [messageIDs, receiverID]
    );
}


async function getDirectHistory(userID, peerID) {
    const result = await pool.query(
        `
        SELECT
            id,
            message_id,
            sender_id,
            receiver_id,
            algorithm,
            version,
            c1,
            c2,
            signature,
            encrypted_payload,
            created_at
        FROM messages
        WHERE message_type = 'direct'
          AND (
              (sender_id = $1 AND receiver_id = $2)
              OR
              (sender_id = $2 AND receiver_id = $1)
          )
        ORDER BY created_at ASC, id ASC
        `,
        [userID, peerID]
    );

    return result.rows.map(row => ({
        type: 'direct',
        version: row.version,
        algorithm: row.algorithm,
        senderID: row.sender_id,
        receiverID: row.receiver_id,
        messageId: row.message_id.replace(/-/g, ''),
        sentAt: Number(row.encrypted_payload.sentAt),
        c1: row.c1,
        c2: row.c2,
        signature: row.signature,
        timestamp: row.encrypted_payload.timestamp
            ?? new Date(row.created_at).getTime(),
    }));
}


let persistedGroupsLoadPromise = null;

/**
 * Persiste um grupo e seus membros em uma única transação.
 * O groupID recebido pelo protocolo contém 32 caracteres hexadecimais;
 * no PostgreSQL, ele é armazenado como UUID.
 */
async function persistGroup(groupID, group) {
    const databaseGroupID = compactHexToUuid(groupID);
    const client = await pool.connect();

    try {
        await client.query('BEGIN');

        await client.query(
            `
            INSERT INTO groups (
                group_id,
                created_by,
                signature,
                created_at
            )
            VALUES ($1::uuid, $2, $3, NOW())
            `,
            [databaseGroupID, group.createdBy, group.signature]
        );

        for (const memberID of group.members) {
            await client.query(
                `
                INSERT INTO group_members (
                    group_id,
                    user_id,
                    joined_at
                )
                VALUES ($1::uuid, $2, NOW())
                `,
                [databaseGroupID, memberID]
            );
        }

        await client.query('COMMIT');
    } catch (error) {
        await client.query('ROLLBACK');
        throw error;
    } finally {
        client.release();
    }
}

/**
 * Carrega os grupos e seus membros do PostgreSQL para o Map usado
 * pelo Socket.IO. A consulta é executada uma única vez por processo,
 * salvo se falhar.
 */
async function loadPersistedGroups() {
    if (persistedGroupsLoadPromise) {
        return persistedGroupsLoadPromise;
    }

    persistedGroupsLoadPromise = (async () => {
        const result = await pool.query(
            `
            SELECT
                g.group_id,
                g.created_by,
                g.signature,
                gm.user_id
            FROM groups g
            LEFT JOIN group_members gm
                ON gm.group_id = g.group_id
            ORDER BY g.created_at ASC, gm.user_id ASC
            `
        );

        const loadedGroups = new Map();

        for (const row of result.rows) {
            const groupID = uuidToCompactHex(row.group_id);

            if (!loadedGroups.has(groupID)) {
                loadedGroups.set(groupID, {
                    members: [],
                    createdBy: row.created_by,
                    signature: row.signature,
                });
            }

            if (row.user_id) {
                loadedGroups.get(groupID).members.push(row.user_id);
            }
        }

        groups.clear();

        for (const [groupID, group] of loadedGroups) {
            groups.set(groupID, group);
        }

        console.log(`Grupos carregados do PostgreSQL: ${groups.size}`);
    })();

    try {
        await persistedGroupsLoadPromise;
    } catch (error) {
        persistedGroupsLoadPromise = null;
        throw error;
    }
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
    persistDirectMessage,
    getPendingMessages,
    markMessagesDelivered,
    getDirectHistory,
    persistGroup,
    loadPersistedGroups,
    persistGroupMessages,
};
