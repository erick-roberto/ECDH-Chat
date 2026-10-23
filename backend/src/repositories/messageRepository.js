const { pool } = require('../config/database');

const {
    compactHexToUuid,
    uuidToCompactHex,
} = require('../utils/identifiers');
const { logEvent, logError } = require('../utils/logger');

async function persistDirectMessage(packet) {
    logEvent('DATABASE', 'Inserindo mensagem direta criptografada', { messageId: packet.messageId, senderID: packet.senderID, receiverID: packet.receiverID, algorithm: packet.algorithm, version: packet.version, c1: packet.c1, c2: packet.c2, signature: packet.signature, status: 'pending' });
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

    logEvent('DATABASE', 'Mensagem direta inserida', { databaseID: result.rows[0].id, messageId: packet.messageId });
    return result.rows[0].id;
}

async function persistGroupMessages(packets) {
    if (!Array.isArray(packets) || packets.length === 0) {
        return [];
    }

    logEvent('DATABASE', 'Iniciando transação para persistir mensagens de grupo', { count: packets.length, groupID: packets[0]?.groupID, messageId: packets[0]?.messageId });
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
        logEvent('DATABASE', 'Transação de mensagens de grupo confirmada', { count: savedMessages.length, databaseIDs: savedMessages.map(item => item.dbId) });

        return savedMessages;
    } catch (error) {
        await client.query('ROLLBACK');
        logError('DATABASE', 'Transação de mensagens de grupo revertida', error);
        throw error;
    } finally {
        client.release();
    }
}


async function getPendingMessages(userID) {
    logEvent('DATABASE', 'Consultando mensagens pendentes', { userID });
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

    const messages = result.rows.map(row => {
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
    logEvent('DATABASE', 'Mensagens pendentes recuperadas', { userID, count: messages.length, messages });
    return messages;
}


async function markMessagesDelivered(messageIDs, receiverID) {
    if (!Array.isArray(messageIDs) || messageIDs.length === 0) {
        return;
    }

    logEvent('DATABASE', 'Atualizando status das mensagens para delivered', { messageIDs, receiverID });
    const result = await pool.query(
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
    logEvent('DATABASE', 'Atualização de entrega concluída', { receiverID, requestedCount: messageIDs.length, updatedCount: result.rowCount });
}


async function getDirectHistory(userID, peerID) {
    logEvent('DATABASE', 'Consultando histórico direto', { userID, peerID });
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

    const messages = result.rows.map(row => ({
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
    logEvent('DATABASE', 'Histórico direto recuperado', { userID, peerID, count: messages.length, messages });
    return messages;
}

module.exports = {
    persistDirectMessage,
    persistGroupMessages,
    getPendingMessages,
    markMessagesDelivered,
    getDirectHistory,
};