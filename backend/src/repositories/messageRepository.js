const { pool } = require('../config/database');

const {
    compactHexToUuid,
    uuidToCompactHex,
} = require('../utils/identifiers');

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
            packet.ePub,
            packet.ciphertext,
            packet.signature,
            JSON.stringify(packet),
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
                    packet.ePub,
                    packet.ciphertext,
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
            algorithm,
            version,
            c1,
            c2,
            signature,
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
        const createdAt = new Date(row.created_at).getTime();

        const packet = {
            ...payload,
            type: row.message_type,
            version: row.version ?? payload.version,
            algorithm: row.algorithm ?? payload.algorithm,
            senderID: row.sender_id,
            receiverID: row.receiver_id,
            messageId: uuidToCompactHex(row.message_id),
            ePub: payload.ePub ?? row.c1,
            iv: payload.iv,
            ciphertext: payload.ciphertext ?? row.c2,
            signature: payload.signature ?? row.signature,
            sentAt: Number(payload.sentAt ?? createdAt),
            timestamp: payload.timestamp ?? createdAt,
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


async function discardPendingMessages(receiverID) {
    await pool.query(
        `
        UPDATE messages
        SET delivery_status = 'delivered',
            delivered_at = NOW()
        WHERE receiver_id = $1
          AND delivery_status = 'pending'
        `,
        [receiverID]
    );
}

async function getDirectHistory(userID, peerID) {    const result = await pool.query(
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

    return result.rows.map(row => {
        const payload = row.encrypted_payload ?? {};
        const createdAt = new Date(row.created_at).getTime();

        return {
            ...payload,
            type: 'direct',
            version: row.version,
            algorithm: row.algorithm,
            senderID: row.sender_id,
            receiverID: row.receiver_id,
            messageId: uuidToCompactHex(row.message_id),
            ePub: payload.ePub ?? row.c1,
            iv: payload.iv,
            ciphertext: payload.ciphertext ?? row.c2,
            signature: payload.signature ?? row.signature,
            sentAt: Number(payload.sentAt ?? createdAt),
            timestamp: payload.timestamp ?? createdAt,
        };
    });
}

module.exports = {
    persistDirectMessage,
    persistGroupMessages,
    getPendingMessages,
    markMessagesDelivered,
    discardPendingMessages,
    getDirectHistory,
};