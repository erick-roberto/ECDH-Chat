const crypto = require('crypto');
const { users, publicKeys, messageQueue, groups } = require('./database');

const ACK_TIMEOUT_MS = 5000;
const MAX_QUEUE_PER_USER = 500;
const MAX_GROUP_SIZE = 100;

const GROUP_ALGORITHM = 'EC-ElGamal-secp256k1-group-demo';

function reply(callback, data) {
    if (typeof callback === 'function') callback(data);
}

function isValidID(value) {
    return typeof value === 'string' &&
        value.trim().length > 0 &&
        value.length <= 128;
}

function isValidKey(value) {
    return typeof value === 'string' &&
        value.length > 0 &&
        value.length <= 4096;
}

function findSocketID(userID) {
    for (const [id, user] of users.entries()) {
        if (user.userID === userID) return id;
    }
    return null;
}

function onlineUserIDs() {
    return [...new Set(Array.from(users.values(), user => user.userID))];
}

function enqueue(userID, packet) {
    const queue = messageQueue.get(userID) || [];

    if (queue.length >= MAX_QUEUE_PER_USER) return false;

    queue.push(packet);
    messageQueue.set(userID, queue);
    return true;
}

function deliver(io, userID, event, packet) {
    const socketID = findSocketID(userID);

    if (socketID) {
        io.to(socketID).emit(event, packet);
        return { delivered: true, queued: false };
    }

    return {
        delivered: false,
        queued: enqueue(userID, packet),
    };
}

function flushQueue(socket, userID) {
    const pending = messageQueue.get(userID);
    if (!pending || pending.length === 0) return;

    const batch = [...pending];

    socket.timeout(ACK_TIMEOUT_MS).emit(
        'pending_messages',
        batch,
        err => {
            if (err) return;

            const remaining = (messageQueue.get(userID) || [])
                .filter(message => !batch.includes(message));

            if (remaining.length > 0) {
                messageQueue.set(userID, remaining);
            } else {
                messageQueue.delete(userID);
            }
        }
    );
}

function groupPublicData(groupID, group) {
    return {
        groupID,
        members: [...group.members],
        createdBy: group.createdBy,
        groupKeys: group.members.map(username => ({
            username,
            publicKey: publicKeys.get(username),
        })),
    };
}

function sendGroupsToUser(socket, userID) {
    const userGroups = [];

    for (const [groupID, group] of groups.entries()) {
        if (group.members.includes(userID)) {
            userGroups.push(groupPublicData(groupID, group));
        }
    }

    socket.emit('your_groups', userGroups);
}

module.exports = function setupSocket(io) {
    io.on('connection', socket => {
        console.log('User connected:', socket.id);

        socket.on('register_public_key', ({ userID, publicKey } = {}, callback) => {
            if (!isValidID(userID) || !isValidKey(publicKey)) {
                return reply(callback, {
                    success: false,
                    message: 'userID ou publicKey inválidos.',
                });
            }

            const existing = publicKeys.get(userID);

            if (existing && existing !== publicKey) {
                return reply(callback, {
                    success: false,
                    message: 'userID já registrado com outra chave pública.',
                });
            }

            publicKeys.set(userID, publicKey);
            users.set(socket.id, { userID, publicKey });

            reply(callback, { success: true });

            io.emit('user_list_update', onlineUserIDs());

            // Envia ao cliente os grupos que ele já integra.
            sendGroupsToUser(socket, userID);

            flushQueue(socket, userID);
        });

        socket.on('request_public_key', ({ targetUserID } = {}, callback) => {
            const key = isValidID(targetUserID)
                ? publicKeys.get(targetUserID)
                : null;

            if (key) {
                reply(callback, { success: true, publicKey: key });
            } else {
                reply(callback, {
                    success: false,
                    message: `Chave pública não encontrada para ${targetUserID}.`,
                });
            }
        });

        // Mensagem direta: o servidor continua sem decifrar o conteúdo.
        socket.on('send_encrypted_message', (payload, callback) => {
            const sender = users.get(socket.id);

            if (!sender) {
                return reply(callback, {
                    success: false,
                    message: 'Registre sua chave pública primeiro.',
                });
            }

            if (!payload || !isValidID(payload.receiverID)) {
                return reply(callback, {
                    success: false,
                    message: 'receiverID inválido.',
                });
            }

            if (!publicKeys.has(payload.receiverID)) {
                return reply(callback, {
                    success: false,
                    message: 'Destinatário desconhecido.',
                });
            }

            const packet = {
                ...payload,
                type: 'direct',
                senderID: sender.userID,
                timestamp: Date.now(),
            };

            const result = deliver(
                io,
                payload.receiverID,
                'receive_encrypted_message',
                packet
            );

            if (result.delivered) {
                reply(callback, {
                    success: true,
                    delivered: true,
                    message: 'Mensagem encaminhada.',
                });
            } else if (result.queued) {
                reply(callback, {
                    success: true,
                    delivered: false,
                    message: 'Destinatário offline; mensagem colocada na fila.',
                });
            } else {
                reply(callback, {
                    success: false,
                    message: 'Fila do destinatário cheia.',
                });
            }
        });

        // Criação de grupo e distribuição de metadados/chaves públicas.
        socket.on('create_group', ({ members } = {}, callback) => {
            const creator = users.get(socket.id);

            if (!creator) {
                return reply(callback, {
                    success: false,
                    message: 'Registre sua chave pública primeiro.',
                });
            }

            if (!Array.isArray(members) || !members.every(isValidID)) {
                return reply(callback, {
                    success: false,
                    message: 'Lista de membros inválida.',
                });
            }

            const uniqueMembers = [
                ...new Set([creator.userID, ...members.map(id => id.trim())]),
            ];

            if (uniqueMembers.length > MAX_GROUP_SIZE) {
                return reply(callback, {
                    success: false,
                    message: 'Grupo excede o limite de membros.',
                });
            }

            const unknown = uniqueMembers.filter(id => !publicKeys.has(id));

            if (unknown.length > 0) {
                return reply(callback, {
                    success: false,
                    message: `Usuários desconhecidos: ${unknown.join(', ')}`,
                });
            }

            const groupID = crypto.randomUUID();

            const group = {
                members: uniqueMembers,
                createdBy: creator.userID,
            };

            groups.set(groupID, group);

            const data = groupPublicData(groupID, group);

            // Informa aos membros online que um grupo foi criado.
            for (const memberID of uniqueMembers) {
                const memberSocketID = findSocketID(memberID);

                if (memberSocketID) {
                    io.to(memberSocketID).emit('group_created', data);
                }
            }

            reply(callback, {
                success: true,
                ...data,
            });

            console.log(
                'Group created:',
                groupID,
                'members:',
                uniqueMembers
            );
        });

        // Cada bloco tem um destinatário, um C2 e uma assinatura ECDSA.
        // O C1 é compartilhado por todos os blocos da mesma mensagem.
        socket.on('send_group_encrypted_message', (payload, callback) => {
            const sender = users.get(socket.id);

            if (!sender) {
                return reply(callback, {
                    success: false,
                    message: 'Registre sua chave pública primeiro.',
                });
            }

            if (
                !payload ||
                !isValidID(payload.groupID) ||
                !isValidKey(payload.c1) ||
                !Array.isArray(payload.encryptedBlocks)
            ) {
                return reply(callback, {
                    success: false,
                    message: 'Payload de grupo inválido.',
                });
            }

            const group = groups.get(payload.groupID);

            if (!group) {
                return reply(callback, {
                    success: false,
                    message: 'Grupo não encontrado.',
                });
            }

            if (!group.members.includes(sender.userID)) {
                return reply(callback, {
                    success: false,
                    message: 'Você não faz parte deste grupo.',
                });
            }

            if (
                payload.version !== 1 ||
                payload.algorithm !== GROUP_ALGORITHM ||
                payload.senderID !== sender.userID
            ) {
                return reply(callback, {
                    success: false,
                    message: 'Versão, algoritmo ou remetente inválido.',
                });
            }

            const expectedRecipients = group.members.filter(
                memberID => memberID !== sender.userID
            );

            const blocks = payload.encryptedBlocks;

            if (blocks.length !== expectedRecipients.length) {
                return reply(callback, {
                    success: false,
                    message: 'Quantidade de blocos cifrados incorreta.',
                });
            }

            const blockByUser = new Map();

            for (const block of blocks) {
                if (
                    !block ||
                    !isValidID(block.username) ||
                    !isValidKey(block.c2) ||
                    !isValidKey(block.signature)
                ) {
                    return reply(callback, {
                        success: false,
                        message: 'Bloco cifrado inválido.',
                    });
                }

                if (
                    block.username === sender.userID ||
                    !expectedRecipients.includes(block.username) ||
                    blockByUser.has(block.username)
                ) {
                    return reply(callback, {
                        success: false,
                        message: 'Destinatário inválido ou duplicado.',
                    });
                }

                blockByUser.set(block.username, block);
            }

            for (const recipientID of expectedRecipients) {
                const block = blockByUser.get(recipientID);

                if (!block) {
                    return reply(callback, {
                        success: false,
                        message: `Bloco ausente para ${recipientID}.`,
                    });
                }
            }

            let deliveredCount = 0;
            let queuedCount = 0;
            let failedCount = 0;
            const timestamp = Date.now();

            for (const recipientID of expectedRecipients) {
                const block = blockByUser.get(recipientID);

                const packet = {
                    type: 'group',
                    version: payload.version,
                    algorithm: payload.algorithm,
                    groupID: payload.groupID,
                    senderID: sender.userID,
                    receiverID: recipientID,
                    c1: payload.c1,
                    c2: block.c2,
                    signature: block.signature,
                    timestamp,
                };

                const result = deliver(
                    io,
                    recipientID,
                    'receive_group_encrypted_message',
                    packet
                );

                if (result.delivered) deliveredCount++;
                else if (result.queued) queuedCount++;
                else failedCount++;
            }

            reply(callback, {
                success: true,
                delivered: deliveredCount,
                queued: queuedCount,
                failed: failedCount,
            });
        });

        socket.on('disconnect', () => {
            const user = users.get(socket.id);

            if (user) {
                users.delete(socket.id);
                io.emit('user_list_update', onlineUserIDs());
                console.log('User disconnected:', user.userID);
            }
        });
    });
};