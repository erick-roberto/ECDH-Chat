const crypto = require('crypto');
const { secp256k1 } = require('@noble/curves/secp256k1');
const { sha256 } = require('@noble/hashes/sha256');
const { users, publicKeys, messageQueue, groups } = require('./database');

const ACK_TIMEOUT_MS = 5000;
const MAX_QUEUE_PER_USER = 500;
const MAX_GROUP_SIZE = 100;

const PROTOCOL_VERSION = 2;
const DIRECT_ALGORITHM = 'EC-ElGamal-secp256k1-direct-v2';
const GROUP_ALGORITHM = 'EC-ElGamal-secp256k1-group-v2';

// Domínios de assinatura: DEVEM ser idênticos aos do frontend (crypto.js).
const REGISTER_DOMAIN = 'chat-ecc/register/v1';
const GROUP_GRANT_DOMAIN = 'chat-ecc/group-grant/v1';

// O servidor só VERIFICA assinaturas com chaves públicas (autenticação de
// sessão e de grupos). Ele nunca cifra, decifra nem vê chaves privadas.
const RATE_WINDOW_MS = 10_000;
const RATE_MAX_EVENTS = 40;

function reply(callback, data) {
    if (typeof callback === 'function') callback(data);
}

function isValidID(value) {
    return typeof value === 'string' &&
        value.trim().length > 0 &&
        value.length <= 128;
}

const isHex = (value, length) =>
    typeof value === 'string' &&
    value.length === length &&
    /^[0-9a-f]+$/i.test(value);

// Ponto comprimido secp256k1 = 33 bytes (66 hex); assinatura compacta = 64 bytes (128 hex).
const isPointHex = value => isHex(value, 66);
const isSignatureHex = value => isHex(value, 128);
const isMessageID = value => isHex(value, 32);
const isTimestamp = value => Number.isSafeInteger(value) && value > 0;

function isValidPublicKey(value) {
    if (!isPointHex(value)) return false;
    try {
        secp256k1.ProjectivePoint.fromHex(value); // valida que está na curva
        return true;
    } catch {
        return false;
    }
}

function verifySignature(domain, fields, signature, publicKey) {
    try {
        const bytes = new TextEncoder().encode(`${domain}\n${JSON.stringify(fields)}`);
        return secp256k1.verify(signature, sha256(bytes), publicKey);
    } catch {
        return false;
    }
}

// Janela deslizante simples por socket.
function allowed(socket) {
    const now = Date.now();
    const hits = (socket.data.hits || []).filter(t => now - t < RATE_WINDOW_MS);
    hits.push(now);
    socket.data.hits = hits;
    return hits.length <= RATE_MAX_EVENTS;
}

const sortedMembers = members => [...new Set(members)].sort();

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
        signature: group.signature,
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

        // 1) O cliente pede um nonce de uso único.
        socket.on('get_auth_challenge', (_payload, callback) => {
            if (!allowed(socket)) {
                return reply(callback, { success: false, message: 'Muitas requisições.' });
            }

            const nonce = crypto.randomBytes(32).toString('hex');
            socket.data.nonce = nonce;
            reply(callback, { success: true, nonce });
        });

        // 2) O cliente prova que possui a chave privada assinando [userID, nonce].
        socket.on('register_public_key', ({ userID, publicKey, signature } = {}, callback) => {
            if (!allowed(socket)) {
                return reply(callback, { success: false, message: 'Muitas requisições.' });
            }

            if (!isValidID(userID) || !isValidPublicKey(publicKey) || !isSignatureHex(signature)) {
                return reply(callback, {
                    success: false,
                    message: 'userID, publicKey ou assinatura inválidos.',
                });
            }

            const nonce = socket.data.nonce;
            socket.data.nonce = null; // uso único: impede replay do registro

            if (!nonce || !verifySignature(REGISTER_DOMAIN, [userID, nonce], signature, publicKey)) {
                return reply(callback, {
                    success: false,
                    message: 'Falha na autenticação: assinatura do desafio inválida.',
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
            if (!allowed(socket)) {
                return reply(callback, { success: false, message: 'Muitas requisições.' });
            }

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

            if (!allowed(socket)) {
                return reply(callback, { success: false, message: 'Muitas requisições.' });
            }

            const valid =
                payload &&
                isValidID(payload.receiverID) &&
                payload.version === PROTOCOL_VERSION &&
                payload.algorithm === DIRECT_ALGORITHM &&
                payload.senderID === sender.userID &&
                isMessageID(payload.messageId) &&
                isTimestamp(payload.sentAt) &&
                isPointHex(payload.c1) &&
                isPointHex(payload.c2) &&
                isSignatureHex(payload.signature);

            if (!valid) {
                return reply(callback, {
                    success: false,
                    message: 'Pacote inválido (versão, algoritmo, remetente ou campos).',
                });
            }

            if (!publicKeys.has(payload.receiverID)) {
                return reply(callback, {
                    success: false,
                    message: 'Destinatário desconhecido.',
                });
            }

            // Whitelist: só os campos conhecidos são repassados.
            const packet = {
                type: 'direct',
                version: payload.version,
                algorithm: payload.algorithm,
                senderID: sender.userID,
                receiverID: payload.receiverID,
                messageId: payload.messageId,
                sentAt: payload.sentAt,
                c1: payload.c1,
                c2: payload.c2,
                signature: payload.signature,
                timestamp: Date.now(), // recebimento no servidor; NÃO é assinado
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
        // O criador gera o groupID e assina [groupID, membros ordenados, criador].
        // O servidor confere a assinatura, mas não consegue forjar nem alterar a lista.
        socket.on('create_group', ({ groupID, members, signature } = {}, callback) => {
            const creator = users.get(socket.id);

            if (!creator) {
                return reply(callback, {
                    success: false,
                    message: 'Registre sua chave pública primeiro.',
                });
            }

            if (!allowed(socket)) {
                return reply(callback, { success: false, message: 'Muitas requisições.' });
            }

            if (
                !isMessageID(groupID) ||
                !Array.isArray(members) ||
                !members.every(isValidID) ||
                !isSignatureHex(signature)
            ) {
                return reply(callback, {
                    success: false,
                    message: 'Dados de grupo inválidos.',
                });
            }

            const uniqueMembers = sortedMembers(members.map(id => id.trim()));

            if (!uniqueMembers.includes(creator.userID)) {
                return reply(callback, {
                    success: false,
                    message: 'O criador deve fazer parte do grupo.',
                });
            }

            if (uniqueMembers.length < 2 || uniqueMembers.length > MAX_GROUP_SIZE) {
                return reply(callback, {
                    success: false,
                    message: 'Tamanho de grupo inválido.',
                });
            }

            if (groups.has(groupID)) {
                return reply(callback, { success: false, message: 'groupID já existe.' });
            }

            const unknown = uniqueMembers.filter(id => !publicKeys.has(id));

            if (unknown.length > 0) {
                return reply(callback, {
                    success: false,
                    message: `Usuários desconhecidos: ${unknown.join(', ')}`,
                });
            }

            const grantOK = verifySignature(
                GROUP_GRANT_DOMAIN,
                [groupID, uniqueMembers, creator.userID],
                signature,
                creator.publicKey
            );

            if (!grantOK) {
                return reply(callback, {
                    success: false,
                    message: 'Assinatura do grupo inválida.',
                });
            }

            const group = {
                members: uniqueMembers,
                createdBy: creator.userID,
                signature,
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

            console.log('Group created:', groupID, 'members:', uniqueMembers);
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

            if (!allowed(socket)) {
                return reply(callback, { success: false, message: 'Muitas requisições.' });
            }

            if (
                !payload ||
                !isMessageID(payload.groupID) ||
                !isPointHex(payload.c1) ||
                !isMessageID(payload.messageId) ||
                !isTimestamp(payload.sentAt) ||
                !Array.isArray(payload.encryptedBlocks) ||
                payload.encryptedBlocks.length > MAX_GROUP_SIZE
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
                payload.version !== PROTOCOL_VERSION ||
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
                    !isPointHex(block.c2) ||
                    !isSignatureHex(block.signature)
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
                    messageId: payload.messageId,
                    sentAt: payload.sentAt,
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