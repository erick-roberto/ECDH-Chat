const crypto = require('crypto');
const { secp256k1 } = require('@noble/curves/secp256k1');
const { sha256 } = require('@noble/hashes/sha256');
const {
    users,
    publicKeys,
    messageQueue,
    groups,
    persistUserPublicKey,
    getPersistedPublicKey,
    persistDirectMessage,
    persistGroupMessages,
    getPendingMessages,
    markMessagesDelivered,
    getDirectHistory,
    persistGroup,
    loadPersistedGroups,
} = require('./database');

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


async function flushQueue(socket, userID) {
    try {
        const pending = await getPendingMessages(userID);

        if (pending.length === 0) return;

        // Mantém o limite do lote para evitar um evento excessivamente grande.
        const batch = pending.slice(0, MAX_QUEUE_PER_USER);
        const packets = batch.map(item => item.packet);
        const databaseIDs = batch.map(item => item.dbId);

        socket.timeout(ACK_TIMEOUT_MS).emit(
            'pending_messages',
            packets,
            async (err, response) => {
                if (err) return;

                if (!response || response.success !== true) {
                console.warn(
                    `O cliente não confirmou o processamento das mensagens de ${userID}.`
                );
                return;
                }

                try {
                await markMessagesDelivered(databaseIDs, userID);
                console.log(
                    `Mensagens pendentes confirmadas para ${userID}: ${databaseIDs.length}`
                );
                } catch (error) {
                console.error(
                    'Erro ao atualizar mensagens entregues:',
                    error.message
                );
                }
            }
            );
    } catch (error) {
        console.error(
            `Erro ao recuperar mensagens pendentes de ${userID}:`,
            error.message
        );
    }
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
        
        socket.on('register_public_key', async ({ userID, publicKey, signature } = {}, callback) => {
            if (!allowed(socket)) {
                return reply(callback, {
                    success: false,
                    message: 'Muitas requisições.',
                });
            }

            if (
                !isValidID(userID) ||
                !isValidPublicKey(publicKey) ||
                !isSignatureHex(signature)
            ) {
                return reply(callback, {
                    success: false,
                    message: 'userID, publicKey ou assinatura inválidos.',
                });
            }

            const nonce = socket.data.nonce;
            socket.data.nonce = null;

            if (
                !nonce ||
                !verifySignature(
                    REGISTER_DOMAIN,
                    [userID, nonce],
                    signature,
                    publicKey
                )
            ) {
                return reply(callback, {
                    success: false,
                    message: 'Falha na autenticação: assinatura do desafio inválida.',
                });
            }

            // Se o usuário já está registrado nesta execução,
            // impede que outra chave seja usada para o mesmo ID.
            const existing = publicKeys.get(userID);

            if (existing && existing !== publicKey) {
                return reply(callback, {
                    success: false,
                    message: 'userID já registrado com outra chave pública.',
                });
            }

            try {
                // Persiste a identidade antes de aceitar a sessão.
                await loadPersistedGroups();
                const persistedUser = await persistUserPublicKey(
                    userID,
                    publicKey
                );

                if (!persistedUser) {
                    return reply(callback, {
                        success: false,
                        message: 'userID já registrado com outra chave pública.',
                    });
                }

                // Atualiza o cache e registra o socket online.
                publicKeys.set(userID, persistedUser.public_key);

                users.set(socket.id, {
                    userID,
                    publicKey: persistedUser.public_key,
                });

                reply(callback, { success: true });

                io.emit('user_list_update', onlineUserIDs());

                sendGroupsToUser(socket, userID);

                flushQueue(socket, userID);
            } catch (error) {
                console.error(
                    'Erro ao persistir usuário:',
                    error.message
                );

                return reply(callback, {
                    success: false,
                    message: 'Não foi possível registrar o usuário no banco de dados.',
                });
            }
        });


        
        socket.on('request_public_key', async ({ targetUserID } = {}, callback) => {
            if (!allowed(socket)) {
                return reply(callback, {
                    success: false,
                    message: 'Muitas requisições.',
                });
            }

            if (!isValidID(targetUserID)) {
                return reply(callback, {
                    success: false,
                    message: 'Identificador do usuário inválido.',
                });
            }

            try {
                const key = await getPersistedPublicKey(targetUserID);

                if (key) {
                    publicKeys.set(targetUserID, key);

                    return reply(callback, {
                        success: true,
                        publicKey: key,
                    });
                }

                return reply(callback, {
                    success: false,
                    message: `Chave pública não encontrada para ${targetUserID}.`,
                });
            } catch (error) {
                console.error(
                    'Erro ao consultar chave pública:',
                    error.message
                );

                return reply(callback, {
                    success: false,
                    message: 'Não foi possível consultar a chave pública.',
                });
            }
        });


        // Mensagem direta: o servidor continua sem decifrar o conteúdo.
        
        socket.on('send_encrypted_message', async (payload, callback) => {
            const sender = users.get(socket.id);

            if (!sender) {
                return reply(callback, {
                    success: false,
                    message: 'Registre sua chave pública primeiro.',
                });
            }

            if (!allowed(socket)) {
                return reply(callback, {
                    success: false,
                    message: 'Muitas requisições.',
                });
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
                timestamp: Date.now(),
            };

            try {
                // Persiste antes de tentar encaminhar.
                const databaseID = await persistDirectMessage(packet);

                const recipientSocketID = findSocketID(payload.receiverID);

                if (recipientSocketID) {
                    io.to(recipientSocketID).emit(
                        'receive_encrypted_message',
                        packet
                    );

                    // O status "delivered" indica encaminhamento pelo servidor.
                    await markMessagesDelivered(
                        [databaseID],
                        payload.receiverID
                    );

                    return reply(callback, {
                        success: true,
                        delivered: true,
                        message: 'Mensagem salva e encaminhada.',
                    });
                }

                // A mensagem já está salva com status "pending".
                // Não precisamos mais colocá-la na fila em memória.
                return reply(callback, {
                    success: true,
                    delivered: false,
                    queued: true,
                    message: 'Mensagem salva; será entregue quando o destinatário se conectar.',
                });
            } catch (error) {
                console.error(
                    'Erro ao persistir ou encaminhar mensagem:',
                    error.message
                );

                return reply(callback, {
                    success: false,
                    message: 'Não foi possível salvar a mensagem no banco de dados.',
                });
            }
        });


        // Criação de grupo e distribuição de metadados/chaves públicas.
        // O criador gera o groupID e assina [groupID, membros ordenados, criador].
        // O servidor confere a assinatura, mas não consegue forjar nem alterar a lista.
        socket.on('create_group', async ({ groupID, members, signature } = {}, callback) => {
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

            try {
                // O grupo só entra no cache depois de ser salvo no banco.
                await persistGroup(groupID, group);
                groups.set(groupID, group);
            } catch (error) {
                console.error('Erro ao persistir grupo:', error.message);

                return reply(callback, {
                    success: false,
                    message: 'Não foi possível salvar o grupo no banco de dados.',
                });
            }

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
        socket.on('send_group_encrypted_message', async (payload, callback) => {
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

            
            const timestamp = Date.now();

            // Monta um pacote independente para cada destinatário.
            const packets = expectedRecipients.map(recipientID => {
                const block = blockByUser.get(recipientID);

                return {
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
            });

            try {
                // 1. Persiste todos os pacotes antes de encaminhar qualquer um.
                const savedMessages = await persistGroupMessages(packets);

                let deliveredCount = 0;
                let queuedCount = 0;

                // 2. Encaminha os pacotes e atualiza o estado de entrega.
                for (const saved of savedMessages) {
                    const packet = saved.packet;
                    const recipientSocketID = findSocketID(packet.receiverID);

                    if (!recipientSocketID) {
                        // A mensagem permanece pendente no PostgreSQL.
                        queuedCount++;
                        continue;
                    }

                    io.to(recipientSocketID).emit(
                        'receive_group_encrypted_message',
                        packet
                    );

                    try {
                        await markMessagesDelivered(
                            [saved.dbId],
                            packet.receiverID
                        );

                        deliveredCount++;
                    } catch (error) {
                        // A mensagem já foi encaminhada, mas o status
                        // continua pendente se a atualização falhar.
                        console.error(
                            'Erro ao atualizar entrega da mensagem de grupo:',
                            error.message
                        );

                        queuedCount++;
                    }
                }

                return reply(callback, {
                    success: true,
                    delivered: deliveredCount,
                    queued: queuedCount,
                    failed: 0,
                    message: 'Mensagens de grupo salvas no banco de dados.',
                });
            } catch (error) {
                console.error(
                    'Erro ao persistir mensagens de grupo:',
                    error.message
                );

                return reply(callback, {
                    success: false,
                    message: 'Não foi possível salvar as mensagens do grupo.',
                });
            }

        });

        
        socket.on('request_direct_history', async ({ peerID } = {}, callback) => {
            const currentUser = users.get(socket.id);

            if (!currentUser) {
                return reply(callback, {
                    success: false,
                    message: 'Registre sua chave pública primeiro.',
                });
            }

            if (!allowed(socket)) {
                return reply(callback, {
                    success: false,
                    message: 'Muitas requisições.',
                });
            }

            if (
                !isValidID(peerID) ||
                peerID === currentUser.userID
            ) {
                return reply(callback, {
                    success: false,
                    message: 'Identificador do contato inválido.',
                });
            }

            try {
                const history = await getDirectHistory(
                    currentUser.userID,
                    peerID
                );

                return reply(callback, {
                    success: true,
                    peerID,
                    messages: history,
                });
            } catch (error) {
                console.error(
                    'Erro ao recuperar histórico de mensagens:',
                    error.message
                );

                return reply(callback, {
                    success: false,
                    message: 'Não foi possível recuperar o histórico.',
                });
            }
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