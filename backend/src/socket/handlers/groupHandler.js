const {
    users, publicKeys, groups, allowed, reply, isValidID, isPointHex,
    isSignatureHex, isMessageID, isTimestamp, sortedMembers, verifySignature,
    GROUP_GRANT_DOMAIN, MAX_GROUP_SIZE, PROTOCOL_VERSION, GROUP_ALGORITHM,
} = require('../utils/shared');
const { persistGroup, persistGroupMessages, markMessagesDelivered } = require('../../database');
const { findSocketID, groupPublicData } = require('../delivery');
const { logEvent, logError } = require('../../utils/logger');
module.exports = function register(socket, io) {
    // Criação de grupo e distribuição de metadados/chaves públicas.
            // O criador gera o groupID e assina [groupID, membros ordenados, criador].
            // O servidor confere a assinatura, mas não consegue forjar nem alterar a lista.
            socket.on('create_group', async ({ groupID, members, signature } = {}, callback) => {
                logEvent('GROUP', 'Solicitação de criação de grupo', { socketID: socket.id, groupID, members, signature });
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

                logEvent('GROUP', 'Validando assinatura de autorização do grupo', { groupID, creatorID: creator.userID, members: uniqueMembers, signature });
                const grantOK = verifySignature(
                    GROUP_GRANT_DOMAIN,
                    [groupID, uniqueMembers, creator.userID],
                    signature,
                    creator.publicKey
                );

                logEvent('GROUP', 'Resultado da assinatura de autorização do grupo', { groupID, creatorID: creator.userID, signatureValid: grantOK });
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
                    logEvent('DATABASE', 'Grupo e membros persistidos', { groupID, createdBy: group.createdBy, members: group.members });
                    groups.set(groupID, group);
                } catch (error) {
                    logError('GROUP', 'Erro ao persistir grupo', error, { groupID, createdBy: creator.userID });

                    return reply(callback, {
                        success: false,
                        message: 'Não foi possível salvar o grupo no banco de dados.',
                    });
                }

                const data = groupPublicData(groupID, group);
                logEvent('GROUP', 'Grupo criado; metadados e chaves públicas preparados', { groupID, createdBy: creator.userID, members: uniqueMembers, groupData: data });

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

                logEvent('GROUP', 'Criação de grupo concluída', { groupID, members: uniqueMembers });
            });

    socket.on('send_group_encrypted_message', async (payload, callback) => {
                logEvent('MESSAGE:GROUP', 'Pacote de grupo criptografado recebido do frontend', {
                    socketID: socket.id,
                    senderID: payload?.senderID,
                    groupID: payload?.groupID,
                    messageId: payload?.messageId,
                    algorithm: payload?.algorithm,
                    version: payload?.version,
                    sentAt: payload?.sentAt,
                    c1: payload?.c1,
                    encryptedBlocks: Array.isArray(payload?.encryptedBlocks) ? payload.encryptedBlocks.map(block => ({ username: block?.username, c2: block?.c2, signature: block?.signature })) : payload?.encryptedBlocks,
                    plaintextAvailableToBackend: false,
                    privateKeyAvailableToBackend: false,
                });
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


                logEvent('MESSAGE:GROUP', 'Pacote de grupo validado; preparando pacotes por destinatário', { groupID: payload.groupID, senderID: sender.userID, messageId: payload.messageId, recipients: expectedRecipients });
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
                    logEvent('DATABASE', 'Pacotes de mensagem de grupo persistidos', { groupID: payload.groupID, messageId: payload.messageId, count: savedMessages.length, recipients: savedMessages.map(item => item.packet.receiverID), packets: savedMessages.map(item => ({ databaseID: item.dbId, packet: item.packet })) });

                    let deliveredCount = 0;
                    let queuedCount = 0;

                    // 2. Encaminha os pacotes e atualiza o estado de entrega.
                    for (const saved of savedMessages) {
                        const packet = saved.packet;
                        const recipientSocketID = findSocketID(packet.receiverID);

                        if (!recipientSocketID) {
                            logEvent('DELIVERY', 'Destinatário de grupo offline; pacote permanece pendente', { databaseID: saved.dbId, groupID: packet.groupID, messageId: packet.messageId, senderID: packet.senderID, receiverID: packet.receiverID });
                            // A mensagem permanece pendente no PostgreSQL.
                            queuedCount++;
                            continue;
                        }

                        logEvent('MESSAGE:GROUP', 'Encaminhando pacote criptografado de grupo', { databaseID: saved.dbId, recipientSocketID, packet });
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
                            logEvent('DELIVERY', 'Pacote de grupo marcado como encaminhado', { databaseID: saved.dbId, groupID: packet.groupID, messageId: packet.messageId, receiverID: packet.receiverID });
                        } catch (error) {
                            // A mensagem já foi encaminhada, mas o status
                            // continua pendente se a atualização falhar.
                            logError('DELIVERY', 'Erro ao atualizar entrega da mensagem de grupo', error, { databaseID: saved.dbId, groupID: packet.groupID, messageId: packet.messageId, receiverID: packet.receiverID });

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
                    logError('MESSAGE:GROUP', 'Erro ao persistir mensagens de grupo', error, { groupID: payload?.groupID, messageId: payload?.messageId });

                    return reply(callback, {
                        success: false,
                        message: 'Não foi possível salvar as mensagens do grupo.',
                    });
                }

            });

};
