const {
    users, publicKeys, groups, allowed, reply, isValidID, isPointHex,
    isSignatureHex, isMessageID, isTimestamp, sortedMembers, verifySignature,
    GROUP_GRANT_DOMAIN, MAX_GROUP_SIZE, PROTOCOL_VERSION, GROUP_ALGORITHM,
} = require('../utils/shared');
const { persistGroup, persistGroupMessages, markMessagesDelivered } = require('../../database');
const { findSocketID, groupPublicData } = require('../delivery');
module.exports = function register(socket, io) {
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

};
