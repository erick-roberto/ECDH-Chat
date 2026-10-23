const {
    users, publicKeys, groups, allowed, reply, isValidID, isPointHex,
    isSignatureHex, isMessageID, isTimestamp, sortedMembers, verifySignature,
    GROUP_GRANT_DOMAIN, MAX_GROUP_SIZE, PROTOCOL_VERSION, GROUP_ALGORITHM,
} = require('../utils/shared');
const { persistGroup, persistGroupMessages, markMessagesDelivered } = require('../../database');
const { findSocketID, groupPublicData } = require('../delivery');

const isHex = val => typeof val === 'string' && /^[0-9a-f]+$/i.test(val);

module.exports = function register(socket, io) {
    socket.on('create_group', async ({ groupID, members, signature } = {}, callback) => {
        // [O código de criação do grupo mantém-se intocado]
        const creator = users.get(socket.id);
        if (!creator) return reply(callback, { success: false, message: 'Registre sua chave pública primeiro.' });
        if (!allowed(socket)) return reply(callback, { success: false, message: 'Muitas requisições.' });
        if (!isMessageID(groupID) || !Array.isArray(members) || !members.every(isValidID) || !isSignatureHex(signature)) {
            return reply(callback, { success: false, message: 'Dados de grupo inválidos.' });
        }
        const uniqueMembers = sortedMembers(members.map(id => id.trim()));
        if (!uniqueMembers.includes(creator.userID)) return reply(callback, { success: false, message: 'O criador deve fazer parte do grupo.' });
        if (uniqueMembers.length < 2 || uniqueMembers.length > MAX_GROUP_SIZE) return reply(callback, { success: false, message: 'Tamanho inválido.' });
        if (groups.has(groupID)) return reply(callback, { success: false, message: 'groupID já existe.' });
        const unknown = uniqueMembers.filter(id => !publicKeys.has(id));
        if (unknown.length > 0) return reply(callback, { success: false, message: `Usuários desconhecidos: ${unknown.join(', ')}` });
        const grantOK = verifySignature(GROUP_GRANT_DOMAIN, [groupID, uniqueMembers, creator.userID], signature, creator.publicKey);
        if (!grantOK) return reply(callback, { success: false, message: 'Assinatura inválida.' });

        const group = { members: uniqueMembers, createdBy: creator.userID, signature };
        try {
            await persistGroup(groupID, group);
            groups.set(groupID, group);
        } catch (error) {
            return reply(callback, { success: false, message: 'Falha no banco.' });
        }
        const data = groupPublicData(groupID, group);
        for (const memberID of uniqueMembers) {
            const memberSocketID = findSocketID(memberID);
            if (memberSocketID) io.to(memberSocketID).emit('group_created', data);
        }
        reply(callback, { success: true, ...data });
    });

    socket.on('send_group_encrypted_message', async (payload, callback) => {
        const sender = users.get(socket.id);
        if (!sender) return reply(callback, { success: false, message: 'Registre sua chave primeiro.' });
        if (!allowed(socket)) return reply(callback, { success: false, message: 'Muitas requisições.' });

        // Nova validação de Grupo Híbrido
        if (
            !payload || !isMessageID(payload.groupID) || !isPointHex(payload.ePub) ||
            !isHex(payload.iv) || !isHex(payload.ciphertext) ||
            !isMessageID(payload.messageId) || !isTimestamp(payload.sentAt) ||
            !Array.isArray(payload.encryptedBlocks) || payload.encryptedBlocks.length > MAX_GROUP_SIZE
        ) {
            return reply(callback, { success: false, message: 'Payload de grupo inválido.' });
        }

        const group = groups.get(payload.groupID);
        if (!group) return reply(callback, { success: false, message: 'Grupo não encontrado.' });
        if (!group.members.includes(sender.userID)) return reply(callback, { success: false, message: 'Você não faz parte.' });
        if (payload.version !== PROTOCOL_VERSION || payload.algorithm !== GROUP_ALGORITHM || payload.senderID !== sender.userID) {
            return reply(callback, { success: false, message: 'Versão/Algoritmo incorreto.' });
        }

        const expectedRecipients = group.members.filter(memberID => memberID !== sender.userID);
        const blocks = payload.encryptedBlocks;
        if (blocks.length !== expectedRecipients.length) return reply(callback, { success: false, message: 'Quantidade de blocos incorreta.' });

        const blockByUser = new Map();
        for (const block of blocks) {
            if (!block || !isValidID(block.username) || !isHex(block.wrappedKey) || !isSignatureHex(block.signature)) {
                return reply(callback, { success: false, message: 'Bloco cifrado inválido.' });
            }
            if (block.username === sender.userID || !expectedRecipients.includes(block.username) || blockByUser.has(block.username)) {
                return reply(callback, { success: false, message: 'Destinatário duplicado/inválido.' });
            }
            blockByUser.set(block.username, block);
        }

        const timestamp = Date.now();
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
                ePub: payload.ePub,
                iv: payload.iv,
                ciphertext: payload.ciphertext,
                wrappedKey: block.wrappedKey,
                signature: block.signature,
                timestamp,
            };
        });

        try {
            const savedMessages = await persistGroupMessages(packets);
            let deliveredCount = 0;
            let queuedCount = 0;

            for (const saved of savedMessages) {
                const packet = saved.packet;
                const recipientSocketID = findSocketID(packet.receiverID);
                if (!recipientSocketID) { queuedCount++; continue; }
                io.to(recipientSocketID).emit('receive_group_encrypted_message', packet);
                try {
                    await markMessagesDelivered([saved.dbId], packet.receiverID);
                    deliveredCount++;
                } catch (error) { queuedCount++; }
            }
            return reply(callback, { success: true, delivered: deliveredCount, queued: queuedCount, failed: 0 });
        } catch (error) {
            return reply(callback, { success: false, message: 'Falha no banco.' });
        }
    });
};