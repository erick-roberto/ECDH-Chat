const {
    users, publicKeys, allowed, reply, isValidID, isPointHex, isSignatureHex,
    isMessageID, isTimestamp, PROTOCOL_VERSION, DIRECT_ALGORITHM,
    verifySignature, DIRECT_DOMAIN
} = require('../utils/shared');
const { persistDirectMessage, markMessagesDelivered, getDirectHistory } = require('../../database');
const { findSocketID } = require('../delivery');

const isHex = val => typeof val === 'string' && /^[0-9a-f]+$/i.test(val);

module.exports = function register(socket, io) {
    socket.on('send_encrypted_message', async (payload, callback) => {
        const sender = users.get(socket.id);
        if (!sender) return reply(callback, { success: false, message: 'Registre sua chave pública primeiro.' });
        if (!allowed(socket)) return reply(callback, { success: false, message: 'Muitas requisições.' });

        const valid =
            payload && isValidID(payload.receiverID) && payload.version === PROTOCOL_VERSION &&
            payload.algorithm === DIRECT_ALGORITHM && payload.senderID === sender.userID &&
            isMessageID(payload.messageId) && isTimestamp(payload.sentAt) &&
            isPointHex(payload.ePub) && isHex(payload.iv) && isHex(payload.ciphertext) &&
            isSignatureHex(payload.signature);

        if (!valid) return reply(callback, { success: false, message: 'Pacote Híbrido estruturalmente inválido.' });
        if (!publicKeys.has(payload.receiverID)) return reply(callback, { success: false, message: 'Destinatário desconhecido.' });

        // Validação de Frescor (Replay no Servidor)
        if (Math.abs(Date.now() - payload.sentAt) > 300000) {
            return reply(callback, { success: false, message: 'Carimbo de tempo expirado (Replay).' });
        }

        // Validação de Assinatura ECDSA (Prevenção de Fila Envenenada)
        const senderPubKey = publicKeys.get(sender.userID);
        const unsignedFields = [
            payload.version, payload.algorithm, payload.senderID, payload.receiverID,
            payload.messageId, payload.sentAt, payload.ePub, payload.iv, payload.ciphertext
        ];

        if (!verifySignature(DIRECT_DOMAIN, unsignedFields, payload.signature, senderPubKey)) {
            return reply(callback, { success: false, message: 'Assinatura criptográfica falsificada.' });
        }

        const packet = {
            type: 'direct', version: payload.version, algorithm: payload.algorithm,
            senderID: sender.userID, receiverID: payload.receiverID, messageId: payload.messageId,
            sentAt: payload.sentAt, ePub: payload.ePub, iv: payload.iv, ciphertext: payload.ciphertext,
            signature: payload.signature, timestamp: Date.now(),
        };

        try {
            const databaseID = await persistDirectMessage(packet);
            const recipientSocketID = findSocketID(payload.receiverID);

            if (recipientSocketID) {
                io.to(recipientSocketID).emit('receive_encrypted_message', packet);
                await markMessagesDelivered([databaseID], payload.receiverID);
                return reply(callback, { success: true, delivered: true, message: 'Mensagem salva e encaminhada.' });
            }

            return reply(callback, { success: true, delivered: false, queued: true, message: 'Na fila offline segura.' });
        } catch (error) {
            return reply(callback, { success: false, message: 'Falha no banco de dados.' });
        }
    });

    socket.on('request_direct_history', async ({ peerID } = {}, callback) => {
        const currentUser = users.get(socket.id);
        if (!currentUser) return reply(callback, { success: false, message: 'Registre sua chave primeiro.' });
        if (!allowed(socket)) return reply(callback, { success: false, message: 'Muitas requisições.' });
        if (!isValidID(peerID) || peerID === currentUser.userID) return reply(callback, { success: false, message: 'ID inválido.' });

        try {
            const history = await getDirectHistory(currentUser.userID, peerID);
            return reply(callback, { success: true, peerID, messages: history });
        } catch (error) {
            return reply(callback, { success: false, message: 'Falha ao recuperar histórico.' });
        }
    });
};