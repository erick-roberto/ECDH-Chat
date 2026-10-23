const {
    users, publicKeys, allowed, reply, isValidID, isPointHex, isSignatureHex,
    isMessageID, isTimestamp, PROTOCOL_VERSION, DIRECT_ALGORITHM,
} = require('../utils/shared');
const {
    persistDirectMessage, markMessagesDelivered, getDirectHistory,
} = require('../../database');
const { findSocketID } = require('../delivery');
const { logEvent, logError } = require('../../utils/logger');
module.exports = function register(socket, io) {
    socket.on('send_encrypted_message', async (payload, callback) => {
                logEvent('MESSAGE:DIRECT', 'Pacote criptografado recebido do frontend', {
                    socketID: socket.id,
                    senderID: payload?.senderID,
                    receiverID: payload?.receiverID,
                    messageId: payload?.messageId,
                    algorithm: payload?.algorithm,
                    version: payload?.version,
                    sentAt: payload?.sentAt,
                    c1: payload?.c1,
                    c2: payload?.c2,
                    signature: payload?.signature,
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
                    logEvent('MESSAGE:DIRECT', 'Pacote rejeitado na validação estrutural', { senderID: sender.userID, receiverID: payload?.receiverID });
                    return reply(callback, {
                        success: false,
                        message: 'Pacote inválido (versão, algoritmo, remetente ou campos).',
                    });
                }

                if (!publicKeys.has(payload.receiverID)) {
                    logEvent('MESSAGE:DIRECT', 'Pacote rejeitado: destinatário desconhecido', { senderID: sender.userID, receiverID: payload.receiverID });
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

                logEvent('MESSAGE:DIRECT', 'Pacote validado; iniciando persistência', { packet });

                try {
                    // Persiste antes de tentar encaminhar.
                    const databaseID = await persistDirectMessage(packet);
                    logEvent('DATABASE', 'Mensagem direta persistida', { databaseID, messageId: packet.messageId, senderID: packet.senderID, receiverID: packet.receiverID, deliveryStatus: 'pending' });

                    const recipientSocketID = findSocketID(payload.receiverID);

                    if (recipientSocketID) {
                        logEvent('MESSAGE:DIRECT', 'Encaminhando pacote criptografado ao destinatário online', { messageId: packet.messageId, senderID: packet.senderID, receiverID: packet.receiverID, recipientSocketID, packet });
                        io.to(recipientSocketID).emit(
                            'receive_encrypted_message',
                            packet
                        );

                        // O status "delivered" indica encaminhamento pelo servidor.
                        await markMessagesDelivered(
                            [databaseID],
                            payload.receiverID
                        );
                        logEvent('DELIVERY', 'Mensagem marcada como encaminhada pelo servidor', { databaseID, messageId: packet.messageId, receiverID: payload.receiverID });

                        return reply(callback, {
                            success: true,
                            delivered: true,
                            message: 'Mensagem salva e encaminhada.',
                        });
                    }

                    logEvent('DELIVERY', 'Destinatário offline; mensagem mantida como pendente', { databaseID, messageId: packet.messageId, receiverID: payload.receiverID });
                    // A mensagem já está salva com status "pending".
                    // Não precisamos mais colocá-la na fila em memória.
                    return reply(callback, {
                        success: true,
                        delivered: false,
                        queued: true,
                        message: 'Mensagem salva; será entregue quando o destinatário se conectar.',
                    });
                } catch (error) {
                    logError('MESSAGE:DIRECT', 'Erro ao persistir ou encaminhar mensagem', error, { messageId: payload?.messageId, senderID: payload?.senderID, receiverID: payload?.receiverID });

                    return reply(callback, {
                        success: false,
                        message: 'Não foi possível salvar a mensagem no banco de dados.',
                    });
                }
            });

    socket.on('request_direct_history', async ({ peerID } = {}, callback) => {
                logEvent('HISTORY', 'Solicitação de histórico direto', { socketID: socket.id, peerID });
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
                    logEvent('HISTORY', 'Histórico direto carregado', { userID: currentUser.userID, peerID, count: history.length, messages: history });

                    return reply(callback, {
                        success: true,
                        peerID,
                        messages: history,
                    });
                } catch (error) {
                    logError('HISTORY', 'Erro ao recuperar histórico de mensagens', error, { userID: currentUser.userID, peerID });

                    return reply(callback, {
                        success: false,
                        message: 'Não foi possível recuperar o histórico.',
                    });
                }
            });

};
