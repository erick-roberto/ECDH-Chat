const {
    users, publicKeys, allowed, reply, isValidID, isPointHex, isSignatureHex,
    isMessageID, isTimestamp, PROTOCOL_VERSION, DIRECT_ALGORITHM,
} = require('../utils/shared');
const {
    persistDirectMessage, markMessagesDelivered, getDirectHistory,
} = require('../../database');
const { findSocketID } = require('../delivery');
module.exports = function register(socket, io) {
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

};
