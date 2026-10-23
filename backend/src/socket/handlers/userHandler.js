const { publicKeys, allowed, reply, isValidID } = require('../utils/shared');
const { getPersistedPublicKey } = require('../../database');
const { logEvent, logError } = require('../../utils/logger');
module.exports = function register(socket, io) {
    socket.on('request_public_key', async ({ targetUserID } = {}, callback) => {
                logEvent('KEYS', 'Solicitação de chave pública', { requesterSocketID: socket.id, targetUserID });
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
                        logEvent('KEYS', 'Chave pública encontrada e enviada', { targetUserID, publicKey: key });

                        return reply(callback, {
                            success: true,
                            publicKey: key,
                        });
                    }

                    logEvent('KEYS', 'Chave pública não encontrada', { targetUserID });
                    return reply(callback, {
                        success: false,
                        message: `Chave pública não encontrada para ${targetUserID}.`,
                    });
                } catch (error) {
                    logError('KEYS', 'Erro ao consultar chave pública', error, { targetUserID });

                    return reply(callback, {
                        success: false,
                        message: 'Não foi possível consultar a chave pública.',
                    });
                }
            });

};
