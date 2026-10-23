const { publicKeys, allowed, reply, isValidID } = require('../utils/shared');
const { getPersistedPublicKey } = require('../../database');
module.exports = function register(socket, io) {
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

};
