const crypto = require('crypto');
const {
    users, publicKeys, allowed, reply, isValidID, isValidPublicKey,
    isSignatureHex, verifySignature, REGISTER_DOMAIN, onlineUserIDs,
} = require('../utils/shared');
const { persistUserPublicKey, loadPersistedGroups } = require('../../database');
const { flushQueue, sendGroupsToUser } = require('../delivery');
const { logEvent, logError } = require('../../utils/logger');
module.exports = function register(socket, io) {
    socket.on('get_auth_challenge', (_payload, callback) => {
                if (!allowed(socket)) {
                    return reply(callback, { success: false, message: 'Muitas requisições.' });
                }

                const nonce = crypto.randomBytes(32).toString('hex');
                logEvent('AUTH', 'Desafio de autenticação gerado', { socketID: socket.id });
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

                logEvent('AUTH', 'Solicitação de registro recebida', { socketID: socket.id, userID, publicKey, signature });

                const nonce = socket.data.nonce;
                socket.data.nonce = null;

                const signatureValid = Boolean(nonce) && verifySignature(
                    REGISTER_DOMAIN,
                    [userID, nonce],
                    signature,
                    publicKey
                );
                logEvent('AUTH', 'Resultado da verificação da assinatura de registro', { userID, signatureValid, challengePresent: Boolean(nonce) });

                if (!signatureValid) {
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
                    logEvent('AUTH', 'Chave pública persistida/confirmada no PostgreSQL', { userID, publicKey: persistedUser.public_key });

                    users.set(socket.id, {
                        userID,
                        publicKey: persistedUser.public_key,
                    });
                    logEvent('AUTH', 'Usuário autenticado e conectado', { userID, socketID: socket.id });

                    reply(callback, { success: true });

                    io.emit('user_list_update', onlineUserIDs());

                    sendGroupsToUser(socket, userID);

                    flushQueue(socket, userID);
                } catch (error) {
                    logError('AUTH', 'Falha ao persistir/registrar usuário', error, { userID });

                    return reply(callback, {
                        success: false,
                        message: 'Não foi possível registrar o usuário no banco de dados.',
                    });
                }
            });

};
