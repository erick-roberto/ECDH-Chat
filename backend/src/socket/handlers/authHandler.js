const crypto = require('crypto');
const {
    users, publicKeys, allowed, reply, isValidID, isValidPublicKey,
    isSignatureHex, verifySignature, REGISTER_DOMAIN,
} = require('../utils/shared');
const { persistUserPublicKey, loadPersistedGroups } = require('../../database');
const { flushQueue, sendGroupsToUser } = require('../delivery');

module.exports = function register(socket, io) {
    socket.on('get_auth_challenge', (_payload, callback) => {
        if (!allowed(socket)) return reply(callback, { success: false, message: 'Muitas requisições.' });

        const nonce = crypto.randomBytes(32).toString('hex');
        socket.data.nonce = nonce;
        reply(callback, { success: true, nonce });
    });

    socket.on('register_public_key', async ({ userID, publicKey, signature } = {}, callback) => {
        if (!allowed(socket)) return reply(callback, { success: false, message: 'Muitas requisições.' });
        if (!isValidID(userID) || !isValidPublicKey(publicKey) || !isSignatureHex(signature)) {
            return reply(callback, { success: false, message: 'Parâmetros inválidos.' });
        }

        const nonce = socket.data.nonce;
        socket.data.nonce = null;

        if (!nonce || !verifySignature(REGISTER_DOMAIN, [userID, nonce], signature, publicKey)) {
            return reply(callback, { success: false, message: 'Falha na autenticação do desafio.' });
        }

        // Mitigação TOFU Incompleto: Removido o bloqueio rígido de substituição de chaves.
        // O cliente agora confia na notificação visual de mudança de PIN.

        try {
            await loadPersistedGroups();
            const persistedUser = await persistUserPublicKey(userID, publicKey);

            if (!persistedUser) return reply(callback, { success: false, message: 'Falha ao guardar chave.' });

            publicKeys.set(userID, persistedUser.public_key);
            users.set(socket.id, { userID, publicKey: persistedUser.public_key });

            reply(callback, { success: true });

            // Mitigação de Privacidade: A lista global de IDs online já não é transmitida.
            // io.emit('user_list_update', onlineUserIDs()); 

            sendGroupsToUser(socket, userID);
            flushQueue(socket, userID);
        } catch (error) {
            console.error('Erro ao persistir usuário:', error.message);
            return reply(callback, { success: false, message: 'Erro no banco de dados.' });
        }
    });
};