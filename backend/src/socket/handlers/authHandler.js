const crypto = require('crypto');
const {
    users, publicKeys, groups, allowed, reply, isValidID, isValidPublicKey,
    isSignatureHex, verifySignature, REGISTER_DOMAIN, KEY_ROTATION_DOMAIN, onlineUserIDs,
} = require('../utils/shared');
const {
    persistUserPublicKey, getPersistedPublicKey, loadPersistedGroups, discardPendingMessages,
} = require('../../database');
const { flushQueue, sendGroupsToUser, findSocketID, groupPublicData } = require('../delivery');

module.exports = function register(socket, io) {
    socket.on('get_auth_challenge', (_payload, callback) => {
        if (!allowed(socket)) return reply(callback, { success: false, message: 'Muitas requisições.' });

        const nonce = crypto.randomBytes(32).toString('hex');
        socket.data.nonce = nonce;
        reply(callback, { success: true, nonce });
    });

    socket.on('register_public_key', async (payload, callback) => {
        if (!allowed(socket)) return reply(callback, { success: false, message: 'Muitas requisições.' });

        const { userID, publicKey, signature, previousPublicKey, rotationSignature } = payload || {};

        if (!isValidID(userID) || !isValidPublicKey(publicKey) || !isSignatureHex(signature)) {
            return reply(callback, { success: false, message: 'Parâmetros inválidos.' });
        }

        const nonce = socket.data.nonce;
        socket.data.nonce = null;

        if (!nonce || !verifySignature(REGISTER_DOMAIN, [userID, nonce], signature, publicKey)) {
            return reply(callback, { success: false, message: 'Falha na autenticação do desafio.' });
        }

        try {
            const existingKey = publicKeys.get(userID) ?? await getPersistedPublicKey(userID);
            const isRotation = Boolean(existingKey) && existingKey !== publicKey;

            if (isRotation) {
                const rotationValid =
                    previousPublicKey === existingKey &&
                    isSignatureHex(rotationSignature) &&
                    verifySignature(
                        KEY_ROTATION_DOMAIN,
                        [userID, previousPublicKey, publicKey, nonce],
                        rotationSignature,
                        existingKey
                    );

                if (!rotationValid) {
                    return reply(callback, {
                        success: false,
                        message: 'Troca de chave recusada: assine a nova chave com a chave privada atual.',
                    });
                }

                const createsGroups = [...groups.values()].some(group => group.createdBy === userID);
                if (createsGroups) {
                    return reply(callback, {
                        success: false,
                        message: 'Troca de chave recusada: recrie primeiro os grupos que você criou.',
                    });
                }
            }

            await loadPersistedGroups();
            const persistedUser = await persistUserPublicKey(userID, publicKey);

            if (!persistedUser) return reply(callback, { success: false, message: 'Falha ao guardar chave.' });

            publicKeys.set(userID, persistedUser.public_key);
            users.set(socket.id, { userID, publicKey: persistedUser.public_key });

            reply(callback, { success: true });

            io.emit('user_list_update', onlineUserIDs());

            sendGroupsToUser(socket, userID);

            if (isRotation) {
                await discardPendingMessages(userID);

                for (const [groupID, group] of groups.entries()) {
                    if (!group.members.includes(userID)) continue;

                    const data = groupPublicData(groupID, group);
                    for (const memberID of group.members) {
                        const memberSocketID = findSocketID(memberID);
                        if (memberSocketID) io.to(memberSocketID).emit('group_created', data);
                    }
                }
            }

            flushQueue(socket, userID);
        } catch (error) {
            console.error('Erro ao persistir usuário:', error.message);
            return reply(callback, { success: false, message: 'Erro no banco de dados.' });
        }
    });
};