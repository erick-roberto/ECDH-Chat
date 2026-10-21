
const crypto = require('crypto');
const { users, publicKeys, messageQueue, groups } = require('./database');

const ACK_TIMEOUT_MS = 5000;
const MAX_QUEUE_PER_USER = 500;
const MAX_GROUP_SIZE = 100;


function reply(callback, data) {
    if (typeof callback === 'function') callback(data);
}

function isValidID(value) {
    return typeof value === 'string' && value.length > 0 && value.length <= 128;
}

function isValidKey(value) {
    return typeof value === 'string' && value.length > 0 && value.length <= 4096;
}

function findSocketID(userID) {
    for (const [id, user] of users.entries()) {
        if (user.userID === userID) return id;
    }
    return null;
}

function onlineUserIDs() {
    return [...new Set(Array.from(users.values(), (u) => u.userID))];
}


function enqueue(userID, packet) {
    const queue = messageQueue.get(userID) || [];
    if (queue.length >= MAX_QUEUE_PER_USER) return false;
    queue.push(packet);
    messageQueue.set(userID, queue);
    return true;
}

function deliver(io, userID, event, packet) {
    const socketID = findSocketID(userID);
    if (socketID) {
        io.to(socketID).emit(event, packet);
        return { delivered: true, queued: false };
    }
    return { delivered: false, queued: enqueue(userID, packet) };
}

function flushQueue(socket, userID) {
    const pending = messageQueue.get(userID);
    if (!pending || pending.length === 0) return;

    const batch = [...pending];
    console.log(`${batch.length} pending messages for user:`, userID);

    socket.timeout(ACK_TIMEOUT_MS).emit('pending_messages', batch, (err) => {
        if (err) return; // sem ACK: mantém na fila para a próxima tentativa
        const remaining = (messageQueue.get(userID) || []).filter((m) => !batch.includes(m));
        if (remaining.length > 0) messageQueue.set(userID, remaining);
        else messageQueue.delete(userID);
    });
}


module.exports = function setupSocket(io) {
    io.on('connection', (socket) => {
        console.log('User connected:', socket.id);

        // Registro da chave pública
        socket.on('register_public_key', ({ userID, publicKey } = {}, callback) => {
            if (!isValidID(userID) || !isValidKey(publicKey)) {
                return reply(callback, { success: false, message: 'userID ou publicKey inválidos.' });
            }

            // Impede substituição da chave de outro usuário
            const existing = publicKeys.get(userID);
            if (existing && existing !== publicKey) {
                return reply(callback, {
                    success: false,
                    message: 'userID já registrado com outra chave pública.',
                });
            }

            publicKeys.set(userID, publicKey);
            users.set(socket.id, { userID, publicKey });
            console.log('Public key registered for user:', userID);

            reply(callback, { success: true });
            io.emit('user_list_update', onlineUserIDs());
            flushQueue(socket, userID);
        });

        // Consulta da chave pública de outro usuário
        socket.on('request_public_key', ({ targetUserID } = {}, callback) => {
            const key = isValidID(targetUserID) ? publicKeys.get(targetUserID) : null;
            if (key) reply(callback, { success: true, publicKey: key });
            else reply(callback, { success: false, message: 'Public key not found for user: ' + targetUserID });
        });

        // Mensagem direta
        socket.on('send_encrypted_message', (payload, callback) => {
            const sender = users.get(socket.id);
            if (!sender) {
                return reply(callback, { success: false, message: 'Registre sua chave pública primeiro.' });
            }
            if (!payload || !isValidID(payload.receiverID)) {
                return reply(callback, { success: false, message: 'receiverID inválido.' });
            }
            if (!publicKeys.has(payload.receiverID)) {
                return reply(callback, { success: false, message: 'Destinatário desconhecido.' });
            }

            // O remetente vem do servidor, nunca do cliente
            const packet = {
                ...payload,
                type: 'direct',
                senderID: sender.userID,
                timestamp: Date.now(),
            };

            console.log(`Message from ${sender.userID} to ${payload.receiverID}`);
            const { delivered, queued } = deliver(io, payload.receiverID, 'receive_encrypted_message', packet);

            if (delivered) {
                reply(callback, { success: true, delivered: true, message: 'Message sent to user: ' + payload.receiverID });
            } else if (queued) {
                reply(callback, { success: true, delivered: false, message: 'User offline, message queued for: ' + payload.receiverID });
            } else {
                reply(callback, { success: false, message: 'Fila do destinatário cheia.' });
            }
        });

        // Criação de grupo
        socket.on('create_group', ({ members } = {}, callback) => {
            const creator = users.get(socket.id);
            if (!creator) {
                return reply(callback, { success: false, message: 'Registre sua chave pública primeiro.' });
            }
            if (!Array.isArray(members) || !members.every(isValidID)) {
                return reply(callback, { success: false, message: 'Lista de membros inválida.' });
            }

            const uniqueMembers = [...new Set([creator.userID, ...members])];
            if (uniqueMembers.length > MAX_GROUP_SIZE) {
                return reply(callback, { success: false, message: 'Grupo excede o limite de membros.' });
            }

            const unknown = uniqueMembers.filter((id) => !publicKeys.has(id));
            if (unknown.length > 0) {
                return reply(callback, { success: false, message: 'Usuários desconhecidos: ' + unknown.join(', ') });
            }

            const groupID = crypto.randomUUID();
            groups.set(groupID, uniqueMembers);
            console.log('Group created with ID:', groupID, 'and members:', uniqueMembers);

            const groupKeys = uniqueMembers.map((username) => ({
                username,
                publicKey: publicKeys.get(username),
            }));

            reply(callback, { success: true, groupID, members: uniqueMembers, groupKeys });
        });

        // Mensagem de grupo
        // payload: { groupID, c1, encryptedBlocks: [{ username, c2 }], signature }
        socket.on('send_group_encrypted_message', (payload, callback) => {
            const sender = users.get(socket.id);
            if (!sender) {
                return reply(callback, { success: false, message: 'Registre sua chave pública primeiro.' });
            }
            if (!payload || !Array.isArray(payload.encryptedBlocks)) {
                return reply(callback, { success: false, message: 'Payload inválido.' });
            }

            const members = groups.get(payload.groupID);
            if (!members) {
                return reply(callback, { success: false, message: 'Grupo não encontrado.' });
            }
            if (!members.includes(sender.userID)) {
                return reply(callback, { success: false, message: 'Você não faz parte deste grupo.' });
            }

            console.log(`Group message from ${sender.userID} to group ${payload.groupID}`);

            let deliveredCount = 0;
            let queuedCount = 0;

            for (const block of payload.encryptedBlocks) {
                if (!block || !members.includes(block.username)) continue; // ignora quem não é do grupo
                if (block.username === sender.userID) continue; // não reenvia para o remetente

                const packet = {
                    type: 'group',
                    groupID: payload.groupID,
                    from: sender.userID,
                    c1: payload.c1,
                    c2: block.c2,
                    signature: payload.signature,
                    timestamp: Date.now(),
                };

                const result = deliver(io, block.username, 'receive_group_encrypted_message', packet);
                if (result.delivered) deliveredCount++;
                else if (result.queued) queuedCount++;
            }

            reply(callback, { success: true, delivered: deliveredCount, queued: queuedCount });
        });

        socket.on('disconnect', () => {
            const user = users.get(socket.id);
            if (user) {
                console.log('User disconnected:', user.userID);
                users.delete(socket.id);
                io.emit('user_list_update', onlineUserIDs());
            }
        });
    });
};