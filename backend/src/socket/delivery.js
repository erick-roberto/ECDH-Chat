const { users, publicKeys, messageQueue, groups } = require('../state/runtimeState');
const { getPendingMessages, markMessagesDelivered } = require('../database');
const { logEvent, logError } = require('../utils/logger');

const ACK_TIMEOUT_MS = 5000;
const MAX_QUEUE_PER_USER = 500;

function enqueue(userID, packet) {
    const queue = messageQueue.get(userID) || [];
    logEvent('DELIVERY', 'Tentativa de enfileirar mensagem em memória', { userID, messageId: packet?.messageId, queueSize: queue.length });
    if (queue.length >= MAX_QUEUE_PER_USER) return false;
    queue.push(packet);
    messageQueue.set(userID, queue);
    return true;
}

function deliver(io, userID, event, packet) {
    const socketID = findSocketID(userID);
    logEvent('DELIVERY', 'Solicitação de entrega', { userID, event, socketID, messageId: packet?.messageId, online: Boolean(socketID), packet });
    if (socketID) {
        io.to(socketID).emit(event, packet);
        return { delivered: true, queued: false };
    }
    return { delivered: false, queued: enqueue(userID, packet) };
}

function findSocketID(userID) {
    for (const [id, user] of users.entries()) {
        if (user.userID === userID) return id;
    }
    return null;
}

async function flushQueue(socket, userID) {
    try {
        logEvent('DELIVERY', 'Buscando mensagens pendentes no PostgreSQL', { userID });
        const pending = await getPendingMessages(userID);
        logEvent('DELIVERY', 'Resultado da busca de mensagens pendentes', { userID, count: pending.length, pending });
        if (pending.length === 0) {
            logEvent('DELIVERY', 'Nenhuma mensagem pendente', { userID });
            return;
        }

        const batch = pending.slice(0, MAX_QUEUE_PER_USER);
        const packets = batch.map(item => item.packet);
        const databaseIDs = batch.map(item => item.dbId);

        logEvent('DELIVERY', 'Enviando lote de mensagens pendentes; aguardando ACK do frontend', { userID, count: packets.length, databaseIDs, packets, timeoutMs: ACK_TIMEOUT_MS });
        socket.timeout(ACK_TIMEOUT_MS).emit('pending_messages', packets, async (err, response) => {
            if (err) {
                logError('DELIVERY', 'Timeout/falha ao aguardar ACK de mensagens pendentes', err, { userID, count: packets.length });
                return;
            }
            logEvent('DELIVERY', 'ACK recebido para mensagens pendentes', { userID, response });
            if (!response || response.success !== true) {
                logEvent('DELIVERY', 'ACK recebido sem confirmação de processamento', { userID, response });
                return;
            }
            try {
                await markMessagesDelivered(databaseIDs, userID);
                logEvent('DELIVERY', 'Mensagens pendentes marcadas como entregues após ACK', { userID, count: databaseIDs.length, databaseIDs });
            } catch (error) {
                logError('DELIVERY', 'Erro ao atualizar mensagens entregues após ACK', error, { userID, databaseIDs });
            }
        });
    } catch (error) {
        logError('DELIVERY', 'Erro ao recuperar mensagens pendentes', error, { userID });
    }
}

function groupPublicData(groupID, group) {
    return {
        groupID,
        members: [...group.members],
        createdBy: group.createdBy,
        signature: group.signature,
        groupKeys: group.members.map(username => ({ username, publicKey: publicKeys.get(username) })),
    };
}

function sendGroupsToUser(socket, userID) {
    const userGroups = [];
    for (const [groupID, group] of groups.entries()) {
        if (group.members.includes(userID)) userGroups.push(groupPublicData(groupID, group));
    }
    logEvent('GROUP', 'Enviando grupos do usuário', { userID, count: userGroups.length, groups: userGroups });
    socket.emit('your_groups', userGroups);
}

module.exports = { enqueue, deliver, flushQueue, groupPublicData, sendGroupsToUser, findSocketID };
