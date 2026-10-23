const { users, publicKeys, messageQueue, groups } = require('../state/runtimeState');
const { getPendingMessages, markMessagesDelivered } = require('../database');

const ACK_TIMEOUT_MS = 5000;
const MAX_QUEUE_PER_USER = 500;

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

function findSocketID(userID) {
    for (const [id, user] of users.entries()) {
        if (user.userID === userID) return id;
    }
    return null;
}

async function flushQueue(socket, userID) {
    try {
        const pending = await getPendingMessages(userID);
        if (pending.length === 0) return;

        const batch = pending.slice(0, MAX_QUEUE_PER_USER);
        const packets = batch.map(item => item.packet);
        const databaseIDs = batch.map(item => item.dbId);

        socket.timeout(ACK_TIMEOUT_MS).emit('pending_messages', packets, async (err, response) => {
            if (err) return;
            if (!response || response.success !== true) {
                console.warn(`O cliente não confirmou o processamento das mensagens de ${userID}.`);
                return;
            }
            try {
                await markMessagesDelivered(databaseIDs, userID);
                console.log(`Mensagens pendentes confirmadas para ${userID}: ${databaseIDs.length}`);
            } catch (error) {
                console.error('Erro ao atualizar mensagens entregues:', error.message);
            }
        });
    } catch (error) {
        console.error(`Erro ao recuperar mensagens pendentes de ${userID}:`, error.message);
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
    socket.emit('your_groups', userGroups);
}

module.exports = { enqueue, deliver, flushQueue, groupPublicData, sendGroupsToUser, findSocketID };
