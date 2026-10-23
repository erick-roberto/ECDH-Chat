const registerAuthHandlers = require('./handlers/authHandler');
const registerUserHandlers = require('./handlers/userHandler');
const registerMessageHandlers = require('./handlers/messageHandler');
const registerGroupHandlers = require('./handlers/groupHandler');
const { users, onlineUserIDs } = require('./utils/shared');
const { logEvent, logError } = require('../utils/logger');

module.exports = function setupSocket(io) {
    io.on('connection', socket => {
        logEvent('SOCKET', 'Novo cliente conectado', { socketID: socket.id, address: socket.handshake.address, transport: socket.conn.transport.name, headers: socket.handshake.headers, query: socket.handshake.query, auth: socket.handshake.auth });

        // Captura todos os eventos recebidos, inclusive payloads não cobertos pelos logs específicos.
        // O Socket.IO remove callbacks dos argumentos de onAny; somente dados serializáveis são registrados.
        socket.onAny((eventName, ...args) => {
            logEvent('SOCKET:IN', `Evento recebido: ${eventName}`, { socketID: socket.id, userID: users.get(socket.id)?.userID || null, eventName, args });
        });

        socket.on('error', error => {
            logError('SOCKET', 'Erro no socket', error, { socketID: socket.id, userID: users.get(socket.id)?.userID || null });
        });

        registerAuthHandlers(socket, io);
        registerUserHandlers(socket, io);
        registerMessageHandlers(socket, io);
        registerGroupHandlers(socket, io);

        socket.on('disconnect', (reason, description) => {
            logEvent('SOCKET', 'Conexão encerrada', { socketID: socket.id, reason, description, userID: users.get(socket.id)?.userID || null });
            const user = users.get(socket.id);
            if (user) {
                users.delete(socket.id);
                io.emit('user_list_update', onlineUserIDs());
                logEvent('SOCKET', 'Usuário desconectado', { userID: user.userID, socketID: socket.id });
            }
        });
    });
};
