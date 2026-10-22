const registerAuthHandlers = require('./handlers/authHandler');
const registerUserHandlers = require('./handlers/userHandler');
const registerMessageHandlers = require('./handlers/messageHandler');
const registerGroupHandlers = require('./handlers/groupHandler');
const { users, onlineUserIDs } = require('./utils/shared');

module.exports = function setupSocket(io) {
    io.on('connection', socket => {
        console.log('User connected:', socket.id);

        registerAuthHandlers(socket, io);
        registerUserHandlers(socket, io);
        registerMessageHandlers(socket, io);
        registerGroupHandlers(socket, io);

        socket.on('disconnect', () => {
            const user = users.get(socket.id);
            if (user) {
                users.delete(socket.id);
                io.emit('user_list_update', onlineUserIDs());
                console.log('User disconnected:', user.userID);
            }
        });
    });
};
