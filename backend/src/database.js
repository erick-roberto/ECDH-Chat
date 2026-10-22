const {
    pool,
    testDatabaseConnection,
} = require('./config/database');

const {
    users,
    publicKeys,
    messageQueue,
    groups,
} = require('./state/runtimeState');

const userRepository = require('./repositories/userRepository');
const messageRepository = require('./repositories/messageRepository');
const groupRepository = require('./repositories/groupRepository');

module.exports = {
    users,
    publicKeys,
    messageQueue,
    groups,
    pool,
    testDatabaseConnection,
    ...userRepository,
    ...messageRepository,
    ...groupRepository,
};