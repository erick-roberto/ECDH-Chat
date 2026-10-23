const { secp256k1 } = require('@noble/curves/secp256k1');
const { sha256 } = require('@noble/hashes/sha256');
const { users, publicKeys, groups } = require('../../state/runtimeState');
const { logEvent } = require('../../utils/logger');

const MAX_GROUP_SIZE = 100;
const PROTOCOL_VERSION = 2;
const DIRECT_ALGORITHM = 'EC-ElGamal-secp256k1-direct-v2';
const GROUP_ALGORITHM = 'EC-ElGamal-secp256k1-group-v2';
const REGISTER_DOMAIN = 'chat-ecc/register/v1';
const GROUP_GRANT_DOMAIN = 'chat-ecc/group-grant/v1';
const RATE_WINDOW_MS = 10_000;
const RATE_MAX_EVENTS = 40;

function reply(callback, data) {
    if (typeof callback === 'function') callback(data);
}

function isValidID(value) {
    return typeof value === 'string' && value.trim().length > 0 && value.length <= 128;
}

const isHex = (value, length) =>
    typeof value === 'string' && value.length === length && /^[0-9a-f]+$/i.test(value);
const isPointHex = value => isHex(value, 66);
const isSignatureHex = value => isHex(value, 128);
const isMessageID = value => isHex(value, 32);
const isTimestamp = value => Number.isSafeInteger(value) && value > 0;

function isValidPublicKey(value) {
    if (!isPointHex(value)) return false;
    try {
        secp256k1.ProjectivePoint.fromHex(value);
        return true;
    } catch {
        return false;
    }
}

function verifySignature(domain, fields, signature, publicKey) {
    try {
        const bytes = new TextEncoder().encode(`${domain}\n${JSON.stringify(fields)}`);
        return secp256k1.verify(signature, sha256(bytes), publicKey);
    } catch {
        return false;
    }
}

function allowed(socket) {
    const now = Date.now();
    const hits = (socket.data.hits || []).filter(t => now - t < RATE_WINDOW_MS);
    hits.push(now);
    socket.data.hits = hits;
    const permitted = hits.length <= RATE_MAX_EVENTS;
    if (!permitted) {
        logEvent('SECURITY', 'Limite de requisições excedido', { socketID: socket.id, countInWindow: hits.length, windowMs: RATE_WINDOW_MS });
    }
    return permitted;
}

const sortedMembers = members => [...new Set(members)].sort();

function findSocketID(userID) {
    for (const [id, user] of users.entries()) {
        if (user.userID === userID) return id;
    }
    return null;
}

function onlineUserIDs() {
    return [...new Set(Array.from(users.values(), user => user.userID))];
}

module.exports = {
    users, publicKeys, groups,
    MAX_GROUP_SIZE, PROTOCOL_VERSION, DIRECT_ALGORITHM, GROUP_ALGORITHM,
    REGISTER_DOMAIN, GROUP_GRANT_DOMAIN,
    reply, isValidID, isPointHex, isSignatureHex, isMessageID, isTimestamp,
    isValidPublicKey, verifySignature, allowed, sortedMembers, findSocketID, onlineUserIDs,
};
