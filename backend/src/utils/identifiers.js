
function compactHexToUuid(value) {
    if (
        typeof value !== 'string' ||
        !/^[0-9a-f]{32}$/i.test(value)
    ) {
        throw new Error('Identificador hexadecimal inválido.');
    }

    return [
        value.slice(0, 8),
        value.slice(8, 12),
        value.slice(12, 16),
        value.slice(16, 20),
        value.slice(20, 32),
    ].join('-');
}

function uuidToCompactHex(value) {
    return String(value).replace(/-/g, '');
}

module.exports = {
    compactHexToUuid,
    uuidToCompactHex,
};
