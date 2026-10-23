// Logger acadêmico detalhado para depuração local do ECDH-Chat.
// Atenção: os payloads podem conter dados sensíveis. Use somente em ambiente de teste.

function safeSerialize(value) {
    const seen = new WeakSet();
    try {
        return JSON.stringify(value, (key, item) => {
            if (typeof item === 'bigint') return item.toString();
            if (item && typeof item === 'object') {
                if (seen.has(item)) return '[Circular]';
                seen.add(item);
            }
            if (Buffer.isBuffer(item)) return { type: 'Buffer', length: item.length, hex: item.toString('hex') };
            if (item instanceof Error) {
                return { name: item.name, message: item.message, code: item.code, stack: item.stack };
            }
            return item;
        }, 2);
    } catch (error) {
        return `[Não foi possível serializar detalhes: ${error.message}]`;
    }
}

function logEvent(scope, event, details = {}) {
    const timestamp = new Date().toISOString();
    console.log(`\n[${timestamp}] [${scope}] ${event}`);
    if (details !== undefined && details !== null) {
        if (typeof details !== 'object' || Object.keys(details).length > 0) {
            console.log(safeSerialize(details));
        }
    }
}

function logError(scope, event, error, details = {}) {
    logEvent(scope, event, {
        ...details,
        error: error?.message || String(error),
        code: error?.code,
        name: error?.name,
        stack: error?.stack,
    });
}

module.exports = { logEvent, logError };
