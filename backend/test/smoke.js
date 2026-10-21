
const { io } = require('socket.io-client');

const URL = process.env.URL || 'http://localhost:3000';
const run = Date.now(); 
const name = (n) => `${n}_${run}`;

let failures = 0;
function check(label, condition) {
    console.log(`${condition ? 'OK  ' : 'FALHA'}  ${label}`);
    if (!condition) failures++;
}

function connect() {
    return new Promise((resolve, reject) => {
        const s = io(URL, { transports: ['websocket'] });
        s.on('connect', () => resolve(s));
        s.on('connect_error', reject);
    });
}

const emit = (socket, event, data) => new Promise((resolve) => socket.emit(event, data, resolve));

function once(socket, event, ms = 2000) {
    return new Promise((resolve, reject) => {
        const t = setTimeout(() => reject(new Error('timeout esperando ' + event)), ms);
        socket.once(event, (...args) => {
            clearTimeout(t);
            resolve(args);
        });
    });
}

// Garante que NADA chegou em `ms` milissegundos
function never(socket, event, ms = 500) {
    return new Promise((resolve) => {
        let got = false;
        socket.once(event, () => (got = true));
        setTimeout(() => resolve(!got), ms);
    });
}

async function main() {
    const alice = name('alice');
    const bob = name('bob');
    const carol = name('carol');

    const sAlice = await connect();
    const sBob = await connect();

    // 1. Registro
    let r = await emit(sAlice, 'register_public_key', { userID: alice, publicKey: 'KEY_ALICE' });
    check('registro de alice', r.success === true);
    r = await emit(sBob, 'register_public_key', { userID: bob, publicKey: 'KEY_BOB' });
    check('registro de bob', r.success === true);

    // 2. Substituição de chave deve ser recusada
    const sMallory = await connect();
    r = await emit(sMallory, 'register_public_key', { userID: alice, publicKey: 'KEY_FALSA' });
    check('recusa substituição da chave de alice', r.success === false);

    // 3. Consulta de chave
    r = await emit(sBob, 'request_public_key', { targetUserID: alice });
    check('request_public_key retorna a chave de alice', r.success && r.publicKey === 'KEY_ALICE');
    r = await emit(sBob, 'request_public_key', { targetUserID: 'ninguem' });
    check('request_public_key de usuário inexistente falha', r.success === false);

    // 4. Mensagem direta online + remetente forjado
    let p = once(sBob, 'receive_encrypted_message');
    r = await emit(sAlice, 'send_encrypted_message', {
        receiverID: bob,
        senderID: 'mallory', // deve ser ignorado
        ciphertext: 'abc',
    });
    const [pkt] = await p;
    check('bob recebeu a mensagem direta', r.success && r.delivered && pkt.ciphertext === 'abc');
    check('senderID forjado foi substituído pelo real', pkt.senderID === alice);

    // 5. Remetente não registrado
    r = await emit(sMallory, 'send_encrypted_message', { receiverID: bob, ciphertext: 'x' });
    check('socket não registrado não envia mensagem', r.success === false);

    // 6. Fila offline + ACK
    let sCarol = await connect();
    await emit(sCarol, 'register_public_key', { userID: carol, publicKey: 'KEY_CAROL' });
    sCarol.disconnect();
    await new Promise((res) => setTimeout(res, 300));

    r = await emit(sAlice, 'send_encrypted_message', { receiverID: carol, ciphertext: 'offline-1' });
    check('mensagem para offline entra na fila', r.success === true && r.delivered === false);

    sCarol = await connect();
    const pending = once(sCarol, 'pending_messages');
    await emit(sCarol, 'register_public_key', { userID: carol, publicKey: 'KEY_CAROL' });
    const [msgs, ack] = await pending;
    check('carol recebeu a pendente ao reconectar', msgs.length === 1 && msgs[0].ciphertext === 'offline-1');
    if (typeof ack === 'function') ack();
    await new Promise((res) => setTimeout(res, 300));

    // Reconectar de novo: fila deve estar vazia (ACK removeu)
    sCarol.disconnect();
    sCarol = await connect();
    const noPending = never(sCarol, 'pending_messages');
    await emit(sCarol, 'register_public_key', { userID: carol, publicKey: 'KEY_CAROL' });
    check('fila vazia depois do ACK', await noPending);

    // 7. Grupo
    r = await emit(sAlice, 'create_group', { members: [bob, carol] });
    check('create_group retorna groupID e chaves', r.success && r.groupID && r.groupKeys.length === 3);
    const groupID = r.groupID;

    const pBob = once(sBob, 'receive_group_encrypted_message');
    const pCarol = once(sCarol, 'receive_group_encrypted_message');
    const aliceNothing = never(sAlice, 'receive_group_encrypted_message');

    r = await emit(sAlice, 'send_group_encrypted_message', {
        groupID,
        c1: 'C1',
        signature: 'SIG',
        encryptedBlocks: [
            { username: alice, c2: 'para-alice' },
            { username: bob, c2: 'para-bob' },
            { username: carol, c2: 'para-carol' },
        ],
    });
    const [gBob] = await pBob;
    const [gCarol] = await pCarol;
    check('mensagem de grupo entregue a bob e carol', r.success && gBob.c2 === 'para-bob' && gCarol.c2 === 'para-carol');
    check('remetente do grupo é alice', gBob.from === alice);
    check('alice não recebe a própria mensagem', await aliceNothing);

    // 8. Quem não é do grupo não pode enviar
    const sDave = await connect();
    await emit(sDave, 'register_public_key', { userID: name('dave'), publicKey: 'KEY_DAVE' });
    r = await emit(sDave, 'send_group_encrypted_message', { groupID, c1: 'x', encryptedBlocks: [] });
    check('não-membro não envia ao grupo', r.success === false);

    [sAlice, sBob, sCarol, sMallory, sDave].forEach((s) => s.disconnect());

    console.log(failures === 0 ? '\nTodos os testes passaram.' : `\n${failures} teste(s) falharam.`);
    process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
    console.error('Erro no teste:', err.message);
    process.exit(1);
});