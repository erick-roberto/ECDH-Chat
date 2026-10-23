const path = require('path');
const { pathToFileURL } = require('url');
const { io } = require('socket.io-client');

const URL = process.env.URL || 'http://localhost:3000';
const CRYPTO_PATH = path.resolve(__dirname, process.env.CRYPTO_PATH || '../../frontend/src/crypto.js');
const run = Date.now();
const name = n => `${n}_${run}`;

let failures = 0;
function check(label, condition) {
    console.log(`${condition ? 'OK   ' : 'FALHA'} ${label}`);
    if (!condition) failures++;
}

const connect = () =>
    new Promise((resolve, reject) => {
        const s = io(URL, { transports: ['websocket'] });
        s.on('connect', () => resolve(s));
        s.on('connect_error', reject);
    });
const emit = (socket, event, data) => new Promise(res => socket.emit(event, data, res));
const once = (socket, event, ms = 2000) =>
    new Promise((resolve, reject) => {
        const t = setTimeout(() => reject(new Error('timeout esperando ' + event)), ms);
        socket.once(event, (...args) => { clearTimeout(t); resolve(args); });
    });
const never = (socket, event, ms = 500) =>
    new Promise(resolve => {
        let got = false;
        socket.once(event, () => (got = true));
        setTimeout(() => resolve(!got), ms);
    });
const sleep = ms => new Promise(r => setTimeout(r, ms));

async function main() {
    const C = await import(pathToFileURL(CRYPTO_PATH).href);

    const ids = { alice: C.createIdentity(), bob: C.createIdentity(), carol: C.createIdentity() };
    const alice = name('alice'), bob = name('bob'), carol = name('carol');

    async function login(socket, userID, ident, overrides = {}) {
        const ch = await emit(socket, 'get_auth_challenge', {});
        return emit(socket, 'register_public_key', {
            userID,
            publicKey: ident.publicKey,
            signature: C.signRegistration(ident.privateKey, userID, ch.nonce),
            ...overrides,
        });
    }

    const sAlice = await connect();
    const sBob = await connect();
    let sCarol = await connect();

    let r = await login(sAlice, alice, ids.alice);
    check('alice autentica com a própria chave', r.success === true);
    r = await login(sBob, bob, ids.bob);
    check('bob autentica', r.success === true);

    const sMallory = await connect();
    const evil = C.createIdentity();
    r = await login(sMallory, alice, ids.alice, {
        signature: C.signRegistration(evil.privateKey, alice, 'x'.repeat(64)),
    });
    check('impersonar alice (sabendo só a chave pública) é recusado', r.success === false);

    r = await emit(sMallory, 'register_public_key', {
        userID: alice, publicKey: ids.alice.publicKey, signature: 'a'.repeat(128),
    });
    check('registro sem desafio é recusado', r.success === false);

    const ch = await emit(sMallory, 'get_auth_challenge', {});
    const sig = C.signRegistration(evil.privateKey, alice, ch.nonce);
    r = await emit(sMallory, 'register_public_key', { userID: alice, publicKey: evil.publicKey, signature: sig });
    check('trocar a chave de alice é recusado (mesmo com assinatura válida da chave nova)', r.success === false);

    r = await emit(sMallory, 'register_public_key', { userID: alice, publicKey: evil.publicKey, signature: sig });
    check('nonce é de uso único (replay do registro falha)', r.success === false);

    r = await emit(sBob, 'request_public_key', { targetUserID: alice });
    check('chave pública de alice disponível', r.success && r.publicKey === ids.alice.publicKey);

    const pkt = await C.encryptForRecipient('Bom dia', ids.bob.publicKey, ids.alice.privateKey, alice, bob);
    let p = once(sBob, 'receive_encrypted_message');
    r = await emit(sAlice, 'send_encrypted_message', pkt);
    const [got] = await p;
    check('servidor encaminhou a mensagem direta', r.success && r.delivered);
    const dec = await C.decryptAndVerify(got, ids.bob.privateKey, ids.alice.publicKey, bob);
    check('bob decifra "Bom dia"', dec.plaintext === 'Bom dia');
    check('servidor não repassa campos extras', !('lixo' in got));

    r = await emit(sAlice, 'send_encrypted_message', { ...pkt, lixo: 'x', senderID: 'mallory' });
    check('senderID forjado é recusado', r.success === false);
    r = await emit(sAlice, 'send_encrypted_message', { ...pkt, iv: 'zz' });
    check('iv malformado é recusado', r.success === false);

    const tampered = {
        ...got,
        ciphertext: got.ciphertext.slice(0, -1) + (got.ciphertext.endsWith('0') ? '1' : '0'),
    };
    let rejected = false;
    try { await C.decryptAndVerify(tampered, ids.bob.privateKey, ids.alice.publicKey, bob); } catch { rejected = true; }
    check('pacote adulterado é descartado pelo destinatário', rejected);

    r = await emit(sMallory, 'send_encrypted_message', pkt);
    check('socket não autenticado não envia mensagem', r.success === false);

    r = await login(sCarol, carol, ids.carol);
    sCarol.disconnect();
    await sleep(300);
    const offPkt = await C.encryptForRecipient('offline', ids.carol.publicKey, ids.alice.privateKey, alice, carol);
    r = await emit(sAlice, 'send_encrypted_message', offPkt);
    check('mensagem para offline entra na fila', r.success && r.delivered === false);

    sCarol = await connect();
    const pending = once(sCarol, 'pending_messages');
    await login(sCarol, carol, ids.carol);
    const [msgs, ack] = await pending;
    check('carol recebe a pendente ao reconectar', msgs.length === 1 && msgs[0].messageId === offPkt.messageId);
    if (typeof ack === 'function') ack({ success: true });
    await sleep(300);

    sCarol.disconnect();
    sCarol = await connect();
    const noPending = never(sCarol, 'pending_messages');
    await login(sCarol, carol, ids.carol);
    check('fila vazia depois do ACK', await noPending);

    const members = [alice, bob, carol];
    const groupID = C.newGroupID();
    r = await emit(sAlice, 'create_group', {
        groupID, members, signature: C.signGroupGrant(ids.alice.privateKey, groupID, members, alice),
    });
    check('create_group com assinatura do criador', r.success && r.groupKeys.length === 3);
    const group = r;
    check('cliente valida a concessão do grupo', C.verifyGroupGrant(group, ids.alice.publicKey));
    check('concessão com membro extra (servidor malicioso) é rejeitada',
        !C.verifyGroupGrant({ ...group, members: [...group.members, 'intruso'] }, ids.alice.publicKey));

    const g2 = C.newGroupID();
    r = await emit(sAlice, 'create_group', {
        groupID: g2, members, signature: C.signGroupGrant(ids.bob.privateKey, g2, members, alice),
    });
    check('create_group com assinatura de outra chave é recusado', r.success === false);

    const pBob = once(sBob, 'receive_group_encrypted_message');
    const pCarol = once(sCarol, 'receive_group_encrypted_message');
    const aliceNothing = never(sAlice, 'receive_group_encrypted_message');
    const gp = await C.encryptForGroup('Oi grupo', groupID, group.groupKeys, ids.alice.privateKey, alice);
    r = await emit(sAlice, 'send_group_encrypted_message', gp);
    const [gBob] = await pBob;
    const [gCarol] = await pCarol;
    check('mensagem de grupo entregue', r.success && r.delivered === 2);
    check('bob decifra no grupo', (await C.decryptGroupAndVerify(gBob, ids.bob.privateKey, ids.alice.publicKey, bob)).plaintext === 'Oi grupo');
    check('carol decifra no grupo', (await C.decryptGroupAndVerify(gCarol, ids.carol.privateKey, ids.alice.publicKey, carol)).plaintext === 'Oi grupo');
    check('ciphertext compartilhado, wrappedKey distintos', gBob.ciphertext === gCarol.ciphertext && gBob.wrappedKey !== gCarol.wrappedKey);
    check('alice não recebe a própria mensagem', await aliceNothing);

    let domainRejected = false;
    try { await C.decryptGroupAndVerify({ ...gBob, algorithm: 'x' }, ids.bob.privateKey, ids.alice.publicKey, bob); } catch { domainRejected = true; }
    check('algoritmo inesperado é recusado', domainRejected);

    const dave = C.createIdentity();
    const sDave = await connect();
    await login(sDave, name('dave'), dave);
    r = await emit(sDave, 'send_group_encrypted_message', { ...gp, senderID: name('dave') });
    check('não-membro não envia ao grupo', r.success === false);

    const sSpam = await connect();
    let blocked = false;
    for (let i = 0; i < 60 && !blocked; i++) {
        const res = await emit(sSpam, 'request_public_key', { targetUserID: alice });
        if (!res.success && /Muitas/.test(res.message)) blocked = true;
    }
    check('rate limit bloqueia excesso de requisições', blocked);

    const rotated = C.createIdentity();
    const chBad = await emit(sBob, 'get_auth_challenge', {});
    r = await emit(sBob, 'register_public_key', {
        userID: bob,
        publicKey: rotated.publicKey,
        signature: C.signRegistration(rotated.privateKey, bob, chBad.nonce),
        previousPublicKey: ids.bob.publicKey,
        rotationSignature: C.signKeyRotation(rotated.privateKey, bob, ids.bob.publicKey, rotated.publicKey, chBad.nonce),
    });
    check('rotação sem a chave privada atual é recusada', r.success === false);

    const chRotate = await emit(sBob, 'get_auth_challenge', {});
    r = await emit(sBob, 'register_public_key', {
        userID: bob,
        publicKey: rotated.publicKey,
        signature: C.signRegistration(rotated.privateKey, bob, chRotate.nonce),
        previousPublicKey: ids.bob.publicKey,
        rotationSignature: C.signKeyRotation(ids.bob.privateKey, bob, ids.bob.publicKey, rotated.publicKey, chRotate.nonce),
    });
    check('rotação assinada pela chave atual é aceite', r.success === true);

    r = await emit(sAlice, 'request_public_key', { targetUserID: bob });
    check('chave pública atualizada após rotação', r.success && r.publicKey === rotated.publicKey);

    const aliceNext = C.createIdentity();
    const chAlice = await emit(sAlice, 'get_auth_challenge', {});
    r = await emit(sAlice, 'register_public_key', {
        userID: alice,
        publicKey: aliceNext.publicKey,
        signature: C.signRegistration(aliceNext.privateKey, alice, chAlice.nonce),
        previousPublicKey: ids.alice.publicKey,
        rotationSignature: C.signKeyRotation(ids.alice.privateKey, alice, ids.alice.publicKey, aliceNext.publicKey, chAlice.nonce),
    });
    check('criador de grupo não troca a chave sem recriar o grupo', r.success === false);

    [sAlice, sBob, sCarol, sMallory, sDave, sSpam].forEach(s => s.disconnect());
    console.log(failures === 0 ? '\nTodos os testes passaram.' : `\n${failures} teste(s) falharam.`);
    process.exit(failures === 0 ? 0 : 1);
}

main().catch(err => { console.error('Erro no teste:', err); process.exit(1); });
