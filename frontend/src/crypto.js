import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';

const Point = secp256k1.ProjectivePoint;
const CURVE_ORDER = secp256k1.CURVE.n;

function randomScalar() {
  const bytes = new Uint8Array(32);
  for (;;) {
    crypto.getRandomValues(bytes);
    let n = BigInt('0x' + bytesToHex(bytes));
    if (n > 0n && n < CURVE_ORDER) return n;
  }
}

function bytesToHex(bytes) {
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}
function hexToBytes(hex) {
  if (typeof hex !== 'string' || hex.length % 2 || !/^[0-9a-f]*$/i.test(hex)) {
    throw new Error('Hexadecimal inválido.');
  }
  return Uint8Array.from(hex.match(/.{2}/g) || [], b => parseInt(b, 16));
}
function bigintToBytes(n, length) {
  return hexToBytes(n.toString(16).padStart(length * 2, '0'));
}
function concat(...arrays) {
  const out = new Uint8Array(arrays.reduce((sum, a) => sum + a.length, 0));
  let offset = 0;
  for (const a of arrays) { out.set(a, offset); offset += a.length; }
  return out;
}

// Domínios de Assinatura
const DIRECT_DOMAIN = 'chat-ecc/direct/v3';
const GROUP_DOMAIN = 'chat-ecc/group/v3';
const REGISTER_DOMAIN = 'chat-ecc/register/v1';
const GROUP_GRANT_DOMAIN = 'chat-ecc/group-grant/v1';

function signedBytes(domain, fields) {
  return new TextEncoder().encode(`${domain}\n${JSON.stringify(fields)}`);
}
function signFields(domain, fields, privateKeyHex) {
  return secp256k1
    .sign(sha256(signedBytes(domain, fields)), hexToBytes(privateKeyHex))
    .toCompactHex();
}
function verifyFields(domain, fields, signatureHex, publicKeyHex) {
  try {
    return secp256k1.verify(signatureHex, sha256(signedBytes(domain, fields)), publicKeyHex);
  } catch {
    return false;
  }
}

export function newMessageId() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return bytesToHex(bytes);
}

function checkEnvelope(packet) {
  if (typeof packet.messageId !== 'string' || !/^[0-9a-f]{32}$/.test(packet.messageId)) {
    throw new Error('messageId inválido.');
  }
  if (!Number.isSafeInteger(packet.sentAt) || packet.sentAt <= 0) {
    throw new Error('sentAt inválido.');
  }
}

export function createIdentity() {
  const privateScalar = randomScalar();
  const privateKey = privateScalar.toString(16).padStart(64, '0');
  const publicKey = Point.BASE.multiply(privateScalar).toHex(true);
  return { privateKey, publicKey };
}

// Novos Algoritmos Híbridos
export const DIRECT_ALGORITHM = 'Hybrid-ECDHE-AES256GCM-direct-v3';
export const GROUP_ALGORITHM = 'Hybrid-ECDHE-AES256GCM-group-v3';
export const PROTOCOL_VERSION = 3;

// A estrutura do pacote mudou: saiu c1/c2, entrou ePub, iv e ciphertext
const directFields = p => [
  p.version, p.algorithm, p.senderID, p.receiverID, p.messageId, p.sentAt, p.ePub, p.iv, p.ciphertext
];
const groupFields = p => [
  p.version, p.algorithm, p.groupID, p.senderID, p.receiverID, p.messageId, p.sentAt, p.ePub, p.iv, p.ciphertext, p.wrappedKey
];

/* ---------- Mensagens Diretas (ECDHE + AES-GCM) ---------- */

export async function encryptForRecipient(text, recipientPublicKeyHex, senderPrivateKeyHex, senderID, receiverID) {
  // 1. ECDHE: Gera chave efêmera para esta mensagem (Garante PFS)
  const ePriv = randomScalar();
  const ePub = Point.BASE.multiply(ePriv).toHex(true);

  // 2. Calcula o Segredo Partilhado com o destinatário
  const sharedSecret = secp256k1.getSharedSecret(bigintToBytes(ePriv, 32), hexToBytes(recipientPublicKeyHex));
  const aesKeyMaterial = sha256(sharedSecret); // Deriva chave de 32 bytes (256 bits)

  // 3. AES-GCM: Cifra a mensagem (Tamanho ilimitado)
  const cryptoKey = await crypto.subtle.importKey('raw', aesKeyMaterial, { name: 'AES-GCM' }, false, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encodedText = new TextEncoder().encode(text);
  const cipherBuffer = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, cryptoKey, encodedText);

  const unsigned = {
    version: PROTOCOL_VERSION,
    algorithm: DIRECT_ALGORITHM,
    senderID,
    receiverID,
    messageId: newMessageId(),
    sentAt: Date.now(),
    ePub,
    iv: bytesToHex(iv),
    ciphertext: bytesToHex(new Uint8Array(cipherBuffer))
  };

  // 4. Assina o pacote com a chave de Identidade para provar a autoria
  const signature = signFields(DIRECT_DOMAIN, directFields(unsigned), senderPrivateKeyHex);
  return { ...unsigned, signature };
}

export async function decryptAndVerify(packet, recipientPrivateKeyHex, senderPublicKeyHex, expectedUserID) {
  if (!packet || packet.algorithm !== DIRECT_ALGORITHM) throw new Error('Algoritmo direto desconhecido.');
  if (packet.version !== PROTOCOL_VERSION) throw new Error('Versão do pacote não suportada.');
  if (expectedUserID && packet.receiverID !== expectedUserID) throw new Error('A mensagem não foi destinada a este usuário.');
  
  checkEnvelope(packet);

  // 1. Verifica Assinatura
  if (!verifyFields(DIRECT_DOMAIN, directFields(packet), packet.signature, senderPublicKeyHex)) {
    throw new Error('Assinatura inválida. Mensagem descartada.');
  }

  // 2. ECDHE: Calcula o Segredo Partilhado usando a chave privada e a ePub recebida
  const sharedSecret = secp256k1.getSharedSecret(hexToBytes(recipientPrivateKeyHex), hexToBytes(packet.ePub));
  const aesKeyMaterial = sha256(sharedSecret);

  // 3. AES-GCM: Decifra a mensagem
  const cryptoKey = await crypto.subtle.importKey('raw', aesKeyMaterial, { name: 'AES-GCM' }, false, ['decrypt']);
  try {
    const plainBuffer = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: hexToBytes(packet.iv) },
      cryptoKey,
      hexToBytes(packet.ciphertext)
    );
    return {
      plaintext: new TextDecoder('utf-8').decode(plainBuffer),
      messageId: packet.messageId,
      sentAt: packet.sentAt
    };
  } catch (err) {
    throw new Error('Falha ao decifrar a mensagem (AES-GCM).');
  }
}

/* ---------- Mensagens de Grupo (AES Envelope + ECDHE) ---------- */

export async function encryptForGroup(text, groupID, recipients, senderPrivateKeyHex, senderID) {
  if (!Array.isArray(recipients) || recipients.length === 0) throw new Error('O grupo está vazio.');

  // 1. Gera uma Chave AES aleatória apenas para esta mensagem e cifra o texto 1 vez
  const messageAesKey = crypto.getRandomValues(new Uint8Array(32));
  const cryptoKey = await crypto.subtle.importKey('raw', messageAesKey, { name: 'AES-GCM' }, false, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const cipherBuffer = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, cryptoKey, new TextEncoder().encode(text));
  const ciphertextHex = bytesToHex(new Uint8Array(cipherBuffer));
  const ivHex = bytesToHex(iv);

  // 2. Gera a Chave Efêmera do Grupo
  const ePriv = randomScalar();
  const ePub = Point.BASE.multiply(ePriv).toHex(true);
  const messageId = newMessageId();
  const sentAt = Date.now();

  // 3. Embrulha a chave AES para cada membro do grupo
  const encryptedBlocks = recipients
    .filter(recipient => recipient.username !== senderID)
    .map(recipient => {
      const sharedSecret = secp256k1.getSharedSecret(bigintToBytes(ePriv, 32), hexToBytes(recipient.publicKey));
      const kek = sha256(sharedSecret); // Key Encryption Key
      
      // Encripta a chave AES fazendo um XOR com o KEK gerado via ECDHE
      const wrappedKey = new Uint8Array(32);
      for (let i = 0; i < 32; i++) wrappedKey[i] = messageAesKey[i] ^ kek[i];
      const wrappedKeyHex = bytesToHex(wrappedKey);

      const unsigned = {
        version: PROTOCOL_VERSION, algorithm: GROUP_ALGORITHM, groupID, senderID,
        receiverID: recipient.username, messageId, sentAt, ePub, iv: ivHex,
        ciphertext: ciphertextHex, wrappedKey: wrappedKeyHex,
      };

      return {
        username: recipient.username,
        wrappedKey: wrappedKeyHex,
        signature: signFields(GROUP_DOMAIN, groupFields(unsigned), senderPrivateKeyHex),
      };
    });

  if (encryptedBlocks.length === 0) throw new Error('Não há outros membros.');

  return {
    version: PROTOCOL_VERSION, algorithm: GROUP_ALGORITHM, groupID, senderID,
    messageId, sentAt, ePub, iv: ivHex, ciphertext: ciphertextHex, encryptedBlocks,
  };
}

export async function decryptGroupAndVerify(packet, recipientPrivateKeyHex, senderPublicKeyHex, expectedUserID) {
  if (!packet || packet.algorithm !== GROUP_ALGORITHM) throw new Error('Algoritmo de grupo desconhecido.');
  if (packet.version !== PROTOCOL_VERSION) throw new Error('Versão não suportada.');
  if (expectedUserID && packet.receiverID !== expectedUserID) throw new Error('Mensagem não destinada a você.');
  
  checkEnvelope(packet);

  if (!verifyFields(GROUP_DOMAIN, groupFields(packet), packet.signature, senderPublicKeyHex)) {
    throw new Error('Assinatura do grupo inválida.');
  }

  // 1. Calcula o Segredo Partilhado e recupera a chave AES
  const sharedSecret = secp256k1.getSharedSecret(hexToBytes(recipientPrivateKeyHex), hexToBytes(packet.ePub));
  const kek = sha256(sharedSecret);
  
  const wrappedKey = hexToBytes(packet.wrappedKey);
  const messageAesKey = new Uint8Array(32);
  for (let i = 0; i < 32; i++) messageAesKey[i] = wrappedKey[i] ^ kek[i];

  // 2. Decifra a mensagem com a chave AES recuperada
  const cryptoKey = await crypto.subtle.importKey('raw', messageAesKey, { name: 'AES-GCM' }, false, ['decrypt']);
  try {
    const plainBuffer = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: hexToBytes(packet.iv) },
      cryptoKey,
      hexToBytes(packet.ciphertext)
    );
    return {
      plaintext: new TextDecoder('utf-8').decode(plainBuffer),
      messageId: packet.messageId,
      sentAt: packet.sentAt,
    };
  } catch(err) {
    throw new Error('Falha ao decifrar mensagem de grupo (AES-GCM).');
  }
}

export function signRegistration(privateKeyHex, userID, nonce) {
  return signFields(REGISTER_DOMAIN, [userID, nonce], privateKeyHex);
}
export function newGroupID() { return newMessageId(); }
const sortedMembers = members => [...new Set(members)].sort();
export function signGroupGrant(privateKeyHex, groupID, members, createdBy) {
  return signFields(GROUP_GRANT_DOMAIN, [groupID, sortedMembers(members), createdBy], privateKeyHex);
}
export function verifyGroupGrant(group, creatorPublicKey) {
  if (!group?.signature) return false;
  return verifyFields(GROUP_GRANT_DOMAIN, [group.groupID, sortedMembers(group.members), group.createdBy], group.signature, creatorPublicKey);
}
export function fingerprint(publicKeyHex) {
  const digest = bytesToHex(sha256(hexToBytes(publicKeyHex))).slice(0, 40);
  return digest.match(/.{4}/g).join(' ');
}
export function validatePrivateKey(hex) {
  const bytes = hexToBytes(hex);
  if (bytes.length !== 32) throw new Error('Chave privada inválida.');
  return true;
}
export function publicFromPrivate(hex) {
  validatePrivateKey(hex);
  return Point.BASE.multiply(BigInt('0x' + hex)).toHex(true);
}