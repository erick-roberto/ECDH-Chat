import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';

const Point = secp256k1.ProjectivePoint;
const CURVE_ORDER = secp256k1.CURVE.n;

function randomScalar() {
  // CSPRNG do navegador; nunca usar Math.random() para material criptográfico.
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
function bytesToBigint(bytes) {
  return BigInt('0x' + bytesToHex(bytes));
}

// Serialização assinada: domínio + array de campos em ordem FIXA (não depende
// da ordem das chaves de um objeto). O prefixo de domínio impede que uma
// assinatura feita para um contexto (mensagem direta) valha em outro (grupo,
// registro), já que a mesma chave de identidade assina tudo.
const DIRECT_DOMAIN = 'chat-ecc/direct/v2';
const GROUP_DOMAIN = 'chat-ecc/group/v2';
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

// Identificador único (128 bits) da mensagem, via CSPRNG. Funciona também em
// contextos não seguros (HTTP na rede local), onde crypto.randomUUID não existe.
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
function parsePublicKey(publicKeyHex) {
  try {
    const point = Point.fromHex(publicKeyHex);
    if (point.equals(Point.ZERO)) throw new Error();
    return point;
  } catch {
    throw new Error('Chave pública inválida.');
  }
}

/*
 * Protótipo didático EC-ElGamal para mensagens curtas:
 * codifica [tamanho (1 byte) || UTF-8] no x de um ponto, usando 8 bits
 * de contador para procurar um x válido. Limite: 28 bytes UTF-8.
 * Não é uma construção padronizada nem deve ser usado para produção.
 */
function encodeMessagePoint(text) {
  const message = new TextEncoder().encode(text);

  if (message.length > 28) {
    throw new Error(
      'Nesta versão didática, a mensagem deve ter até 28 bytes UTF-8.'
    );
  }

  // Bloco fixo de 29 bytes:
  // 1 byte para o tamanho + até 28 bytes para a mensagem.
  const framed = new Uint8Array(29);
  framed[0] = message.length;
  framed.set(message, 1);

  // Reserva os 8 bits inferiores para o contador.
  const base = bytesToBigint(framed) << 8n;

  for (let counter = 0n; counter < 256n; counter++) {
    const x = base | counter;

    if (x >= secp256k1.CURVE.p) break;

    for (const prefix of [2, 3]) {
      try {
        const encodedPoint = concat(
          Uint8Array.of(prefix),
          bigintToBytes(x, 32)
        );

        return Point.fromHex(encodedPoint);
      } catch {
        // Tenta o próximo prefixo ou contador.
      }
    }
  }

  throw new Error('Não foi possível codificar a mensagem como ponto.');
}
function decodeMessagePoint(point) {
  const x = point.toAffine().x;

  // Recupera exatamente os 29 bytes usados na codificação.
  const framed = bigintToBytes(x >> 8n, 29);
  const length = framed[0];

  if (length > 28) {
    throw new Error(
      'Ponto descriptografado não contém uma mensagem válida.'
    );
  }

  return new TextDecoder('utf-8', { fatal: true }).decode(
    framed.slice(1, 1 + length)
  );
}

export function createIdentity() {
  const privateScalar = randomScalar();
  const privateKey = privateScalar.toString(16).padStart(64, '0');
  const publicKey = Point.BASE.multiply(privateScalar).toHex(true);
  return { privateKey, publicKey };
}

export const DIRECT_ALGORITHM = 'EC-ElGamal-secp256k1-direct-v2';
export const GROUP_ALGORITHM = 'EC-ElGamal-secp256k1-group-v2';
export const PROTOCOL_VERSION = 2;

const directFields = p => [
  p.version, p.algorithm, p.senderID, p.receiverID, p.messageId, p.sentAt, p.c1, p.c2
];
const groupFields = p => [
  p.version, p.algorithm, p.groupID, p.senderID, p.receiverID, p.messageId, p.sentAt, p.c1, p.c2
];

export function encryptForRecipient(text, recipientPublicKey, senderPrivateKey, senderID, receiverID) {
  const recipientPoint = parsePublicKey(recipientPublicKey);
  const messagePoint = encodeMessagePoint(text);
  const ephemeral = randomScalar();
  const c1 = Point.BASE.multiply(ephemeral);
  const c2 = messagePoint.add(recipientPoint.multiply(ephemeral));
  const unsigned = {
    version: PROTOCOL_VERSION,
    algorithm: DIRECT_ALGORITHM,
    senderID,
    receiverID,
    messageId: newMessageId(),
    sentAt: Date.now(),
    c1: c1.toHex(true),
    c2: c2.toHex(true)
  };
  const signature = signFields(DIRECT_DOMAIN, directFields(unsigned), senderPrivateKey);
  return { ...unsigned, signature };
}

// Retorna { plaintext, messageId, sentAt }. A assinatura é verificada ANTES de decifrar.
export function decryptAndVerify(packet, recipientPrivateKey, senderPublicKey, expectedUserID) {
  if (!packet || packet.algorithm !== DIRECT_ALGORITHM) {
    throw new Error('Algoritmo de mensagem direta desconhecido.');
  }
  if (packet.version !== PROTOCOL_VERSION) {
    throw new Error('Versão do pacote não suportada.');
  }
  if (expectedUserID && packet.receiverID !== expectedUserID) {
    throw new Error('A mensagem não foi destinada a este usuário.');
  }
  checkEnvelope(packet);
  // `type` e `timestamp` são adicionados pelo servidor e ficam fora da assinatura.
  if (!verifyFields(DIRECT_DOMAIN, directFields(packet), packet.signature, senderPublicKey)) {
    throw new Error('Assinatura inválida. Mensagem descartada.');
  }
  const d = BigInt('0x' + recipientPrivateKey);
  const c1 = Point.fromHex(packet.c1);
  const c2 = Point.fromHex(packet.c2);
  const messagePoint = c2.add(c1.multiply(d).negate());
  return {
    plaintext: decodeMessagePoint(messagePoint),
    messageId: packet.messageId,
    sentAt: packet.sentAt
  };
}

export function encryptForGroup(text, groupID, recipients, senderPrivateKey, senderID) {
  if (!Array.isArray(recipients) || recipients.length === 0) {
    throw new Error('O grupo não possui outros destinatários.');
  }

  const messagePoint = encodeMessagePoint(text);
  const ephemeral = randomScalar();
  const messageId = newMessageId();
  const sentAt = Date.now();

  // Um único C1 é compartilhado entre todos os destinatários.
  const c1 = Point.BASE.multiply(ephemeral).toHex(true);

  const encryptedBlocks = recipients
    .filter(recipient => recipient.username !== senderID)
    .map(recipient => {
      if (!recipient.username || !recipient.publicKey) {
        throw new Error('Chave pública de membro inválida.');
      }

      const recipientPoint = parsePublicKey(recipient.publicKey);

      // C2 específico para a chave pública deste destinatário.
      const c2 = messagePoint.add(recipientPoint.multiply(ephemeral)).toHex(true);

      const unsigned = {
        version: PROTOCOL_VERSION,
        algorithm: GROUP_ALGORITHM,
        groupID,
        senderID,
        receiverID: recipient.username,
        messageId,
        sentAt,
        c1,
        c2,
      };

      return {
        username: recipient.username,
        c2,
        signature: signFields(GROUP_DOMAIN, groupFields(unsigned), senderPrivateKey),
      };
    });

  if (encryptedBlocks.length === 0) {
    throw new Error('Não há outros membros para receber a mensagem.');
  }

  return {
    version: PROTOCOL_VERSION,
    algorithm: GROUP_ALGORITHM,
    groupID,
    senderID,
    messageId,
    sentAt,
    c1,
    encryptedBlocks,
  };
}

export function decryptGroupAndVerify(packet, recipientPrivateKey, senderPublicKey, expectedUserID) {
  if (!packet || packet.algorithm !== GROUP_ALGORITHM) {
    throw new Error('Algoritmo de mensagem de grupo desconhecido.');
  }
  if (packet.version !== PROTOCOL_VERSION) {
    throw new Error('Versão do pacote de grupo não suportada.');
  }
  if (expectedUserID && packet.receiverID !== expectedUserID) {
    throw new Error('A mensagem não foi destinada a este usuário.');
  }
  checkEnvelope(packet);

  if (!verifyFields(GROUP_DOMAIN, groupFields(packet), packet.signature, senderPublicKey)) {
    throw new Error('Assinatura do grupo inválida. Mensagem descartada.');
  }

  const privateScalar = BigInt(`0x${recipientPrivateKey}`);
  const c1 = Point.fromHex(packet.c1);
  const c2 = Point.fromHex(packet.c2);

  // Pm = C2 - d*C1
  const messagePoint = c2.add(c1.multiply(privateScalar).negate());

  return {
    plaintext: decodeMessagePoint(messagePoint),
    messageId: packet.messageId,
    sentAt: packet.sentAt,
  };
}

/* ---------- Autenticação de sessão (prova de posse da chave de identidade) ---------- */

// O servidor envia um nonce de uso único; o cliente assina [userID, nonce].
export function signRegistration(privateKeyHex, userID, nonce) {
  return signFields(REGISTER_DOMAIN, [userID, nonce], privateKeyHex);
}

/* ---------- Concessão de grupo: o criador assina a lista de membros ---------- */
// Impede que o servidor adicione/remova membros sem que os clientes percebam.

export function newGroupID() {
  return newMessageId();
}
const sortedMembers = members => [...new Set(members)].sort();

export function signGroupGrant(privateKeyHex, groupID, members, createdBy) {
  return signFields(GROUP_GRANT_DOMAIN, [groupID, sortedMembers(members), createdBy], privateKeyHex);
}
export function verifyGroupGrant(group, creatorPublicKey) {
  if (!group?.signature) return false;
  return verifyFields(
    GROUP_GRANT_DOMAIN,
    [group.groupID, sortedMembers(group.members), group.createdBy],
    group.signature,
    creatorPublicKey
  );
}

/* ---------- Fingerprint para verificação fora de banda ---------- */

export function fingerprint(publicKeyHex) {
  const digest = bytesToHex(sha256(hexToBytes(publicKeyHex))).slice(0, 40);
  return digest.match(/.{4}/g).join(' ');
}

export function validatePrivateKey(hex) {
  const bytes = hexToBytes(hex);
  if (bytes.length !== 32) throw new Error('Chave privada inválida.');
  const n = bytesToBigint(bytes);
  if (n <= 0n || n >= CURVE_ORDER) throw new Error('Chave privada fora do intervalo.');
  return true;
}

export function publicFromPrivate(hex) {
  validatePrivateKey(hex);
  return Point.BASE.multiply(BigInt('0x' + hex)).toHex(true);
}