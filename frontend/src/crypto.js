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
function stablePacketBytes(packet) {
  return new TextEncoder().encode(JSON.stringify(packet));
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

export function encryptForRecipient(text, recipientPublicKey, senderPrivateKey, senderID, receiverID) {
  const recipientPoint = parsePublicKey(recipientPublicKey);
  const messagePoint = encodeMessagePoint(text);
  const ephemeral = randomScalar();
  const c1 = Point.BASE.multiply(ephemeral);
  const c2 = messagePoint.add(recipientPoint.multiply(ephemeral));
  const unsigned = {
    version: 1,
    algorithm: 'EC-ElGamal-secp256k1-demo',
    senderID,
    receiverID,
    c1: c1.toHex(true),
    c2: c2.toHex(true)
  };
  const signature = secp256k1.sign(sha256(stablePacketBytes(unsigned)), hexToBytes(senderPrivateKey)).toCompactHex();
  return { ...unsigned, signature };
}

export function decryptAndVerify(packet, recipientPrivateKey, senderPublicKey) {
  // Assina/verifica apenas os campos criptográficos imutáveis. O servidor adiciona
  // `type` e `timestamp` ao rotear a mensagem, portanto esses campos não entram na assinatura.
  const unsigned = {
    version: packet.version,
    algorithm: packet.algorithm,
    senderID: packet.senderID,
    receiverID: packet.receiverID,
    c1: packet.c1,
    c2: packet.c2
  };
  const verified = secp256k1.verify(
    packet.signature,
    sha256(stablePacketBytes(unsigned)),
    senderPublicKey
  );
  if (!verified) throw new Error('Assinatura inválida. Mensagem descartada.');
  const d = BigInt('0x' + recipientPrivateKey);
  const c1 = Point.fromHex(packet.c1);
  const c2 = Point.fromHex(packet.c2);
  const messagePoint = c2.add(c1.multiply(d).negate());
  return decodeMessagePoint(messagePoint);
}

const GROUP_ALGORITHM = 'EC-ElGamal-secp256k1-group-demo';

export function encryptForGroup(
  text,
  groupID,
  recipients,
  senderPrivateKey,
  senderID
) {
  if (!Array.isArray(recipients) || recipients.length === 0) {
    throw new Error('O grupo não possui outros destinatários.');
  }

  const messagePoint = encodeMessagePoint(text);
  const ephemeral = randomScalar();

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
      const c2 = messagePoint
        .add(recipientPoint.multiply(ephemeral))
        .toHex(true);

      const unsigned = {
        version: 1,
        algorithm: GROUP_ALGORITHM,
        groupID,
        senderID,
        receiverID: recipient.username,
        c1,
        c2,
      };

      const signature = secp256k1
        .sign(
          sha256(stablePacketBytes(unsigned)),
          hexToBytes(senderPrivateKey)
        )
        .toCompactHex();

      return {
        username: recipient.username,
        c2,
        signature,
      };
    });

  if (encryptedBlocks.length === 0) {
    throw new Error('Não há outros membros para receber a mensagem.');
  }

  return {
    version: 1,
    algorithm: GROUP_ALGORITHM,
    groupID,
    senderID,
    c1,
    encryptedBlocks,
  };
}

export function decryptGroupAndVerify(
  packet,
  recipientPrivateKey,
  senderPublicKey,
  expectedUserID
) {
  if (!packet || packet.algorithm !== GROUP_ALGORITHM) {
    throw new Error('Algoritmo de mensagem de grupo desconhecido.');
  }

  if (packet.version !== 1) {
    throw new Error('Versão do pacote de grupo não suportada.');
  }

  if (
    expectedUserID &&
    packet.receiverID !== expectedUserID
  ) {
    throw new Error('A mensagem não foi destinada a este usuário.');
  }

  const unsigned = {
    version: packet.version,
    algorithm: packet.algorithm,
    groupID: packet.groupID,
    senderID: packet.senderID,
    receiverID: packet.receiverID,
    c1: packet.c1,
    c2: packet.c2,
  };

  const verified = secp256k1.verify(
    packet.signature,
    sha256(stablePacketBytes(unsigned)),
    senderPublicKey
  );

  if (!verified) {
    throw new Error('Assinatura do grupo inválida. Mensagem descartada.');
  }

  const privateScalar = BigInt(`0x${recipientPrivateKey}`);
  const c1 = Point.fromHex(packet.c1);
  const c2 = Point.fromHex(packet.c2);

  // Pm = C2 - d*C1
  const messagePoint = c2.add(c1.multiply(privateScalar).negate());

  return decodeMessagePoint(messagePoint);
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