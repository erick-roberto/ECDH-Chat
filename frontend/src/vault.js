const ENCODER = new TextEncoder();
const DECODER = new TextDecoder();
const SALT_KEY = 'chat-ecc.salt';
const DATA_KEY = 'chat-ecc.vault.v1';

function getSalt() {
  let saltHex = localStorage.getItem(SALT_KEY);
  if (!saltHex) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    saltHex = Array.from(salt).map(b => b.toString(16).padStart(2, '0')).join('');
    localStorage.setItem(SALT_KEY, saltHex);
  }
  return new Uint8Array(saltHex.match(/.{1,2}/g).map(b => parseInt(b, 16)));
}

async function getEncryptionKey(password) {
  const keyMaterial = await crypto.subtle.importKey(
    'raw', ENCODER.encode(password), { name: 'PBKDF2' }, false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: getSalt(), iterations: 100000, hash: 'SHA-256' },
    keyMaterial, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
  );
}

export async function saveIdentitySecurely(identity, password) {
  const key = await getEncryptionKey(password);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encodedData = ENCODER.encode(JSON.stringify(identity));
  
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encodedData);
  
  const payload = {
    iv: Array.from(iv).map(b => b.toString(16).padStart(2, '0')).join(''),
    data: Array.from(new Uint8Array(encrypted)).map(b => b.toString(16).padStart(2, '0')).join('')
  };
  localStorage.setItem(DATA_KEY, JSON.stringify(payload));
}

export async function loadIdentitySecurely(password) {
  const payloadStr = localStorage.getItem(DATA_KEY);
  if (!payloadStr) return null;
  
  const payload = JSON.parse(payloadStr);
  const key = await getEncryptionKey(password);
  const iv = new Uint8Array(payload.iv.match(/.{1,2}/g).map(b => parseInt(b, 16)));
  const encrypted = new Uint8Array(payload.data.match(/.{1,2}/g).map(b => parseInt(b, 16)));
  
  try {
    const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, encrypted);
    return JSON.parse(DECODER.decode(decrypted));
  } catch (e) {
    console.error("Error decrypting identity:", e);
    throw new Error("Palavra-passe incorreta ou cofre corrompido.");
  }
}

export function hasSecureIdentity() {
  return localStorage.getItem(DATA_KEY) !== null;
}