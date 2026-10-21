// Fixação de chaves (TOFU) e deduplicação de mensagens.
// Só guarda dados PÚBLICOS (chaves públicas e IDs de mensagem), nunca chaves privadas.
const PINS_KEY = 'chat-ecc.pins.v2';
const SEEN_KEY = 'chat-ecc.seen.v2';
const MAX_SEEN = 2000;

function load(key, fallback) {
  try {
    return JSON.parse(localStorage.getItem(key) || 'null') ?? fallback;
  } catch {
    return fallback;
  }
}
function save(key, value) {
  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch {
    /* armazenamento cheio ou indisponível: segue sem persistir */
  }
}

// Primeira vez que vemos o usuário: fixa a chave. Depois, qualquer mudança é
// tratada como possível ataque (o servidor é quem distribui as chaves).
export function pinKey(userID, publicKey) {
  const pins = load(PINS_KEY, {});
  if (!pins[userID]) {
    pins[userID] = publicKey;
    save(PINS_KEY, pins);
    return 'new';
  }
  if (pins[userID] !== publicKey) {
    throw new Error(
      `A chave pública de "${userID}" mudou. Possível ataque man-in-the-middle; verifique o fingerprint com a pessoa antes de continuar.`
    );
  }
  return 'same';
}

export function forgetPin(userID) {
  const pins = load(PINS_KEY, {});
  delete pins[userID];
  save(PINS_KEY, pins);
}

// Retorna true se o messageId já foi processado (replay) e registra se for novo.
const seen = new Set(load(SEEN_KEY, []));
export function alreadySeen(messageId) {
  if (seen.has(messageId)) return true;
  seen.add(messageId);
  const list = [...seen].slice(-MAX_SEEN);
  save(SEEN_KEY, list);
  return false;
}