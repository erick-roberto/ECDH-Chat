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
    return;
  }
}

export function pinKey(userID, publicKey) {
  const pins = load(PINS_KEY, {});
  if (!pins[userID]) {
    pins[userID] = publicKey;
    save(PINS_KEY, pins);
    return { status: 'new' };
  }
  if (pins[userID] !== publicKey) {
    return { status: 'changed' };
  }
  return { status: 'same' };
}

export function acceptNewKey(userID, publicKey) {
  const pins = load(PINS_KEY, {});
  pins[userID] = publicKey;
  save(PINS_KEY, pins);
}

export function forgetPin(userID) {
  const pins = load(PINS_KEY, {});
  delete pins[userID];
  save(PINS_KEY, pins);
}

let seen = new Set(load(SEEN_KEY, []));
export function alreadySeen(messageId) {
  if (seen.has(messageId)) return true;
  seen.add(messageId);
  if (seen.size > MAX_SEEN) {
    seen = new Set([...seen].slice(-MAX_SEEN));
  }
  save(SEEN_KEY, [...seen]);
  return false;
}