const worker = new Worker(new URL('./crypto.worker.js', import.meta.url), { type: 'module' });

let callId = 0;
const pending = new Map();

worker.onmessage = (e) => {
  const { id, success, result, error } = e.data;
  
  if (pending.has(id)) {
    const { resolve, reject } = pending.get(id);
    pending.delete(id);
    
    if (success) {
      resolve(result);
    } else {
      reject(new Error(error));
    }
  }
};

export function runCrypto(method, ...args) {
  return new Promise((resolve, reject) => {
    const id = ++callId;
    pending.set(id, { resolve, reject });
    
    worker.postMessage({ id, method, args });
  });
}