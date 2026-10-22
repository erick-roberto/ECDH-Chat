import { encryptForGroup, encryptForRecipient, decryptAndVerify, decryptGroupAndVerify } from './crypto';

self.onmessage = (e) => {
  const { id, method, args } = e.data;
  try {
    let result;
    switch (method) {
      case 'encryptForRecipient':
        result = encryptForRecipient(...args);
        break;
      case 'encryptForGroup':
        result = encryptForGroup(...args);
        break;
      case 'decryptAndVerify':
        result = decryptAndVerify(...args);
        break;
      case 'decryptGroupAndVerify':
        result = decryptGroupAndVerify(...args);
        break;
      default:
        throw new Error('Método criptográfico desconhecido.');
    }
    self.postMessage({ id, success: true, result });
  } catch (error) {
    self.postMessage({ id, success: false, error: error.message });
  }
};