import { io } from 'socket.io-client';

const URL = import.meta.env.VITE_SOCKET_URL || 'http://localhost:3000';

export function createSocket() {
  return io(URL, { autoConnect: false, transports: ['websocket', 'polling'] });
}

export function emitAck(socket, event, payload) {
  return new Promise((resolve, reject) => {
    if (!socket?.connected) return reject(new Error('Não conectado ao servidor.'));
    const timeout = setTimeout(() => reject(new Error(`Tempo esgotado no evento ${event}.`)), 8000);
    socket.emit(event, payload, response => {
      clearTimeout(timeout);
      if (!response) return reject(new Error('Resposta vazia do servidor.'));
      resolve(response);
    });
  });
}