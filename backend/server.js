// caminho: backend/server.js
const express = require('express');
const http = require('http');
const cors = require('cors');
const { Server } = require('socket.io');
const setupSocket = require('./src/socket');

// Em produção, defina CORS_ORIGIN (ex.: https://meuchat.com). Em dev, aceita qualquer origem.
const CORS_ORIGIN = process.env.CORS_ORIGIN || '*';

const app = express();
app.use(cors({ origin: CORS_ORIGIN }));

app.get('/health', (req, res) => res.json({ status: 'ok' }));

const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: CORS_ORIGIN,
        methods: ['GET', 'POST'],
    },
    maxHttpBufferSize: 1e6, // 1 MB por mensagem
});

setupSocket(io);

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log('Server is running on port:', PORT);
});