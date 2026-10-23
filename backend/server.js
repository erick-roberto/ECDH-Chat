
require('dotenv').config();

const express = require('express');
const http = require('http');
const cors = require('cors');
const { Server } = require('socket.io');
const { logEvent, logError } = require('./src/utils/logger');

const setupSocket = require('./src/socket');
const {
    testDatabaseConnection,
    loadPersistedPublicKeys,
} = require('./src/database');

const CORS_ORIGIN = process.env.CORS_ORIGIN || '*';
const PORT = process.env.PORT || 3000;

const app = express();

app.use(cors({ origin: CORS_ORIGIN }));
app.use(express.json());

app.use((req, res, next) => {
    const startedAt = Date.now();
    logEvent('HTTP', 'Requisição recebida', { method: req.method, path: req.originalUrl, ip: req.ip, headers: req.headers, body: req.body });
    res.on('finish', () => {
        logEvent('HTTP', 'Resposta enviada', { method: req.method, path: req.originalUrl, statusCode: res.statusCode, durationMs: Date.now() - startedAt });
    });
    next();
});

app.use(cors({ origin: CORS_ORIGIN }));
app.use(express.json());

app.get('/health', (req, res) => {
    logEvent('HTTP', 'Verificação de saúde solicitada', { method: req.method, path: req.path, ip: req.ip });
    res.json({ status: 'ok' });
});


app.use((error, req, res, next) => {
    logError('HTTP', 'Erro no middleware HTTP', error, { method: req.method, path: req.originalUrl });
    if (res.headersSent) return next(error);
    res.status(400).json({ success: false, message: 'Requisição inválida.' });
});

const server = http.createServer(app);

const io = new Server(server, {
    cors: {
        origin: CORS_ORIGIN,
        methods: ['GET', 'POST'],
    },
    maxHttpBufferSize: 1e6,
});

setupSocket(io);

async function startServer() {
    logEvent('STARTUP', 'Iniciando backend ECDH-Chat', { port: PORT, corsOrigin: CORS_ORIGIN, nodeVersion: process.version });
    try {
        await testDatabaseConnection();
        await loadPersistedPublicKeys();

        server.listen(PORT, () => {
            logEvent('STARTUP', 'Backend pronto para receber conexões', { port: PORT, healthEndpoint: `/health` });
        });
    } catch (error) {
        logError('STARTUP', 'Não foi possível iniciar o backend', error);

        process.exitCode = 1;
    }
}

startServer();
