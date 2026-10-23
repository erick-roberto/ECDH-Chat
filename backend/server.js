require('dotenv').config();

const express = require('express');
const http = require('http');
const cors = require('cors');
const { Server } = require('socket.io');

const setupSocket = require('./src/socket/index');
const { corsOrigin, isProduction, configuredOrigins } = require('./src/config/cors');
const {
    testDatabaseConnection,
    loadPersistedPublicKeys,
    loadPersistedGroups,
} = require('./src/database');

const PORT = process.env.PORT || 3000;

const app = express();

app.use(cors({ origin: corsOrigin }));

app.get('/health', (req, res) => {
    res.json({ status: 'ok' });
});

const server = http.createServer(app);

const io = new Server(server, {
    cors: {
        origin: corsOrigin,
        methods: ['GET', 'POST'],
    },
    maxHttpBufferSize: 1e6,
});

setupSocket(io);

async function startServer() {
    try {
        await testDatabaseConnection();
        await loadPersistedPublicKeys();
        await loadPersistedGroups();

        server.listen(PORT, () => {
            console.log('Server is running on port:', PORT);
            console.log(
                isProduction
                    ? `CORS restrito a: ${configuredOrigins.join(', ')}`
                    : 'CORS de desenvolvimento: localhost, 127.0.0.1, 0.0.0.0 e IPs privados permitidos.'
            );
            console.log('AVISO: Em produção, configure HTTPS/WSS (Transporte TLS obrigatório).');
        });
    } catch (error) {
        console.error('Não foi possível iniciar o backend.');
        console.error('Erro:', error.message);
        process.exitCode = 1;
    }
}

startServer();