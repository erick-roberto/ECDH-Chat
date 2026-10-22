
require('dotenv').config();

const express = require('express');
const http = require('http');
const cors = require('cors');
const { Server } = require('socket.io');

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

app.get('/health', (req, res) => {
    res.json({ status: 'ok' });
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
    try {
        await testDatabaseConnection();
        await loadPersistedPublicKeys();

        server.listen(PORT, () => {
            console.log('Server is running on port:', PORT);
        });
    } catch (error) {
        console.error('Não foi possível iniciar o backend.');
        console.error('Nome do erro:', error.name);
        console.error('Código:', error.code);
        console.error('Mensagem:', error.message);

        process.exitCode = 1;
    }
}

startServer();
