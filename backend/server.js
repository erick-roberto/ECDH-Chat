const express = require('express');
const http = require('http');
const socketIO = require('socket.io');
const socketHandler = require('./src/socket');

const app = express();
app.use(cors());

const server = http.createServer(app);
const io = new Server(server,{
    cors: {
        origin: '*',
        methods: ['GET', 'POST'],
    }
});

socketHandler.setupdSocket(io);

const Port = process.env.PORT || 3000;
server.listen(Port, () => {
    console.log('Server is running on port: ', Port);
});