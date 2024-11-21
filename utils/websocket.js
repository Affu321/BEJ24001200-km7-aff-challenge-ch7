const { Server } = require('socket.io');

const initWebSocket = (server) => {
    const io = new Server(server, {
        cors: {
            origin: '*', // Ganti sesuai domain frontend Anda
            methods: ['GET', 'POST'],
        },
    });

    io.on('connection', (socket) => {
        console.log('User connected:', socket.id);

        // Listen to notification event
        socket.on('notify', (data) => {
            io.emit('notification', data);
        });

        socket.on('disconnect', () => {
            console.log('User disconnected:', socket.id);
        });
    });

    return io;
};

module.exports = initWebSocket;
