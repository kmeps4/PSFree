/**
 * PSFree Logger Server
 *
 * Server sederhana untuk menerima dan menampilkan log dari PSFree
 * yang berjalan di PS4/PS5.
 */

const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const bodyParser = require('body-parser');
const chalk = require('chalk');
const moment = require('moment');
const fs = require('fs');
const path = require('path');
const os = require('os');

// Konfigurasi server
const PORT = process.env.PORT || 3000;
const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
    cors: {
        origin: '*',
        methods: ['GET', 'POST']
    }
});

// Middleware
app.use(cors());
app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '50mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Simpan sesi aktif
const activeSessions = new Map();
// Simpan log untuk setiap sesi
const sessionLogs = new Map();

// Dapatkan alamat IP lokal
function getLocalIpAddress() {
    const interfaces = os.networkInterfaces();
    const addresses = [];

    for (const interfaceName in interfaces) {
        const interfaceInfo = interfaces[interfaceName];
        for (const info of interfaceInfo) {
            // Hanya ambil IPv4 dan bukan loopback
            if (info.family === 'IPv4' && !info.internal) {
                addresses.push(info.address);
            }
        }
    }

    return addresses;
}

// Buat folder logs jika belum ada
const logsDir = path.join(__dirname, 'logs');
if (!fs.existsSync(logsDir)) {
    fs.mkdirSync(logsDir);
}

// Fungsi untuk menyimpan log ke file
function saveLogToFile(sessionId, log) {
    const sessionDir = path.join(logsDir, sessionId);
    if (!fs.existsSync(sessionDir)) {
        fs.mkdirSync(sessionDir, { recursive: true });
    }

    const logFile = path.join(sessionDir, 'session.log');
    const logEntry = `[${moment().format('YYYY-MM-DD HH:mm:ss.SSS')}] [${log.levelName}] ${log.message}\n`;

    fs.appendFileSync(logFile, logEntry);

    // Periksa apakah log berisi informasi status eksploitasi
    if (log.message && (
        log.message.includes('kernel exploit succeeded') ||
        log.message.includes('Exploit berhasil') ||
        log.message.includes('Payload berhasil dimuat')
    )) {
        // Tandai folder sebagai berhasil
        updateSessionFolderStatus(sessionId, 'SUCCESS');
    } else if (log.message && (
        log.message.includes('kernel exploit failed') ||
        log.message.includes('Exploit gagal') ||
        log.message.includes('test read of &"evf cv" failed') ||
        log.message.includes('Kernel Panic detected')
    )) {
        // Tandai folder sebagai gagal
        updateSessionFolderStatus(sessionId, 'FAILED');
    }
}

// Fungsi untuk memperbarui nama folder log dengan status eksploitasi
function updateSessionFolderStatus(sessionId, status) {
    const sessionDir = path.join(logsDir, sessionId);
    if (!fs.existsSync(sessionDir)) {
        return; // Folder tidak ditemukan
    }

    // Periksa apakah folder sudah ditandai
    if (sessionId.includes('_SUCCESS_') || sessionId.includes('_FAILED_')) {
        return; // Folder sudah ditandai
    }

    // Buat nama folder baru dengan status
    const newSessionId = `${sessionId}_${status}`;
    const newSessionDir = path.join(logsDir, newSessionId);

    // Jika folder baru sudah ada, hapus dulu
    if (fs.existsSync(newSessionDir)) {
        try {
            fs.rmdirSync(newSessionDir, { recursive: true });
        } catch (error) {
            console.error(`Error removing existing directory: ${error.message}`);
            return;
        }
    }

    // Rename folder
    try {
        fs.renameSync(sessionDir, newSessionDir);
        console.log(chalk.green(`[+] Folder log ${sessionId} ditandai sebagai ${status}`));

        // Update referensi di activeSessions dan sessionLogs
        if (activeSessions.has(sessionId)) {
            const session = activeSessions.get(sessionId);
            activeSessions.delete(sessionId);
            session.id = newSessionId;
            activeSessions.set(newSessionId, session);
        }

        if (sessionLogs.has(sessionId)) {
            const logs = sessionLogs.get(sessionId);
            sessionLogs.delete(sessionId);
            sessionLogs.set(newSessionId, logs);
        }
    } catch (error) {
        console.error(`Error renaming directory: ${error.message}`);
    }
}

// Fungsi untuk mencetak log ke konsol
function printLog(log) {
    const timestamp = chalk.gray(`[${moment(log.timestamp).format('HH:mm:ss.SSS')}]`);
    let levelColor;

    switch (log.level) {
        case 0: // DEBUG
            levelColor = chalk.blue('[DEBUG]');
            break;
        case 1: // INFO
            levelColor = chalk.green('[INFO]');
            break;
        case 2: // WARN
            levelColor = chalk.yellow('[WARN]');
            break;
        case 3: // ERROR
            levelColor = chalk.red('[ERROR]');
            break;
        default:
            levelColor = chalk.white(`[${log.levelName}]`);
    }

    const sessionId = chalk.cyan(`[${log.sessionId.substring(0, 8)}]`);
    const message = log.message;

    console.log(`${timestamp} ${levelColor} ${sessionId} ${message}`);

    // Jika ada data tambahan, cetak sebagai JSON
    if (log.data && Object.keys(log.data).length > 0) {
        console.log(chalk.gray(JSON.stringify(log.data, null, 2)));
    }
}

// Routes
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Endpoint untuk ping
app.get('/ping', (req, res) => {
    res.status(200).send('pong');
});

// Endpoint untuk mendaftarkan sesi baru (mendukung GET dan POST)
app.all('/session', (req, res) => {
    // Ambil data dari query atau body
    const sessionId = req.query.sessionId || (req.body ? req.body.sessionId : null);
    let deviceInfo = req.query.deviceInfo || (req.body ? req.body.deviceInfo : null);
    const timestamp = req.query.timestamp || (req.body ? req.body.timestamp : new Date().toISOString());

    // Jika deviceInfo adalah string JSON, parse
    if (typeof deviceInfo === 'string') {
        try {
            deviceInfo = JSON.parse(deviceInfo);
        } catch (e) {
            console.error('Error parsing deviceInfo:', e);
            deviceInfo = { error: 'Failed to parse deviceInfo' };
        }
    }

    // Validasi sessionId
    if (!sessionId) {
        console.log(chalk.yellow('[!] Sesi baru tanpa ID'));
        return res.status(400).send('Session ID is required');
    }

    // Simpan informasi sesi
    activeSessions.set(sessionId, {
        id: sessionId,
        deviceInfo,
        timestamp,
        lastActivity: new Date()
    });

    // Inisialisasi array log untuk sesi ini
    if (!sessionLogs.has(sessionId)) {
        sessionLogs.set(sessionId, []);
    }

    // Cetak informasi sesi
    console.log(chalk.green(`[+] Sesi baru terdaftar: ${sessionId}`));
    console.log(chalk.gray(JSON.stringify(deviceInfo, null, 2)));

    // Broadcast ke semua client
    io.emit('newSession', {
        id: sessionId,
        deviceInfo,
        timestamp
    });

    res.status(200).send('OK');
});

// Endpoint untuk menerima log (mendukung GET dan POST)
app.all('/log', (req, res) => {
    // Ambil data dari query atau body
    const log = req.method === 'GET' ? req.query : req.body;

    // Validasi log
    if (!log.sessionId || !log.message) {
        return res.status(400).send('Invalid log format');
    }

    // Parse data jika dalam bentuk string
    if (log.data && typeof log.data === 'string') {
        try {
            log.data = JSON.parse(log.data);
        } catch (e) {
            console.error('Error parsing log data:', e);
            log.data = { error: 'Failed to parse data' };
        }
    }

    // Update waktu aktivitas terakhir
    if (activeSessions.has(log.sessionId)) {
        const session = activeSessions.get(log.sessionId);
        session.lastActivity = new Date();
        activeSessions.set(log.sessionId, session);
    } else {
        // Jika sesi tidak ditemukan, buat sesi baru
        activeSessions.set(log.sessionId, {
            id: log.sessionId,
            deviceInfo: { note: 'Session created from log' },
            timestamp: new Date().toISOString(),
            lastActivity: new Date()
        });

        // Inisialisasi array log untuk sesi ini
        if (!sessionLogs.has(log.sessionId)) {
            sessionLogs.set(log.sessionId, []);
        }

        // Cetak informasi sesi baru
        console.log(chalk.green(`[+] Sesi baru dibuat dari log: ${log.sessionId}`));

        // Broadcast ke semua client
        io.emit('newSession', {
            id: log.sessionId,
            deviceInfo: { note: 'Session created from log' },
            timestamp: new Date().toISOString()
        });
    }

    // Simpan log
    if (sessionLogs.has(log.sessionId)) {
        sessionLogs.get(log.sessionId).push(log);
    } else {
        sessionLogs.set(log.sessionId, [log]);
    }

    // Cetak log ke konsol
    printLog(log);

    // Simpan log ke file
    saveLogToFile(log.sessionId, log);

    // Broadcast ke semua client
    io.emit('newLog', log);

    res.status(200).send('OK');
});

// Endpoint untuk menerima batch log (mendukung GET dan POST)
app.all('/logs', (req, res) => {
    // Ambil data dari query atau body
    let logs;

    if (req.method === 'GET') {
        // Jika GET, coba parse parameter logs
        try {
            logs = JSON.parse(req.query.logs);
        } catch (e) {
            return res.status(400).send('Invalid logs format');
        }
    } else {
        // Jika POST, ambil dari body
        logs = req.body.logs;
    }

    if (!Array.isArray(logs)) {
        return res.status(400).send('Invalid logs format');
    }

    for (const log of logs) {
        // Validasi log
        if (!log.sessionId || !log.message) {
            continue;
        }

        // Parse data jika dalam bentuk string
        if (log.data && typeof log.data === 'string') {
            try {
                log.data = JSON.parse(log.data);
            } catch (e) {
                console.error('Error parsing log data:', e);
                log.data = { error: 'Failed to parse data' };
            }
        }

        // Update waktu aktivitas terakhir
        if (activeSessions.has(log.sessionId)) {
            const session = activeSessions.get(log.sessionId);
            session.lastActivity = new Date();
            activeSessions.set(log.sessionId, session);
        } else {
            // Jika sesi tidak ditemukan, buat sesi baru
            activeSessions.set(log.sessionId, {
                id: log.sessionId,
                deviceInfo: { note: 'Session created from batch log' },
                timestamp: new Date().toISOString(),
                lastActivity: new Date()
            });

            // Inisialisasi array log untuk sesi ini
            if (!sessionLogs.has(log.sessionId)) {
                sessionLogs.set(log.sessionId, []);
            }

            // Cetak informasi sesi baru
            console.log(chalk.green(`[+] Sesi baru dibuat dari batch log: ${log.sessionId}`));

            // Broadcast ke semua client
            io.emit('newSession', {
                id: log.sessionId,
                deviceInfo: { note: 'Session created from batch log' },
                timestamp: new Date().toISOString()
            });
        }

        // Simpan log
        if (sessionLogs.has(log.sessionId)) {
            sessionLogs.get(log.sessionId).push(log);
        } else {
            sessionLogs.set(log.sessionId, [log]);
        }

        // Cetak log ke konsol
        printLog(log);

        // Simpan log ke file
        saveLogToFile(log.sessionId, log);

        // Broadcast ke semua client
        io.emit('newLog', log);
    }

    res.status(200).send('OK');
});

// Endpoint untuk mendapatkan semua sesi aktif
app.get('/sessions', (req, res) => {
    const sessions = Array.from(activeSessions.values());
    res.json(sessions);
});

// Endpoint untuk mendapatkan log dari sesi tertentu
app.get('/sessions/:sessionId/logs', (req, res) => {
    const { sessionId } = req.params;

    if (!sessionLogs.has(sessionId)) {
        return res.status(404).send('Session not found');
    }

    res.json(sessionLogs.get(sessionId));
});

// Endpoint untuk menandai folder log secara manual
app.post('/api/sessions/:sessionId/mark', (req, res) => {
    const { sessionId } = req.params;
    const { status } = req.body;

    if (!status || (status !== 'SUCCESS' && status !== 'FAILED')) {
        return res.status(400).send('Invalid status. Must be SUCCESS or FAILED');
    }

    // Cari sessionId yang cocok (bisa sebagian)
    const sessions = Array.from(activeSessions.keys());
    const matchingSession = sessions.find(id => id.includes(sessionId));

    if (!matchingSession) {
        return res.status(404).send('Session not found');
    }

    // Update status folder
    updateSessionFolderStatus(matchingSession, status);

    res.status(200).json({
        success: true,
        message: `Session ${matchingSession} marked as ${status}`,
        newSessionId: `${matchingSession}_${status}`
    });
});

// Socket.IO
io.on('connection', (socket) => {
    console.log(chalk.green(`[+] Client terhubung: ${socket.id}`));

    // Kirim semua sesi aktif ke client baru
    socket.emit('sessions', Array.from(activeSessions.values()));

    socket.on('disconnect', () => {
        console.log(chalk.yellow(`[-] Client terputus: ${socket.id}`));
    });
});

// Mulai server
server.listen(PORT, () => {
    console.log(chalk.green(`[+] Server berjalan di port ${PORT}`));
    console.log(chalk.green(`[+] Alamat IP lokal:`));

    const ipAddresses = getLocalIpAddress();
    for (const ip of ipAddresses) {
        console.log(chalk.cyan(`    http://${ip}:${PORT}`));
    }

    console.log(chalk.yellow(`[!] Untuk menggunakan logger, tambahkan parameter ?server=<IP> ke URL PSFree`));
    console.log(chalk.yellow(`[!] Contoh: http://ps4.local/index.html?server=${ipAddresses[0]}`));
});
