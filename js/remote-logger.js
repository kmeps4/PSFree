/**
 * PSFree Remote Logger
 *
 * Sistem logging jarak jauh untuk PSFree yang mengirim log ke server lokal
 * untuk memantau progress exploit secara real-time.
 *
 * TODO: Tambahkan fitur reconnect otomatis jika koneksi terputus
 */

// Konfigurasi logger
const RemoteLogger = {
    // Konfigurasi server
    config: {
        // URL server logging (ganti dengan IP komputer Anda)
        serverUrl: 'http://192.168.1.100:3000',
        // Apakah logging diaktifkan
        enabled: true,
        // Apakah log juga dicetak ke konsol lokal
        localConsole: true,
        // Level log minimum yang dikirim (0=DEBUG, 1=INFO, 2=WARN, 3=ERROR)
        minLevel: 0,
        // ID unik untuk sesi logging ini
        sessionId: generateSessionId(),
        // Informasi perangkat
        deviceInfo: {
            userAgent: navigator.userAgent,
            firmware: detectFirmware(),
            timestamp: new Date().toISOString()
        },
        // Buffer untuk menyimpan log jika koneksi terputus
        logBuffer: [],
        // Ukuran maksimum buffer
        maxBufferSize: 100,
        // Status koneksi
        connected: false
    },

    // Level log
    LEVEL: {
        DEBUG: 0,
        INFO: 1,
        WARN: 2,
        ERROR: 3
    },

    // Inisialisasi logger
    init: function(customConfig = {}) {
        // Gabungkan konfigurasi default dengan konfigurasi kustom
        this.config = { ...this.config, ...customConfig };

        // Coba deteksi IP server secara otomatis jika tidak diatur
        if (this.config.serverUrl === 'http://192.168.1.100:3000') {
            this.autoDetectServerIp();
        }

        // Kirim informasi sesi ke server
        this.sendSessionInfo();

        // Override fungsi console.log asli
        this.overrideConsoleLog();

        // Log inisialisasi
        this.info('Remote Logger initialized', {
            config: {
                serverUrl: this.config.serverUrl,
                sessionId: this.config.sessionId,
                deviceInfo: this.config.deviceInfo
            }
        });

        return this;
    },

    // Coba deteksi IP server secara otomatis
    autoDetectServerIp: function() {
        // Daftar IP yang umum digunakan dalam jaringan lokal
        const commonIps = [
            'http://192.168.1.100:3000',
            'http://192.168.1.101:3000',
            'http://192.168.1.102:3000',
            'http://192.168.1.103:3000',
            'http://192.168.1.104:3000',
            'http://192.168.1.105:3000',
            'http://192.168.0.100:3000',
            'http://192.168.0.101:3000',
            'http://192.168.0.102:3000',
            'http://192.168.0.103:3000',
            'http://192.168.0.104:3000',
            'http://192.168.0.105:3000',
            'http://10.0.0.100:3000',
            'http://10.0.0.101:3000',
            'http://10.0.0.102:3000'
        ];

        // Coba ping setiap IP untuk menemukan server yang aktif
        for (const ip of commonIps) {
            fetch(`${ip}/ping`, {
                method: 'GET',
                mode: 'no-cors',
                cache: 'no-cache',
                headers: {
                    'Content-Type': 'application/json'
                },
                timeout: 500
            })
            .then(() => {
                // Jika berhasil, gunakan IP ini
                this.config.serverUrl = ip;
                this.info(`Server ditemukan di ${ip}`);
            })
            .catch(() => {
                // Jika gagal, coba IP berikutnya
            });
        }
    },

    // Kirim informasi sesi ke server
    sendSessionInfo: function() {
        if (!this.config.enabled) return;

        // Buat URL dengan parameter query untuk menghindari masalah CORS dengan body
        const sessionData = {
            sessionId: this.config.sessionId,
            deviceInfo: JSON.stringify(this.config.deviceInfo),
            timestamp: new Date().toISOString()
        };

        // Buat query string dari data
        const queryString = Object.keys(sessionData)
            .map(key => `${encodeURIComponent(key)}=${encodeURIComponent(sessionData[key])}`)
            .join('&');

        // Kirim request dengan metode GET dan parameter query
        fetch(`${this.config.serverUrl}/session?${queryString}`, {
            method: 'GET',
            mode: 'no-cors',
            cache: 'no-cache'
        })
        .then(() => {
            this.config.connected = true;

            // Log sukses
            if (this.config.localConsole) {
                console.log(`Connected to logging server at ${this.config.serverUrl}`);
                console.log(`Session ID: ${this.config.sessionId}`);
            }

            // Kirim log yang ada di buffer
            this.flushBuffer();
        })
        .catch(error => {
            this.config.connected = false;
            if (this.config.localConsole) {
                console.error('Failed to connect to logging server:', error);
            }
        });
    },

    // Override fungsi console.log asli
    overrideConsoleLog: function() {
        const originalLog = console.log;
        const originalWarn = console.warn;
        const originalError = console.error;
        const self = this;

        console.log = function(...args) {
            // Panggil fungsi asli
            if (self.config.localConsole) {
                originalLog.apply(console, args);
            }

            // Kirim log ke server
            self.debug(args.map(arg => {
                if (typeof arg === 'object') {
                    return JSON.stringify(arg);
                }
                return arg;
            }).join(' '));
        };

        console.warn = function(...args) {
            // Panggil fungsi asli
            if (self.config.localConsole) {
                originalWarn.apply(console, args);
            }

            // Kirim log ke server
            self.warn(args.map(arg => {
                if (typeof arg === 'object') {
                    return JSON.stringify(arg);
                }
                return arg;
            }).join(' '));
        };

        console.error = function(...args) {
            // Panggil fungsi asli
            if (self.config.localConsole) {
                originalError.apply(console, args);
            }

            // Kirim log ke server
            self.error(args.map(arg => {
                if (typeof arg === 'object') {
                    return JSON.stringify(arg);
                }
                return arg;
            }).join(' '));
        };
    },

    // Kirim log ke server
    sendLog: function(level, message, data = {}) {
        if (!this.config.enabled || level < this.config.minLevel) return;

        const logEntry = {
            sessionId: this.config.sessionId,
            timestamp: new Date().toISOString(),
            level: level,
            levelName: Object.keys(this.LEVEL).find(key => this.LEVEL[key] === level),
            message: message,
            data: JSON.stringify(data)
        };

        // Jika tidak terhubung, simpan di buffer
        if (!this.config.connected) {
            this.bufferLog(logEntry);
            return;
        }

        // Buat query string dari data log
        const queryString = Object.keys(logEntry)
            .map(key => `${encodeURIComponent(key)}=${encodeURIComponent(logEntry[key])}`)
            .join('&');

        // Kirim log ke server dengan metode GET dan parameter query
        fetch(`${this.config.serverUrl}/log?${queryString}`, {
            method: 'GET',
            mode: 'no-cors',
            cache: 'no-cache'
        })
        .catch(error => {
            this.config.connected = false;
            this.bufferLog(logEntry);
            if (this.config.localConsole) {
                console.error('Failed to send log to server:', error);
            }
        });
    },

    // Simpan log di buffer jika koneksi terputus
    bufferLog: function(logEntry) {
        this.config.logBuffer.push(logEntry);

        // Jika buffer terlalu besar, hapus log lama
        if (this.config.logBuffer.length > this.config.maxBufferSize) {
            this.config.logBuffer.shift();
        }
    },

    // Kirim semua log yang ada di buffer
    flushBuffer: function() {
        if (!this.config.connected || this.config.logBuffer.length === 0) return;

        // Kirim log satu per satu
        for (const log of this.config.logBuffer) {
            this.sendLog(log.level, log.message, log.data ? JSON.parse(log.data) : {});
        }

        // Kosongkan buffer
        this.config.logBuffer = [];
    },

    // Fungsi logging
    debug: function(message, data = {}) {
        this.sendLog(this.LEVEL.DEBUG, message, data);
    },

    info: function(message, data = {}) {
        this.sendLog(this.LEVEL.INFO, message, data);
    },

    warn: function(message, data = {}) {
        this.sendLog(this.LEVEL.WARN, message, data);
    },

    error: function(message, data = {}) {
        this.sendLog(this.LEVEL.ERROR, message, data);
    },

    // Log stage exploit
    logStage: function(stage, percent, details = {}) {
        this.info(`STAGE: ${stage}`, {
            stage: stage,
            percent: percent,
            details: details
        });

        // Kirim event untuk UI
        document.dispatchEvent(new CustomEvent('exploitProgress', {
            detail: {
                stage: stage,
                percent: percent
            }
        }));
    }
};

// Fungsi untuk menghasilkan ID sesi unik
function generateSessionId() {
    return 'xxxx-xxxx-xxxx-xxxx'.replace(/[x]/g, () => {
        const r = Math.random() * 16 | 0;
        return r.toString(16);
    });
}

// Fungsi untuk mendeteksi firmware
function detectFirmware() {
    const userAgent = navigator.userAgent;
    let firmware = null;

    // Detect PS4 firmware
    const ps4Match = userAgent.match(/PlayStation 4\/([0-9.]+)/);
    if (ps4Match && ps4Match[1]) {
        firmware = {
            console: 'PS4',
            version: ps4Match[1]
        };
    }

    // Detect PS5 firmware
    const ps5Match = userAgent.match(/PlayStation 5\/([0-9.]+)/);
    if (ps5Match && ps5Match[1]) {
        firmware = {
            console: 'PS5',
            version: ps5Match[1]
        };
    }

    return firmware;
}

// Ekspor RemoteLogger ke window
window.RemoteLogger = RemoteLogger;
