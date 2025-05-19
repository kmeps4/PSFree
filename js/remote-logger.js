/**
 * PSFree Remote Logger
 *
 * Remote logging system for PSFree that sends logs to a local server
 * to monitor exploit progress in real-time.
 *
 * TODO: Add automatic reconnect feature if the connection is lost
 */

// Logger configuration
const RemoteLogger = {
    // Server configuration
    config: {
        // Logging server URL (replace with your computer's IP)
        serverUrl: 'http://192.168.1.100:3000',
        // Whether logging is enabled
        enabled: true,
        // Whether to also print logs to the local console
        localConsole: true,
        // Minimum log level to be sent (0=DEBUG, 1=INFO, 2=WARN, 3=ERROR)
        minLevel: 0,
        // Unique ID for this logging session
        sessionId: generateSessionId(),
        // Device information
        deviceInfo: {
            userAgent: navigator.userAgent,
            firmware: detectFirmware(),
            timestamp: new Date().toISOString()
        },
        // Buffer to store logs if connection is lost
        logBuffer: [],
        // Maximum buffer size
        maxBufferSize: 100,
        // Connection status
        connected: false
    },

    // Log levels
    LEVEL: {
        DEBUG: 0,
        INFO: 1,
        WARN: 2,
        ERROR: 3
    },

    // Initialize the logger
    init: function(customConfig = {}) {
        // Merge default config with custom config
        this.config = { ...this.config, ...customConfig };

        // Try to auto-detect server IP if not configured
        if (this.config.serverUrl === 'http://192.168.1.100:3000') {
            this.autoDetectServerIp();
        }

        // Send session info to the server
        this.sendSessionInfo();

        // Override the original console.log function
        this.overrideConsoleLog();

        // Initialization log
        this.info('Remote Logger initialized', {
            config: {
                serverUrl: this.config.serverUrl,
                sessionId: this.config.sessionId,
                deviceInfo: this.config.deviceInfo
            }
        });

        return this;
    },

    // Try to auto-detect server IP
    autoDetectServerIp: function() {
        // List of commonly used IPs in local networks
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

        // Try pinging each IP to find an active server
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
                // If successful, use this IP
                this.config.serverUrl = ip;
                this.info(`Server found at ${ip}`);
            })
            .catch(() => {
                // If failed, try the next IP
            });
        }
    },

    // Send session info to the server
    sendSessionInfo: function() {
        if (!this.config.enabled) return;

        // Create URL with query parameters to avoid CORS issues with body
        const sessionData = {
            sessionId: this.config.sessionId,
            deviceInfo: JSON.stringify(this.config.deviceInfo),
            timestamp: new Date().toISOString()
        };

        // Create query string from data
        const queryString = Object.keys(sessionData)
            .map(key => `${encodeURIComponent(key)}=${encodeURIComponent(sessionData[key])}`)
            .join('&');

        // Send request using GET method and query parameters
        fetch(`${this.config.serverUrl}/session?${queryString}`, {
            method: 'GET',
            mode: 'no-cors',
            cache: 'no-cache'
        })
        .then(() => {
            this.config.connected = true;

            // Success log
            if (this.config.localConsole) {
                console.log(`Connected to logging server at ${this.config.serverUrl}`);
                console.log(`Session ID: ${this.config.sessionId}`);
            }

            // Send logs stored in buffer
            this.flushBuffer();
        })
        .catch(error => {
            this.config.connected = false;
            if (this.config.localConsole) {
                console.error('Failed to connect to logging server:', error);
            }
        });
    },

    // Override the original console.log functions
    overrideConsoleLog: function() {
        const originalLog = console.log;
        const originalWarn = console.warn;
        const originalError = console.error;
        const self = this;

        console.log = function(...args) {
            if (self.config.localConsole) {
                originalLog.apply(console, args);
            }

            self.debug(args.map(arg => {
                if (typeof arg === 'object') {
                    return JSON.stringify(arg);
                }
                return arg;
            }).join(' '));
        };

        console.warn = function(...args) {
            if (self.config.localConsole) {
                originalWarn.apply(console, args);
            }

            self.warn(args.map(arg => {
                if (typeof arg === 'object') {
                    return JSON.stringify(arg);
                }
                return arg;
            }).join(' '));
        };

        console.error = function(...args) {
            if (self.config.localConsole) {
                originalError.apply(console, args);
            }

            self.error(args.map(arg => {
                if (typeof arg === 'object') {
                    return JSON.stringify(arg);
                }
                return arg;
            }).join(' '));
        };
    },

    // Send log to server
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

        // If not connected, save to buffer
        if (!this.config.connected) {
            this.bufferLog(logEntry);
            return;
        }

        // Create query string from log data
        const queryString = Object.keys(logEntry)
            .map(key => `${encodeURIComponent(key)}=${encodeURIComponent(logEntry[key])}`)
            .join('&');

        // Send log to server using GET method
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

    // Save log in buffer if connection is lost
    bufferLog: function(logEntry) {
        this.config.logBuffer.push(logEntry);

        // If buffer is too large, remove oldest logs
        if (this.config.logBuffer.length > this.config.maxBufferSize) {
            this.config.logBuffer.shift();
        }
    },

    // Send all buffered logs
    flushBuffer: function() {
        if (!this.config.connected || this.config.logBuffer.length === 0) return;

        for (const log of this.config.logBuffer) {
            this.sendLog(log.level, log.message, log.data ? JSON.parse(log.data) : {});
        }

        this.config.logBuffer = [];
    },

    // Logging functions
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

    // Log exploit stage
    logStage: function(stage, percent, details = {}) {
        this.info(`STAGE: ${stage}`, {
            stage: stage,
            percent: percent,
            details: details
        });

        // Dispatch event for UI
        document.dispatchEvent(new CustomEvent('exploitProgress', {
            detail: {
                stage: stage,
                percent: percent
            }
        }));
    }
};

// Function to generate unique session ID
function generateSessionId() {
    return 'xxxx-xxxx-xxxx-xxxx'.replace(/[x]/g, () => {
        const r = Math.random() * 16 | 0;
        return r.toString(16);
    });
}

// Function to detect firmware
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

// Export RemoteLogger to window
window.RemoteLogger = RemoteLogger;
