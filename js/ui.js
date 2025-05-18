/**
 * PSFree Enhanced UI
 * Compatible with PS4 FW 9.00 Browser
 * TODO: Implement controller navigation and optimize for PS4 display
 */

// Status constants
const STATUS = {
    WAITING: 'waiting',
    RUNNING: 'running',
    SUCCESS: 'success',
    ERROR: 'error'
};

// Global state
let state = {
    status: STATUS.RUNNING, // Diubah dari WAITING ke RUNNING karena otomatis berjalan
    progress: 0,
    selectedPayload: 'payload.bin', // Selalu menggunakan payload default
    customPayloads: [],
    settings: {
        autoRun: true, // Diubah menjadi true untuk auto-run
        verboseLogging: false,
        safeMode: true
    },
    controllerNavigation: {
        enabled: false,
        currentFocusIndex: 0,
        focusableElements: []
    }
};

// TODO: Exploit akan otomatis berjalan saat halaman dimuat

// Original console.log function
const originalLog = console.log;

// Override console.log to also update the UI
console.log = function(...args) {
    // Call original console.log
    originalLog.apply(console, args);

    // Update UI console
    const message = args.map(arg => {
        if (typeof arg === 'object') {
            return JSON.stringify(arg);
        }
        return arg;
    }).join(' ');

    appendToConsole(message);
};

// Function to append text to the console
function appendToConsole(text) {
    const consoleElement = document.getElementById('console');
    if (consoleElement) {
        consoleElement.textContent += text + '\n';
        consoleElement.scrollTop = consoleElement.scrollHeight;
    }
}

// Function to clear the console
function clearConsole() {
    const consoleElement = document.getElementById('console');
    if (consoleElement) {
        consoleElement.textContent = '';
    }
}

// Function to update the UI status
function updateStatus(status, message) {
    state.status = status;

    const statusIcon = document.getElementById('status-icon');
    const statusText = document.getElementById('status-text');

    if (!statusIcon || !statusText) return;

    // Remove all status classes
    statusIcon.classList.remove('status-waiting', 'status-running', 'status-success', 'status-error');

    // Add the appropriate class
    statusIcon.classList.add(`status-${status}`);

    // Update the status text
    statusText.textContent = message;

    // TODO: Tombol jalankan exploit dan reset telah dihapus
}

// Function to update the progress bar
function updateProgress(percent) {
    state.progress = percent;
    const progressBar = document.getElementById('progress-bar');
    if (progressBar) {
        progressBar.style.width = `${percent}%`;
    }
}

// Function to handle tab switching
function switchTab(tabId) {
    // Hide all tab contents
    document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.remove('active');
    });

    // Deactivate all tabs
    document.querySelectorAll('.tab').forEach(tab => {
        tab.classList.remove('active');
    });

    // Activate the selected tab and content
    const tabContent = document.getElementById(`tab-${tabId}`);
    const tabElement = document.querySelector(`.tab[data-tab="${tabId}"]`);

    if (tabContent && tabElement) {
        tabContent.classList.add('active');
        tabElement.classList.add('active');
    }
}

// Function to add a custom payload
function addCustomPayload(name, data) {
    const payloadList = document.getElementById('payload-list');
    if (!payloadList) return;

    // Create a new payload item
    const payloadItem = document.createElement('div');
    payloadItem.className = 'payload-item';
    payloadItem.dataset.payload = name;
    payloadItem.setAttribute('tabindex', '0'); // Make focusable for controller navigation

    // Create the payload content
    payloadItem.innerHTML = `
        <input type="radio" name="payload" id="payload-${name}">
        <div class="payload-info">
            <label for="payload-${name}"><strong>${name}</strong></label>
            <p>Custom payload (${formatBytes(data.byteLength)})</p>
        </div>
        <button class="btn btn-danger remove-payload" data-name="${name}">Hapus</button>
    `;

    // Add the payload to the list
    payloadList.appendChild(payloadItem);

    // Store the payload data
    state.customPayloads.push({
        name: name,
        data: data
    });

    // Save to localStorage
    saveCustomPayloads();

    // Update controller navigation
    updateFocusableElements();
}

// Function to format bytes to human-readable format
function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';

    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];

    const i = Math.floor(Math.log(bytes) / Math.log(k));

    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

// Function to save custom payloads to localStorage
function saveCustomPayloads() {
    try {
        // We can only store the names in localStorage, not the actual binary data
        const payloadNames = state.customPayloads.map(p => p.name);
        localStorage.setItem('customPayloadNames', JSON.stringify(payloadNames));
    } catch (e) {
        console.log('Error saving custom payloads to localStorage:', e);
    }
}

// Function to save settings to localStorage
function saveSettings() {
    try {
        localStorage.setItem('settings', JSON.stringify(state.settings));
        console.log('Pengaturan disimpan');
    } catch (e) {
        console.log('Error saving settings to localStorage:', e);
    }
}

// Function to load settings from localStorage
function loadSettings() {
    try {
        const savedSettings = localStorage.getItem('settings');
        if (savedSettings) {
            state.settings = JSON.parse(savedSettings);

            // Update UI to reflect loaded settings
            const autoRunElement = document.getElementById('auto-run');
            const verboseLoggingElement = document.getElementById('verbose-logging');
            const safeModeElement = document.getElementById('safe-mode');

            if (autoRunElement) autoRunElement.checked = state.settings.autoRun;
            if (verboseLoggingElement) verboseLoggingElement.checked = state.settings.verboseLogging;
            if (safeModeElement) safeModeElement.checked = state.settings.safeMode;
        }
    } catch (e) {
        console.log('Error loading settings from localStorage:', e);
    }
}

// Function to detect firmware version
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

// Function to check browser compatibility
function checkCompatibility() {
    const userAgent = navigator.userAgent;
    let isCompatible = true;
    let message = '';

    // Check if running on PS4/PS5 browser
    if (userAgent.includes('PlayStation 4') || userAgent.includes('PlayStation 5')) {
        console.log('Terdeteksi browser PlayStation. Kompatibilitas optimal.');

        // Enable controller navigation if on PlayStation
        state.controllerNavigation.enabled = true;
    } else {
        console.log('PERINGATAN: Tidak berjalan di browser PlayStation. Beberapa fitur mungkin tidak berfungsi.');
        isCompatible = false;
        message = 'Tidak berjalan di browser PlayStation';
    }

    // Check specific firmware version
    const firmware = detectFirmware();
    if (firmware) {
        console.log(`Terdeteksi ${firmware.console} FW ${firmware.version}`);

        if (firmware.console === 'PS4' && firmware.version === '9.00') {
            console.log('Terdeteksi PS4 FW 9.00. Kompatibilitas optimal.');
        }
    }

    return { isCompatible, message, firmware };
}

// Function to run the exploit
function runExploit() {
    updateStatus(STATUS.RUNNING, 'Menjalankan exploit...');
    updateProgress(5);

    // Clear the console if not in verbose mode
    if (!state.settings.verboseLogging) {
        clearConsole();
    }

    console.log('Memulai PSFree exploit...');

    // The actual exploit will be triggered here via the import of lapse.mjs
    // This is handled by the original code in index.html

    // Listen for exploit progress events
    document.addEventListener('exploitProgress', function(event) {
        updateProgress(event.detail.percent);
    });

    // Listen for exploit status events
    document.addEventListener('exploitStatus', function(event) {
        updateStatus(event.detail.status, event.detail.message);
    });
}

// Function to reset the exploit
function resetExploit() {
    updateStatus(STATUS.WAITING, 'Siap untuk memulai');
    updateProgress(0);

    if (!state.settings.verboseLogging) {
        clearConsole();
    }

    console.log('Exploit direset. Siap untuk memulai kembali.');

    // Reload the page to reset everything
    if (confirm('Halaman akan dimuat ulang untuk mereset exploit. Lanjutkan?')) {
        window.location.reload();
    }
}

// Function to update focusable elements for controller navigation
function updateFocusableElements() {
    if (!state.controllerNavigation.enabled) return;

    // Get all focusable elements
    state.controllerNavigation.focusableElements = Array.from(document.querySelectorAll('button, .tab, .payload-item, input[type="checkbox"]'));

    // Reset focus index
    state.controllerNavigation.currentFocusIndex = 0;
}

// Function to handle controller navigation
function handleControllerNavigation(event) {
    if (!state.controllerNavigation.enabled) return;

    const elements = state.controllerNavigation.focusableElements;
    let currentIndex = state.controllerNavigation.currentFocusIndex;

    // Handle navigation with D-pad
    switch (event.key) {
        case 'ArrowUp':
            currentIndex = Math.max(0, currentIndex - 1);
            break;
        case 'ArrowDown':
            currentIndex = Math.min(elements.length - 1, currentIndex + 1);
            break;
        case 'ArrowLeft':
            // If in tabs, navigate between tabs
            if (elements[currentIndex].classList.contains('tab')) {
                const tabs = Array.from(document.querySelectorAll('.tab'));
                const tabIndex = tabs.indexOf(elements[currentIndex]);
                if (tabIndex > 0) {
                    currentIndex = elements.indexOf(tabs[tabIndex - 1]);
                }
            } else {
                currentIndex = Math.max(0, currentIndex - 1);
            }
            break;
        case 'ArrowRight':
            // If in tabs, navigate between tabs
            if (elements[currentIndex].classList.contains('tab')) {
                const tabs = Array.from(document.querySelectorAll('.tab'));
                const tabIndex = tabs.indexOf(elements[currentIndex]);
                if (tabIndex < tabs.length - 1) {
                    currentIndex = elements.indexOf(tabs[tabIndex + 1]);
                }
            } else {
                currentIndex = Math.min(elements.length - 1, currentIndex + 1);
            }
            break;
        case 'Enter':
            // Simulate click on the focused element
            elements[currentIndex].click();
            return;
    }

    // Update focus
    if (currentIndex !== state.controllerNavigation.currentFocusIndex) {
        // Remove focus from all elements
        elements.forEach(el => {
            el.classList.remove('controller-focus');
        });

        // Add focus to the current element
        elements[currentIndex].classList.add('controller-focus');
        elements[currentIndex].focus();

        // Update current index
        state.controllerNavigation.currentFocusIndex = currentIndex;
    }
}

// Setup event listeners
function setupEventListeners() {
    // Tab switching - hanya untuk tab console
    document.querySelectorAll('.tab').forEach(tab => {
        tab.addEventListener('click', () => {
            switchTab(tab.dataset.tab);
        });
    });

    // TODO: Tombol jalankan exploit, reset, upload payload, dan pengaturan telah dihapus

    // Controller navigation
    document.addEventListener('keydown', handleControllerNavigation);

    // Custom events from exploit
    document.addEventListener('exploitProgress', function(event) {
        updateProgress(event.detail.percent);
    });

    document.addEventListener('exploitStatus', function(event) {
        updateStatus(event.detail.status, event.detail.message);
    });

    // Payload events
    document.addEventListener('payloadLoaded', function(event) {
        console.log(`Payload dimuat: ${event.detail.name} (${formatBytes(event.detail.size)})`);
    });

    document.addEventListener('payloadError', function(event) {
        console.log(`Error memuat payload ${event.detail.name}: ${event.detail.error}`);
        updateStatus(STATUS.ERROR, `Error memuat payload: ${event.detail.error}`);
    });
}

// Initialize the UI
function initUI() {
    console.log('Initializing PSFree UI...');

    // Load settings
    loadSettings();

    // Setup event listeners
    setupEventListeners();

    // Check compatibility
    checkCompatibility();

    // Update focusable elements for controller navigation
    updateFocusableElements();

    // Selalu jalankan exploit secara otomatis
    setTimeout(() => {
        console.log('Menjalankan exploit secara otomatis...');
        runExploit();
    }, 1000);

    console.log('UI initialized. Exploit akan berjalan otomatis.');

    // TODO: Exploit akan selalu berjalan otomatis tanpa kondisi
}

// Initialize when the DOM is fully loaded
document.addEventListener('DOMContentLoaded', initUI);
