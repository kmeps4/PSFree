/**
 * PSFree Payload Selector
 * Sistem untuk memilih file payload bin dari folder bin
 *
 * TODO: Tambahkan fitur untuk mengunggah payload kustom
 * TODO: Tambahkan validasi payload yang lebih baik
 * TODO: Tambahkan deskripsi untuk setiap payload
 */

// State global untuk payload selector
const PayloadSelector = {
    // Daftar semua payload yang tersedia
    availablePayloads: [],

    // Payload yang dipilih saat ini
    selectedPayload: null,

    // Elemen dropdown
    dropdownElement: null,

    // Inisialisasi payload selector
    init: function() {
        console.log('Initializing Payload Selector...');

        // Dapatkan elemen dropdown
        this.dropdownElement = document.getElementById('payload-dropdown');

        // Jika elemen dropdown tidak ditemukan, buat elemen baru
        if (!this.dropdownElement) {
            this.createDropdownUI();
        }

        // Tambahkan event listener untuk perubahan dropdown
        this.dropdownElement.addEventListener('change', this.handlePayloadSelection.bind(this));

        // Muat daftar payload
        this.loadPayloadList();
    },

    // Buat UI dropdown
    createDropdownUI: function() {
        console.log('Creating Payload Selector UI...');

        // Buat container untuk dropdown
        const container = document.createElement('div');
        container.className = 'payload-selector-container';
        container.style.margin = '20px 0';
        container.style.display = 'flex';
        container.style.alignItems = 'center';
        container.style.flexWrap = 'wrap';
        container.style.backgroundColor = '#161b22';
        container.style.padding = '15px';
        container.style.borderRadius = '8px';
        container.style.border = '1px solid #30363d';
        container.style.boxShadow = '0 4px 6px rgba(0,0,0,0.1)';

        // Buat header
        const header = document.createElement('h3');
        header.textContent = 'Pemilihan Payload';
        header.style.margin = '0 0 15px 0';
        header.style.width = '100%';
        header.style.color = '#58a6ff';

        // Buat label
        const label = document.createElement('label');
        label.htmlFor = 'payload-dropdown';
        label.textContent = 'Pilih Payload: ';
        label.style.marginRight = '10px';
        label.style.fontWeight = 'bold';

        // Buat dropdown
        this.dropdownElement = document.createElement('select');
        this.dropdownElement.id = 'payload-dropdown';
        this.dropdownElement.className = 'payload-dropdown';
        this.dropdownElement.style.padding = '8px';
        this.dropdownElement.style.borderRadius = '5px';
        this.dropdownElement.style.backgroundColor = '#0d1117';
        this.dropdownElement.style.color = '#e6edf3';
        this.dropdownElement.style.border = '1px solid #30363d';
        this.dropdownElement.style.marginRight = '10px';
        this.dropdownElement.style.minWidth = '200px';

        // Buat tombol jalankan exploit
        const runButton = document.createElement('button');
        runButton.id = 'run-exploit-button';
        runButton.textContent = 'Jalankan Exploit';
        runButton.style.padding = '8px 16px';
        runButton.style.borderRadius = '5px';
        runButton.style.backgroundColor = '#238636';
        runButton.style.color = 'white';
        runButton.style.border = 'none';
        runButton.style.cursor = 'pointer';
        runButton.style.marginLeft = '10px';
        runButton.style.fontWeight = 'bold';
        runButton.style.fontSize = '16px';
        runButton.style.boxShadow = '0 2px 4px rgba(0,0,0,0.2)';
        runButton.style.display = 'none'; // Sembunyikan tombol sampai payload dipilih

        // Tambahkan event listener untuk tombol
        runButton.addEventListener('click', this.runExploit.bind(this));

        // Tambahkan elemen ke container
        container.appendChild(header);
        container.appendChild(label);
        container.appendChild(this.dropdownElement);
        container.appendChild(runButton);

        // Tambahkan container ke halaman
        // Cari elemen yang tepat untuk menambahkan dropdown
        const targetElement = document.querySelector('.status-container') ||
                             document.querySelector('.card') ||
                             document.body.firstChild;

        if (targetElement) {
            targetElement.parentNode.insertBefore(container, targetElement.nextSibling);
        } else {
            document.body.appendChild(container);
        }
    },

    // Fungsi untuk menjalankan exploit
    runExploit: function() {
        console.log('Menjalankan exploit dengan payload:', this.selectedPayload);

        // Pastikan payload sudah dimuat
        if (!window.pld) {
            this.showError('Payload belum dimuat. Silakan pilih payload terlebih dahulu.');
            return;
        }

        // Jalankan exploit
        if (typeof window.runExploit === 'function') {
            window.runExploit();
        } else {
            console.error('Fungsi runExploit tidak ditemukan');
            this.showError('Fungsi runExploit tidak ditemukan. Silakan muat ulang halaman.');
        }
    },

    // Muat daftar payload dari folder bin
    loadPayloadList: function() {
        console.log('Loading payload list...');

        // Daftar file bin yang diketahui
        // Ini akan digunakan jika tidak bisa mendapatkan daftar file dari folder bin
        const knownBinFiles = [
            'goldhen_2.3_900.bin',
            'ps4debug_900.bin',
            'ftps4_900.bin'
        ];

        // Coba mendapatkan daftar file dari folder bin
        fetch('bin/index.html')
            .then(response => {
                if (!response.ok) {
                    throw new Error('Failed to load bin directory');
                }
                return response.text();
            })
            .then(html => {
                // Parse HTML untuk mendapatkan daftar file
                const parser = new DOMParser();
                const doc = parser.parseFromString(html, 'text/html');

                // Coba dapatkan daftar file dari index.html yang kita buat
                let binFiles = [];
                const fileList = doc.getElementById('file-list');

                if (fileList) {
                    // Jika index.html kita berhasil dimuat
                    const links = fileList.querySelectorAll('a');
                    binFiles = Array.from(links)
                        .map(link => link.textContent)
                        .filter(name => name && name.endsWith('.bin'));
                } else {
                    // Jika tidak, coba parse dari Apache directory listing
                    const links = doc.querySelectorAll('a');
                    binFiles = Array.from(links)
                        .map(link => link.getAttribute('href'))
                        .filter(href => href && href.endsWith('.bin'));
                }

                // Jika tidak ada file yang ditemukan, gunakan daftar yang diketahui
                if (binFiles.length === 0) {
                    console.log('No bin files found in directory listing, using known files');
                    binFiles = knownBinFiles;
                }

                // Simpan daftar payload
                this.availablePayloads = binFiles;

                // Perbarui dropdown
                this.updateDropdown();

                console.log(`Found ${binFiles.length} payload files`);

                // Tampilkan tombol run exploit jika ada payload yang dipilih
                this.updateRunButton();
            })
            .catch(error => {
                console.error('Error loading bin directory:', error);

                // Jika gagal mendapatkan daftar file, gunakan daftar yang diketahui
                console.log('Using known bin files');
                this.availablePayloads = knownBinFiles;

                // Perbarui dropdown
                this.updateDropdown();

                // Tampilkan pesan informasi
                this.showSuccess('Menggunakan daftar payload yang diketahui.');
            });
    },

    // Perbarui dropdown dengan daftar payload
    updateDropdown: function() {
        // Hapus semua opsi yang ada
        this.dropdownElement.innerHTML = '';

        // Tambahkan opsi default
        const defaultOption = document.createElement('option');
        defaultOption.value = 'payload.bin';
        defaultOption.textContent = 'Default Payload (payload.bin)';
        this.dropdownElement.appendChild(defaultOption);

        // Tambahkan opsi untuk setiap payload
        this.availablePayloads.forEach(payload => {
            // Jika payload adalah payload default, lewati
            if (payload === 'payload.bin') return;

            const option = document.createElement('option');
            option.value = payload;
            option.textContent = this.formatPayloadName(payload);
            this.dropdownElement.appendChild(option);
        });

        // Coba muat payload yang tersimpan di localStorage
        const savedPayload = localStorage.getItem('selectedPayload');
        if (savedPayload && this.availablePayloads.includes(savedPayload)) {
            this.dropdownElement.value = savedPayload;
            this.selectedPayload = savedPayload;
        } else {
            // Gunakan payload default
            this.selectedPayload = 'payload.bin';
        }

        // Trigger event change untuk memuat payload yang dipilih
        this.handlePayloadSelection({ target: this.dropdownElement });
    },

    // Format nama payload untuk ditampilkan di dropdown
    formatPayloadName: function(filename) {
        // Hapus path folder jika ada
        let name = filename.split('/').pop();

        // Hapus ekstensi .bin
        name = name.replace('.bin', '');

        // Ganti underscore dengan spasi
        name = name.replace(/_/g, ' ');

        // Kapitalisasi setiap kata
        name = name.split(' ').map(word => {
            return word.charAt(0).toUpperCase() + word.slice(1);
        }).join(' ');

        return name;
    },

    // Handle pemilihan payload
    handlePayloadSelection: function(event) {
        const selectedValue = event.target.value;
        console.log(`Payload selected: ${selectedValue}`);

        // Simpan pilihan di localStorage
        localStorage.setItem('selectedPayload', selectedValue);

        // Simpan pilihan di state
        this.selectedPayload = selectedValue;

        // Muat payload yang dipilih
        this.loadSelectedPayload();

        // Tampilkan tombol run exploit
        this.updateRunButton();
    },

    // Perbarui tampilan tombol run exploit
    updateRunButton: function() {
        const runButton = document.getElementById('run-exploit-button');
        if (!runButton) return;

        if (this.selectedPayload) {
            // Tampilkan tombol jika payload dipilih
            runButton.style.display = 'inline-block';

            // Tambahkan animasi untuk menarik perhatian
            runButton.style.animation = 'pulse 2s infinite';
            runButton.style.transition = 'all 0.3s ease';

            // Tambahkan style untuk animasi pulse
            if (!document.getElementById('pulse-animation')) {
                const style = document.createElement('style');
                style.id = 'pulse-animation';
                style.textContent = `
                    @keyframes pulse {
                        0% { transform: scale(1); }
                        50% { transform: scale(1.05); }
                        100% { transform: scale(1); }
                    }
                `;
                document.head.appendChild(style);
            }
        } else {
            // Sembunyikan tombol jika tidak ada payload yang dipilih
            runButton.style.display = 'none';
        }
    },

    // Muat payload yang dipilih
    loadSelectedPayload: function() {
        console.log(`Loading payload: ${this.selectedPayload}`);

        // Tentukan path payload
        let payloadPath = this.selectedPayload;

        // Jika bukan payload default dan tidak dimulai dengan 'bin/', tambahkan prefix
        if (this.selectedPayload !== 'payload.bin' && !this.selectedPayload.startsWith('bin/')) {
            payloadPath = `bin/${this.selectedPayload}`;
        }

        // Muat payload menggunakan fetch
        fetch(payloadPath)
            .then(response => {
                if (!response.ok) {
                    throw new Error(`Failed to load payload: ${response.status} ${response.statusText}`);
                }
                return response.arrayBuffer();
            })
            .then(arrayBuffer => {
                // Validasi payload
                if (this.validatePayload(arrayBuffer)) {
                    // Simpan payload di window.pld untuk digunakan oleh exploit
                    window.pld = new Uint32Array(arrayBuffer);
                    console.log(`Payload loaded successfully: ${this.selectedPayload} (${arrayBuffer.byteLength} bytes)`);

                    // Tampilkan notifikasi sukses
                    this.showSuccess(`Payload ${this.formatPayloadName(this.selectedPayload)} dimuat (${this.formatBytes(arrayBuffer.byteLength)})`);

                    // Dispatch event untuk memberi tahu komponen lain
                    document.dispatchEvent(new CustomEvent('payloadLoaded', {
                        detail: {
                            name: this.selectedPayload,
                            size: arrayBuffer.byteLength
                        }
                    }));
                } else {
                    throw new Error('Invalid payload format');
                }
            })
            .catch(error => {
                console.error(`Error loading payload: ${error}`);

                // Jika gagal, coba muat payload default
                if (this.selectedPayload !== 'payload.bin') {
                    this.showError(`Gagal memuat payload ${this.formatPayloadName(this.selectedPayload)}. Menggunakan payload default.`);
                    this.selectedPayload = 'payload.bin';
                    this.dropdownElement.value = 'payload.bin';
                    this.loadSelectedPayload();
                } else {
                    this.showError('Gagal memuat payload default. Silakan muat ulang halaman.');

                    // Dispatch event error
                    document.dispatchEvent(new CustomEvent('payloadError', {
                        detail: {
                            name: this.selectedPayload,
                            error: error.message
                        }
                    }));
                }
            });
    },

    // Validasi payload
    validatePayload: function(arrayBuffer) {
        // TODO: Implementasikan validasi payload yang lebih baik

        // Validasi sederhana: periksa ukuran payload
        return arrayBuffer.byteLength > 0;
    },

    // Format ukuran file dalam bytes ke format yang lebih mudah dibaca
    formatBytes: function(bytes, decimals = 2) {
        if (bytes === 0) return '0 Bytes';

        const k = 1024;
        const dm = decimals < 0 ? 0 : decimals;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];

        const i = Math.floor(Math.log(bytes) / Math.log(k));

        return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
    },

    // Tampilkan notifikasi sukses
    showSuccess: function(message) {
        this.showNotification(message, '#4CAF50');
    },

    // Tampilkan notifikasi error
    showError: function(message) {
        this.showNotification(message, '#f44336');
    },

    // Tampilkan notifikasi
    showNotification: function(message, color) {
        // Cek apakah sudah ada notifikasi
        let notification = document.querySelector('.payload-notification');

        // Jika belum ada, buat elemen baru
        if (!notification) {
            notification = document.createElement('div');
            notification.className = 'payload-notification';
            notification.style.position = 'fixed';
            notification.style.bottom = '10px';
            notification.style.left = '10px';
            notification.style.padding = '10px';
            notification.style.borderRadius = '5px';
            notification.style.color = 'white';
            notification.style.zIndex = '1000';
            notification.style.maxWidth = '80%';
            notification.style.boxShadow = '0 2px 5px rgba(0,0,0,0.2)';
            document.body.appendChild(notification);
        }

        // Atur pesan dan warna
        notification.textContent = message;
        notification.style.backgroundColor = color;

        // Tampilkan notifikasi
        notification.style.display = 'block';

        // Hilangkan notifikasi setelah 5 detik
        setTimeout(() => {
            notification.style.opacity = '0';
            notification.style.transition = 'opacity 1s';
            setTimeout(() => {
                notification.style.display = 'none';
                notification.style.opacity = '1';
            }, 1000);
        }, 5000);
    }
};

// Inisialisasi payload selector saat DOM loaded
document.addEventListener('DOMContentLoaded', function() {
    PayloadSelector.init();
});
