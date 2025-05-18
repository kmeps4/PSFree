// Fungsi untuk memvalidasi payload
function validatePayload(buffer) {
    // Periksa ukuran payload
    if (buffer.byteLength < 100) {
        console.warn("WARNING: Payload size is suspiciously small:", buffer.byteLength, "bytes");
    }

    // Periksa apakah payload memiliki header yang valid
    // Ini hanya contoh sederhana, sesuaikan dengan format payload yang sebenarnya
    const view = new DataView(buffer);
    const magic = view.getUint32(0, true); // Little endian

    // Log informasi payload untuk debugging
    console.log("Payload size:", buffer.byteLength, "bytes");
    console.log("Payload first 4 bytes (magic):", "0x" + magic.toString(16));

    return true;
}

// Fungsi untuk memuat payload dengan penanganan error
function loadPayload() {
    console.log("Loading payload.bin...");

    fetch('./payload.bin')
        .then(res => {
            if (!res.ok) {
                throw new Error(`Failed to load payload: ${res.status} ${res.statusText}`);
            }
            console.log("Payload fetched successfully, processing...");
            return res.arrayBuffer();
        })
        .then(arr => {
            try {
                // Validasi payload
                if (validatePayload(arr)) {
                    // Simpan payload di window.pld
                    window.pld = new Uint32Array(arr);
                    console.log("Payload loaded and validated successfully");

                    // Dispatch event untuk memberi tahu komponen lain
                    const event = new CustomEvent('payloadLoaded', {
                        detail: { size: arr.byteLength }
                    });
                    document.dispatchEvent(event);
                }
            } catch (e) {
                console.error("Error processing payload:", e);

                // Dispatch event error
                const event = new CustomEvent('payloadError', {
                    detail: { error: e.message }
                });
                document.dispatchEvent(event);
            }
        })
        .catch(err => {
            console.error("Error loading payload:", err);

            // Dispatch event error
            const event = new CustomEvent('payloadError', {
                detail: { error: err.message }
            });
            document.dispatchEvent(event);
        });
}

// Muat payload saat script dijalankan
loadPayload();