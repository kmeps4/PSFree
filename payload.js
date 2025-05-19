// Function to validate the payload
function validatePayload(buffer) {
    // Check the size of the payload
    if (buffer.byteLength < 100) {
        console.warn("WARNING: Payload size is suspiciously small:", buffer.byteLength, "bytes");
    }

    // Check if the payload has a valid header
    // This is just a simple example, adjust to match the actual payload format
    const view = new DataView(buffer);
    const magic = view.getUint32(0, true); // Little endian

    // Log payload info for debugging
    console.log("Payload size:", buffer.byteLength, "bytes");
    console.log("Payload first 4 bytes (magic):", "0x" + magic.toString(16));

    return true;
}

// Function to load the payload with error handling
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
                // Validate the payload
                if (validatePayload(arr)) {
                    // Store payload in window.pld
                    window.pld = new Uint32Array(arr);
                    console.log("Payload loaded and validated successfully");

                    // Dispatch event to notify other components
                    const event = new CustomEvent('payloadLoaded', {
                        detail: { size: arr.byteLength }
                    });
                    document.dispatchEvent(event);
                }
            } catch (e) {
                console.error("Error processing payload:", e);

                // Dispatch error event
                const event = new CustomEvent('payloadError', {
                    detail: { error: e.message }
                });
                document.dispatchEvent(event);
            }
        })
        .catch(err => {
            console.error("Error loading payload:", err);

            // Dispatch error event
            const event = new CustomEvent('payloadError', {
                detail: { error: err.message }
            });
            document.dispatchEvent(event);
        });
}

// Load payload when the script runs
loadPayload();
