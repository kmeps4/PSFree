/**
 * PSFree Payload Manager
 * Compatible with PS4 FW 9.00 Browser
 * TODO: Add support for multiple payloads and payload verification
 */

// Global state for payloads
window.payloadState = {
    defaultPayload: null,
    customPayloads: {},
    selectedPayload: 'payload.bin'
};

// Function to load the default payload
function loadDefaultPayload() {
    console.log('Loading default payload...');
    
    fetch('./payload.bin')
        .then(response => {
            if (!response.ok) {
                throw new Error('Failed to load default payload');
            }
            return response.arrayBuffer();
        })
        .then(arrayBuffer => {
            window.payloadState.defaultPayload = new Uint32Array(arrayBuffer);
            window.pld = window.payloadState.defaultPayload; // For backward compatibility
            console.log('Default payload loaded successfully');
            
            // Dispatch event for UI to update
            document.dispatchEvent(new CustomEvent('payloadLoaded', {
                detail: {
                    name: 'payload.bin',
                    size: arrayBuffer.byteLength
                }
            }));
        })
        .catch(error => {
            console.error('Error loading default payload:', error);
            
            // Dispatch event for UI to update
            document.dispatchEvent(new CustomEvent('payloadError', {
                detail: {
                    name: 'payload.bin',
                    error: error.message
                }
            }));
        });
}

// Function to load a custom payload
function loadCustomPayload(name, arrayBuffer) {
    console.log(`Loading custom payload: ${name}`);
    
    try {
        const payload = new Uint32Array(arrayBuffer);
        window.payloadState.customPayloads[name] = payload;
        
        console.log(`Custom payload "${name}" loaded successfully`);
        
        // Dispatch event for UI to update
        document.dispatchEvent(new CustomEvent('customPayloadLoaded', {
            detail: {
                name: name,
                size: arrayBuffer.byteLength
            }
        }));
        
        return true;
    } catch (error) {
        console.error(`Error loading custom payload "${name}":`, error);
        
        // Dispatch event for UI to update
        document.dispatchEvent(new CustomEvent('payloadError', {
            detail: {
                name: name,
                error: error.message
            }
        }));
        
        return false;
    }
}

// Function to select a payload
function selectPayload(name) {
    console.log(`Selecting payload: ${name}`);
    
    if (name === 'payload.bin') {
        if (window.payloadState.defaultPayload) {
            window.pld = window.payloadState.defaultPayload;
            window.payloadState.selectedPayload = name;
            return true;
        }
        return false;
    } else if (window.payloadState.customPayloads[name]) {
        window.pld = window.payloadState.customPayloads[name];
        window.payloadState.selectedPayload = name;
        return true;
    }
    
    return false;
}

// Function to get the currently selected payload
function getSelectedPayload() {
    const name = window.payloadState.selectedPayload;
    
    if (name === 'payload.bin') {
        return window.payloadState.defaultPayload;
    } else {
        return window.payloadState.customPayloads[name];
    }
}

// Initialize by loading the default payload
loadDefaultPayload();

// Export functions to window for access from other scripts
window.payloadManager = {
    loadCustomPayload,
    selectPayload,
    getSelectedPayload
};
