// hooks_template.js

// Helper function to log data to a file (simulated via send for now, Python side handles writing)
function logSecret(type, address, data) {
    send({
        type: 'secret',
        payload: {
            type: type,
            address: address,
            data: data
        }
    });
}

// Helper to hexdump memory
function memoryDump(address, length) {
    try {
        return hexdump(ptr(address), {
            offset: 0,
            length: length,
            header: false,
            ansi: false
        });
    } catch (e) {
        return "Error reading memory: " + e;
    }
}

console.log("[*] Frida script loaded");

// --- DYNAMIC HOOKS START ---
// This section will be populated by instrumentation.py
// {{DYNAMIC_HOOKS}}
// --- DYNAMIC HOOKS END ---

// Example of what might be injected:
/*
Interceptor.attach(ptr("0x123456"), {
    onEnter: function(args) {
        logSecret("register_dump", "0x123456", {
            r0: this.context.r0,
            r1: this.context.r1
        });
    }
});
*/
