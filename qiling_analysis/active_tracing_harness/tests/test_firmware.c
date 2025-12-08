/*
 * Simple Test Binary for Active Tracing Harness
 * 
 * This simulates a firmware binary that:
 * 1. Initializes
 * 2. Reads from network (recv)
 * 3. Validates the input
 * 4. Performs "key exchange"
 * 5. Exits with success/error
 * 
 * Compile:
 *   x86_64: gcc -o test_firmware test_firmware.c -static
 *   ARM:    arm-linux-gnueabi-gcc -o test_firmware_arm test_firmware.c -static
 *   MIPS:   mips-linux-gnu-gcc -o test_firmware_mips test_firmware.c -static
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define MAGIC_HEADER 0xDEADBEEF
#define BUFFER_SIZE 256

// Simulated crypto operation
void aes_encrypt(unsigned char *data, int len) {
    for (int i = 0; i < len; i++) {
        data[i] ^= 0x42;  // Simple XOR "encryption"
    }
}

// Simulated key derivation
void derive_key(unsigned char *input, unsigned char *output) {
    for (int i = 0; i < 16; i++) {
        output[i] = input[i] ^ input[i+16];
    }
}

int main(int argc, char *argv[]) {
    int sockfd;
    struct sockaddr_in server_addr;
    unsigned char buffer[BUFFER_SIZE];
    unsigned char session_key[16];
    int bytes_received;
    unsigned int magic;
    
    printf("[INIT] Firmware starting...\n");
    printf("[INIT] Version: 1.0.0\n");
    
    // Create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        fprintf(stderr, "[ERROR] Socket creation failed\n");
        return 1;
    }
    
    printf("[INIT] Socket created: fd=%d\n", sockfd);
    
    // Setup server address (won't actually connect)
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(8888);
    inet_pton(AF_INET, "192.168.1.100", &server_addr.sin_addr);
    
    // Attempt to connect (this will fail in harness, but that's OK)
    printf("[INIT] Attempting connection to server...\n");
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        // In real firmware this would error, but harness bypasses this
        printf("[INIT] Connection established (or bypassed)\n");
    }
    
    // ========================================================================
    // CRITICAL: This is where the binary would normally hang without a server
    // The harness will hook this recv() and inject golden input
    // ========================================================================
    
    printf("[HANDSHAKE] Waiting for handshake data...\n");
    bytes_received = recv(sockfd, buffer, BUFFER_SIZE, 0);
    
    if (bytes_received <= 0) {
        fprintf(stderr, "[ERROR] No data received\n");
        close(sockfd);
        return 2;
    }
    
    printf("[HANDSHAKE] Received %d bytes\n", bytes_received);
    
    // Validate magic header
    memcpy(&magic, buffer, sizeof(magic));
    if (magic != MAGIC_HEADER) {
        fprintf(stderr, "[ERROR] Invalid magic header: 0x%08x (expected 0x%08x)\n", 
                magic, MAGIC_HEADER);
        close(sockfd);
        return 3;
    }
    
    printf("[HANDSHAKE] Magic header validated\n");
    
    // Extract version byte
    unsigned char version = buffer[4];
    if (version != 1) {
        fprintf(stderr, "[ERROR] Unsupported protocol version: %d\n", version);
        close(sockfd);
        return 4;
    }
    
    printf("[HANDSHAKE] Protocol version: %d\n", version);
    
    // ========================================================================
    // Key Exchange Phase
    // ========================================================================
    
    printf("[KEY_EXCHANGE] Deriving session key...\n");
    
    // Use bytes 5-36 as key material (32 bytes)
    derive_key(buffer + 5, session_key);
    
    printf("[KEY_EXCHANGE] Session key derived: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", session_key[i]);
    }
    printf("\n");
    
    // ========================================================================
    // Processing Phase
    // ========================================================================
    
    printf("[PROCESSING] Encrypting response...\n");
    
    unsigned char response[32];
    memset(response, 0xAA, sizeof(response));
    aes_encrypt(response, sizeof(response));
    
    printf("[PROCESSING] Sending response...\n");
    // In real firmware, would send() here
    // send(sockfd, response, sizeof(response), 0);
    
    printf("[SUCCESS] Handshake complete!\n");
    
    close(sockfd);
    return 0;
}
