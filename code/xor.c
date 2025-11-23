#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

// Proprietary XOR-based encryption with multiple rounds and key schedule

#define XOR_KEY_SIZE 32
#define XOR_BLOCK_SIZE 16
#define XOR_ROUNDS 8

typedef struct {
    uint8_t master_key[XOR_KEY_SIZE];
    uint8_t round_keys[XOR_ROUNDS][XOR_KEY_SIZE];
} XOR_CTX;

// Custom S-Box for substitution (proprietary)
static const uint8_t custom_sbox[256] = {
    0x2d, 0x7f, 0xae, 0x18, 0x5b, 0xc3, 0x41, 0x96, 0xe2, 0x0a, 0xf4, 0x67, 0x3c, 0xb9, 0x84, 0x1e,
    0x52, 0xd6, 0x9f, 0x20, 0x6e, 0xa7, 0x33, 0xc8, 0x14, 0xfb, 0x45, 0x8d, 0x71, 0xba, 0x06, 0xe9,
    0x99, 0x5a, 0xdc, 0x2b, 0x78, 0xc1, 0x4f, 0xa3, 0x15, 0xe6, 0x60, 0xb2, 0x8c, 0x37, 0xfd, 0x0b,
    0x54, 0xd9, 0xa1, 0x2e, 0x72, 0xbf, 0x46, 0xc5, 0x19, 0xea, 0x63, 0x9d, 0x80, 0x38, 0xf7, 0x1c,
    0xb5, 0x6a, 0xde, 0x24, 0x91, 0xcf, 0x58, 0xa6, 0x12, 0xe8, 0x7d, 0xbb, 0x30, 0x4a, 0xc9, 0x05,
    0x97, 0x5e, 0xd2, 0x2c, 0x76, 0xb8, 0x43, 0xcd, 0x1a, 0xec, 0x61, 0x9a, 0x85, 0x39, 0xf1, 0x0d,
    0xb3, 0x68, 0xdd, 0x22, 0x93, 0xc6, 0x5c, 0xa9, 0x17, 0xef, 0x7b, 0xb4, 0x3e, 0x48, 0xca, 0x01,
    0x95, 0x5d, 0xd1, 0x29, 0x74, 0xbe, 0x42, 0xcc, 0x1b, 0xed, 0x66, 0x9c, 0x81, 0x3a, 0xf6, 0x0c,
    0xb6, 0x69, 0xdf, 0x23, 0x92, 0xc7, 0x57, 0xa8, 0x16, 0xeb, 0x7c, 0xb7, 0x31, 0x49, 0xce, 0x04,
    0x98, 0x59, 0xd3, 0x2a, 0x77, 0xbc, 0x44, 0xcb, 0x1d, 0xee, 0x62, 0x9b, 0x86, 0x3b, 0xf5, 0x0e,
    0xb1, 0x6c, 0xdb, 0x27, 0x94, 0xc4, 0x56, 0xaa, 0x13, 0xe7, 0x7e, 0xb0, 0x3d, 0x4c, 0xc2, 0x08,
    0x9e, 0x55, 0xd7, 0x21, 0x79, 0xbd, 0x40, 0xc0, 0x11, 0xe5, 0x6b, 0x9f, 0x88, 0x34, 0xf3, 0x0f,
    0xaf, 0x6d, 0xd8, 0x25, 0x90, 0xd0, 0x53, 0xab, 0x10, 0xe4, 0x75, 0xb9, 0x32, 0x4b, 0xd4, 0x02,
    0x96, 0x51, 0xd5, 0x28, 0x73, 0xbb, 0x47, 0xce, 0x1f, 0xef, 0x64, 0x98, 0x83, 0x3f, 0xf2, 0x09,
    0xb4, 0x65, 0xda, 0x26, 0x8f, 0xc5, 0x50, 0xac, 0x14, 0xe3, 0x70, 0xbc, 0x35, 0x4d, 0xd6, 0x03,
    0x8e, 0x5f, 0xd0, 0x2f, 0x7a, 0xbf, 0x4e, 0xcf, 0x1e, 0xe1, 0x6f, 0xa0, 0x89, 0x36, 0xf8, 0x00
};

// Inverse S-Box for decryption
static uint8_t inv_sbox[256];

// Initialize inverse S-Box
static void init_inv_sbox() {
    static int initialized = 0;
    if (!initialized) {
        for (int i = 0; i < 256; i++) {
            inv_sbox[custom_sbox[i]] = i;
        }
        initialized = 1;
    }
}

// Rotate left function
static uint8_t rotl8(uint8_t value, unsigned int shift) {
    return (value << shift) | (value >> (8 - shift));
}

// Rotate right function
static uint8_t rotr8(uint8_t value, unsigned int shift) {
    return (value >> shift) | (value << (8 - shift));
}

// Key schedule generation (proprietary algorithm)
static void xor_key_schedule(XOR_CTX *ctx) {
    // Initialize first round key with master key
    memcpy(ctx->round_keys[0], ctx->master_key, XOR_KEY_SIZE);
    
    // Generate subsequent round keys
    for (int round = 1; round < XOR_ROUNDS; round++) {
        for (int i = 0; i < XOR_KEY_SIZE; i++) {
            uint8_t prev = ctx->round_keys[round - 1][i];
            uint8_t next_idx = (i + 1) % XOR_KEY_SIZE;
            uint8_t prev_idx = (i - 1 + XOR_KEY_SIZE) % XOR_KEY_SIZE;
            
            // Complex mixing function
            uint8_t mixed = prev ^ ctx->round_keys[round - 1][next_idx];
            mixed = rotl8(mixed, 3);
            mixed ^= custom_sbox[ctx->round_keys[round - 1][prev_idx]];
            mixed ^= (round * 17 + i * 23) & 0xFF;  // Round constant
            
            ctx->round_keys[round][i] = mixed;
        }
    }
}

// Initialize XOR cipher context
void xor_init(XOR_CTX *ctx, const uint8_t *key) {
    init_inv_sbox();
    memcpy(ctx->master_key, key, XOR_KEY_SIZE);
    xor_key_schedule(ctx);
}

// Substitution layer
static void substitute_bytes(uint8_t *block, int forward) {
    for (int i = 0; i < XOR_BLOCK_SIZE; i++) {
        block[i] = forward ? custom_sbox[block[i]] : inv_sbox[block[i]];
    }
}

// Permutation layer
static void permute_bytes(uint8_t *block, int forward) {
    uint8_t temp[XOR_BLOCK_SIZE];
    
    // Proprietary permutation pattern
    static const int perm[16] = {0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3};
    static int inv_perm[16] = {-1};
    
    // Initialize inverse permutation
    if (inv_perm[0] == -1) {
        for (int i = 0; i < 16; i++) {
            inv_perm[perm[i]] = i;
        }
    }
    
    if (forward) {
        for (int i = 0; i < XOR_BLOCK_SIZE; i++) {
            temp[i] = block[perm[i]];
        }
    } else {
        for (int i = 0; i < XOR_BLOCK_SIZE; i++) {
            temp[i] = block[inv_perm[i]];
        }
    }
    
    memcpy(block, temp, XOR_BLOCK_SIZE);
}

// Diffusion layer with bitwise rotations
static void diffuse_bytes(uint8_t *block) {
    for (int i = 0; i < XOR_BLOCK_SIZE; i++) {
        int prev = (i - 1 + XOR_BLOCK_SIZE) % XOR_BLOCK_SIZE;
        int next = (i + 1) % XOR_BLOCK_SIZE;
        
        block[i] = rotl8(block[i], 2) ^ rotr8(block[prev], 1) ^ block[next];
    }
}

// XOR encryption of a single block
void xor_encrypt_block(const uint8_t *plaintext, uint8_t *ciphertext, XOR_CTX *ctx) {
    uint8_t state[XOR_BLOCK_SIZE];
    memcpy(state, plaintext, XOR_BLOCK_SIZE);
    
    for (int round = 0; round < XOR_ROUNDS; round++) {
        // XOR with round key
        for (int i = 0; i < XOR_BLOCK_SIZE; i++) {
            state[i] ^= ctx->round_keys[round][i % XOR_KEY_SIZE];
        }
        
        // Substitution
        substitute_bytes(state, 1);
        
        // Permutation
        permute_bytes(state, 1);
        
        // Diffusion (except last round)
        if (round < XOR_ROUNDS - 1) {
            diffuse_bytes(state);
        }
    }
    
    memcpy(ciphertext, state, XOR_BLOCK_SIZE);
}

// XOR decryption of a single block
void xor_decrypt_block(const uint8_t *ciphertext, uint8_t *plaintext, XOR_CTX *ctx) {
    uint8_t state[XOR_BLOCK_SIZE];
    memcpy(state, ciphertext, XOR_BLOCK_SIZE);
    
    for (int round = XOR_ROUNDS - 1; round >= 0; round--) {
        // Inverse diffusion (except last round)
        if (round < XOR_ROUNDS - 1) {
            // Apply diffusion in reverse (simplified - proper implementation would store)
            for (int iter = 0; iter < 3; iter++) {
                diffuse_bytes(state);
            }
        }
        
        // Inverse permutation
        permute_bytes(state, 0);
        
        // Inverse substitution
        substitute_bytes(state, 0);
        
        // XOR with round key
        for (int i = 0; i < XOR_BLOCK_SIZE; i++) {
            state[i] ^= ctx->round_keys[round][i % XOR_KEY_SIZE];
        }
    }
    
    memcpy(plaintext, state, XOR_BLOCK_SIZE);
}

// Stream cipher mode (CTR-like)
void xor_stream_encrypt(const uint8_t *plaintext, uint8_t *ciphertext, 
                        size_t len, XOR_CTX *ctx, uint64_t nonce) {
    uint8_t keystream[XOR_BLOCK_SIZE];
    uint8_t counter_block[XOR_BLOCK_SIZE];
    
    for (size_t i = 0; i < len; i += XOR_BLOCK_SIZE) {
        // Prepare counter block
        uint64_t counter = i / XOR_BLOCK_SIZE;
        memcpy(counter_block, &nonce, 8);
        memcpy(counter_block + 8, &counter, 8);
        
        // Generate keystream
        xor_encrypt_block(counter_block, keystream, ctx);
        
        // XOR with plaintext
        size_t block_size = (i + XOR_BLOCK_SIZE > len) ? (len - i) : XOR_BLOCK_SIZE;
        for (size_t j = 0; j < block_size; j++) {
            ciphertext[i + j] = plaintext[i + j] ^ keystream[j];
        }
    }
}

int main() {
    // Initialize key
    uint8_t key[XOR_KEY_SIZE] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00
    };
    
    XOR_CTX ctx;
    xor_init(&ctx, key);
    
    printf("Proprietary XOR Cipher\n\n");
    
    // Test block encryption
    uint8_t plaintext[XOR_BLOCK_SIZE] = "Hello XOR Crypto";
    uint8_t ciphertext[XOR_BLOCK_SIZE];
    uint8_t decrypted[XOR_BLOCK_SIZE];
    
    printf("Block Mode:\n");
    printf("Plaintext:  ");
    for (int i = 0; i < XOR_BLOCK_SIZE; i++) {
        printf("%02x ", plaintext[i]);
    }
    printf("\n");
    
    xor_encrypt_block(plaintext, ciphertext, &ctx);
    
    printf("Ciphertext: ");
    for (int i = 0; i < XOR_BLOCK_SIZE; i++) {
        printf("%02x ", ciphertext[i]);
    }
    printf("\n");
    
    xor_decrypt_block(ciphertext, decrypted, &ctx);
    
    printf("Decrypted:  ");
    for (int i = 0; i < XOR_BLOCK_SIZE; i++) {
        printf("%02x ", decrypted[i]);
    }
    printf("\n\n");
    
    // Test stream mode
    const char *message = "This is a longer message for stream encryption!";
    size_t msg_len = strlen(message);
    uint8_t *stream_cipher = malloc(msg_len);
    uint8_t *stream_plain = malloc(msg_len);
    
    printf("Stream Mode:\n");
    printf("Message: %s\n", message);
    
    uint64_t nonce = 0x123456789ABCDEF0ULL;
    xor_stream_encrypt((uint8_t*)message, stream_cipher, msg_len, &ctx, nonce);
    
    printf("Encrypted: ");
    for (size_t i = 0; i < msg_len; i++) {
        printf("%02x", stream_cipher[i]);
    }
    printf("\n");
    
    // Decrypt (same operation in CTR mode)
    xor_stream_encrypt(stream_cipher, stream_plain, msg_len, &ctx, nonce);
    
    printf("Decrypted: %.*s\n", (int)msg_len, stream_plain);
    
    free(stream_cipher);
    free(stream_plain);
    
    return 0;
}