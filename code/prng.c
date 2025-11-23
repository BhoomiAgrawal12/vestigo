#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

// Cryptographic Pseudo-Random Number Generator (PRNG)
// Implements multiple algorithms: Linear Congruential, Xorshift, ChaCha20-like

// ============================================================================
// Linear Congruential Generator (LCG)
// ============================================================================

typedef struct {
    uint64_t state;
    uint64_t a;  // Multiplier
    uint64_t c;  // Increment
    uint64_t m;  // Modulus
} LCG_State;

void lcg_init(LCG_State *lcg, uint64_t seed) {
    // Using parameters from Numerical Recipes
    lcg->a = 6364136223846793005ULL;
    lcg->c = 1442695040888963407ULL;
    lcg->m = 0xFFFFFFFFFFFFFFFFULL; // 2^64
    lcg->state = seed;
}

uint64_t lcg_next(LCG_State *lcg) {
    lcg->state = (lcg->a * lcg->state + lcg->c);  // Modulo 2^64 implicit
    return lcg->state;
}

// ============================================================================
// Xorshift128+ Generator
// ============================================================================

typedef struct {
    uint64_t s[2];
} Xorshift128_State;

void xorshift128_init(Xorshift128_State *xs, uint64_t seed) {
    xs->s[0] = seed;
    xs->s[1] = seed ^ 0x123456789ABCDEFULL;
    
    // Warm up
    for (int i = 0; i < 10; i++) {
        uint64_t s1 = xs->s[0];
        uint64_t s0 = xs->s[1];
        xs->s[0] = s0;
        s1 ^= s1 << 23;
        xs->s[1] = s1 ^ s0 ^ (s1 >> 18) ^ (s0 >> 5);
    }
}

uint64_t xorshift128_next(Xorshift128_State *xs) {
    uint64_t s1 = xs->s[0];
    uint64_t s0 = xs->s[1];
    uint64_t result = s0 + s1;
    
    xs->s[0] = s0;
    s1 ^= s1 << 23;
    xs->s[1] = s1 ^ s0 ^ (s1 >> 18) ^ (s0 >> 5);
    
    return result;
}

// ============================================================================
// ChaCha20-based PRNG (Simplified)
// ============================================================================

#define CHACHA_ROUNDS 20

typedef struct {
    uint32_t state[16];
    uint32_t keystream[16];
    int available;
} ChaCha_State;

#define ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

#define CHACHA_QUARTERROUND(a, b, c, d) \
    a += b; d ^= a; d = ROTL32(d, 16); \
    c += d; b ^= c; b = ROTL32(b, 12); \
    a += b; d ^= a; d = ROTL32(d, 8);  \
    c += d; b ^= c; b = ROTL32(b, 7);

void chacha_init(ChaCha_State *chacha, const uint8_t *key, uint64_t nonce) {
    // ChaCha constants: "expand 32-byte k"
    chacha->state[0] = 0x61707865;
    chacha->state[1] = 0x3320646e;
    chacha->state[2] = 0x79622d32;
    chacha->state[3] = 0x6b206574;
    
    // Key (256 bits)
    for (int i = 0; i < 8; i++) {
        chacha->state[4 + i] = ((uint32_t*)key)[i];
    }
    
    // Counter
    chacha->state[12] = 0;
    chacha->state[13] = 0;
    
    // Nonce (64 bits)
    chacha->state[14] = (uint32_t)(nonce & 0xFFFFFFFF);
    chacha->state[15] = (uint32_t)(nonce >> 32);
    
    chacha->available = 0;
}

void chacha_block(ChaCha_State *chacha) {
    uint32_t x[16];
    
    // Copy state
    for (int i = 0; i < 16; i++) {
        x[i] = chacha->state[i];
    }
    
    // 20 rounds (10 double rounds)
    for (int i = 0; i < CHACHA_ROUNDS; i += 2) {
        // Column rounds
        CHACHA_QUARTERROUND(x[0], x[4], x[8],  x[12]);
        CHACHA_QUARTERROUND(x[1], x[5], x[9],  x[13]);
        CHACHA_QUARTERROUND(x[2], x[6], x[10], x[14]);
        CHACHA_QUARTERROUND(x[3], x[7], x[11], x[15]);
        
        // Diagonal rounds
        CHACHA_QUARTERROUND(x[0], x[5], x[10], x[15]);
        CHACHA_QUARTERROUND(x[1], x[6], x[11], x[12]);
        CHACHA_QUARTERROUND(x[2], x[7], x[8],  x[13]);
        CHACHA_QUARTERROUND(x[3], x[4], x[9],  x[14]);
    }
    
    // Add original state
    for (int i = 0; i < 16; i++) {
        chacha->keystream[i] = x[i] + chacha->state[i];
    }
    
    // Increment counter
    chacha->state[12]++;
    if (chacha->state[12] == 0) {
        chacha->state[13]++;
    }
    
    chacha->available = 16;
}

uint32_t chacha_next(ChaCha_State *chacha) {
    if (chacha->available == 0) {
        chacha_block(chacha);
    }
    
    return chacha->keystream[--chacha->available];
}

// ============================================================================
// Mersenne Twister MT19937
// ============================================================================

#define MT_N 624
#define MT_M 397
#define MT_MATRIX_A 0x9908b0dfUL
#define MT_UPPER_MASK 0x80000000UL
#define MT_LOWER_MASK 0x7fffffffUL

typedef struct {
    uint32_t mt[MT_N];
    int mti;
} MT_State;

void mt_init(MT_State *mt, uint32_t seed) {
    mt->mt[0] = seed;
    for (mt->mti = 1; mt->mti < MT_N; mt->mti++) {
        mt->mt[mt->mti] = (1812433253UL * (mt->mt[mt->mti - 1] ^ (mt->mt[mt->mti - 1] >> 30)) + mt->mti);
    }
}

uint32_t mt_next(MT_State *mt) {
    uint32_t y;
    static uint32_t mag01[2] = {0x0UL, MT_MATRIX_A};
    
    if (mt->mti >= MT_N) {
        int kk;
        
        for (kk = 0; kk < MT_N - MT_M; kk++) {
            y = (mt->mt[kk] & MT_UPPER_MASK) | (mt->mt[kk + 1] & MT_LOWER_MASK);
            mt->mt[kk] = mt->mt[kk + MT_M] ^ (y >> 1) ^ mag01[y & 0x1UL];
        }
        
        for (; kk < MT_N - 1; kk++) {
            y = (mt->mt[kk] & MT_UPPER_MASK) | (mt->mt[kk + 1] & MT_LOWER_MASK);
            mt->mt[kk] = mt->mt[kk + (MT_M - MT_N)] ^ (y >> 1) ^ mag01[y & 0x1UL];
        }
        
        y = (mt->mt[MT_N - 1] & MT_UPPER_MASK) | (mt->mt[0] & MT_LOWER_MASK);
        mt->mt[MT_N - 1] = mt->mt[MT_M - 1] ^ (y >> 1) ^ mag01[y & 0x1UL];
        
        mt->mti = 0;
    }
    
    y = mt->mt[mt->mti++];
    
    // Tempering
    y ^= (y >> 11);
    y ^= (y << 7) & 0x9d2c5680UL;
    y ^= (y << 15) & 0xefc60000UL;
    y ^= (y >> 18);
    
    return y;
}

// ============================================================================
// Unified PRNG Interface
// ============================================================================

typedef enum {
    PRNG_LCG,
    PRNG_XORSHIFT128,
    PRNG_CHACHA20,
    PRNG_MT19937
} PRNG_Type;

typedef struct {
    PRNG_Type type;
    union {
        LCG_State lcg;
        Xorshift128_State xorshift;
        ChaCha_State chacha;
        MT_State mt;
    } state;
} PRNG;

void prng_init(PRNG *prng, PRNG_Type type, uint64_t seed) {
    prng->type = type;
    
    switch (type) {
        case PRNG_LCG:
            lcg_init(&prng->state.lcg, seed);
            break;
        case PRNG_XORSHIFT128:
            xorshift128_init(&prng->state.xorshift, seed);
            break;
        case PRNG_CHACHA20: {
            uint8_t key[32];
            for (int i = 0; i < 32; i++) {
                key[i] = (seed >> (i % 8 * 8)) & 0xFF;
            }
            chacha_init(&prng->state.chacha, key, seed);
            break;
        }
        case PRNG_MT19937:
            mt_init(&prng->state.mt, (uint32_t)seed);
            break;
    }
}

uint64_t prng_next(PRNG *prng) {
    switch (prng->type) {
        case PRNG_LCG:
            return lcg_next(&prng->state.lcg);
        case PRNG_XORSHIFT128:
            return xorshift128_next(&prng->state.xorshift);
        case PRNG_CHACHA20:
            return ((uint64_t)chacha_next(&prng->state.chacha) << 32) | chacha_next(&prng->state.chacha);
        case PRNG_MT19937:
            return ((uint64_t)mt_next(&prng->state.mt) << 32) | mt_next(&prng->state.mt);
        default:
            return 0;
    }
}

// Generate random bytes
void prng_bytes(PRNG *prng, uint8_t *buffer, size_t len) {
    for (size_t i = 0; i < len; i += 8) {
        uint64_t val = prng_next(prng);
        size_t copy_len = (i + 8 > len) ? (len - i) : 8;
        memcpy(buffer + i, &val, copy_len);
    }
}

// Generate random integer in range [0, max)
uint64_t prng_range(PRNG *prng, uint64_t max) {
    return prng_next(prng) % max;
}

// Generate random double in [0, 1)
double prng_double(PRNG *prng) {
    return (double)prng_next(prng) / (double)0xFFFFFFFFFFFFFFFFULL;
}

int main() {
    uint64_t seed = (uint64_t)time(NULL);
    
    printf("Cryptographic PRNG Test\n");
    printf("Seed: %llu\n\n", seed);
    
    // Test each PRNG type
    const char *prng_names[] = {"LCG", "Xorshift128+", "ChaCha20", "MT19937"};
    
    for (int type = 0; type < 4; type++) {
        PRNG prng;
        prng_init(&prng, (PRNG_Type)type, seed);
        
        printf("=== %s ===\n", prng_names[type]);
        
        // Generate 10 random numbers
        printf("Random numbers: ");
        for (int i = 0; i < 10; i++) {
            printf("%llu ", prng_next(&prng));
        }
        printf("\n");
        
        // Generate random bytes
        uint8_t bytes[16];
        prng_bytes(&prng, bytes, 16);
        printf("Random bytes: ");
        for (int i = 0; i < 16; i++) {
            printf("%02x ", bytes[i]);
        }
        printf("\n");
        
        // Generate random doubles
        printf("Random doubles: ");
        for (int i = 0; i < 5; i++) {
            printf("%.6f ", prng_double(&prng));
        }
        printf("\n\n");
    }
    
    // Statistical test: generate distribution
    printf("=== Distribution Test (ChaCha20) ===\n");
    PRNG prng;
    prng_init(&prng, PRNG_CHACHA20, seed);
    
    int buckets[10] = {0};
    int samples = 10000;
    
    for (int i = 0; i < samples; i++) {
        int bucket = prng_range(&prng, 10);
        buckets[bucket]++;
    }
    
    printf("Distribution over %d samples:\n", samples);
    for (int i = 0; i < 10; i++) {
        printf("Bucket %d: %d (%.1f%%)\n", i, buckets[i], 100.0 * buckets[i] / samples);
    }
    
    return 0;
}