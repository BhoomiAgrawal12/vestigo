/* fntt64.c
   FNTT-64: Feistel cipher with NTT-inspired mixing in round function
   - 64-bit block (L,R 32-bit), 128-bit key (16 bytes)
   - 12 rounds Feistel: R' = L ^ F(R, roundkey)
   - F() does small modular "butterfly" operations on 4 bytes (vector) using mod 257 arithmetic
   Compile: gcc -std=c11 -O2 -o fntt64 fntt64.c
*/

#include <stdio.h>
#include <stdint.h>
#include <string.h>

/* Helpers */
static inline uint32_t read_u32_be(const uint8_t *b){
    return ((uint32_t)b[0]<<24) | ((uint32_t)b[1]<<16) | ((uint32_t)b[2]<<8) | b[3];
}
static inline void write_u32_be(uint8_t *b, uint32_t v){
    b[0] = (v>>24)&0xFF; b[1] = (v>>16)&0xFF; b[2] = (v>>8)&0xFF; b[3] = v&0xFF;
}

#define ROUNDS_F 12

/* Small constants chosen for round mixing */
static const uint16_t MIXC[4] = {3, 5, 11, 17}; /* co-prime-ish to 257 */

/* Modular add/mul in Z_257 (a small prime) */
static inline uint16_t mod257_add(uint16_t a, uint16_t b){ uint16_t s = a + b; if(s >= 257) s -= 257; return s; }
static inline uint16_t mod257_mul(uint16_t a, uint16_t b){ return (uint16_t)(( (uint32_t)a * (uint32_t)b ) % 257); }

/* Key schedule: generate ROUNDS_F 4-byte subkeys from 16-byte master key */
static void key_schedule(const uint8_t master[16], uint8_t subk[ROUNDS_F][4]){
    uint8_t tmp[16];
    memcpy(tmp, master, 16);
    for(int r=0;r<ROUNDS_F;r++){
        for(int i=0;i<4;i++) subk[r][i] = tmp[(r+i) & 15] ^ (uint8_t)(r*0x9 + i*0x3);
        /* simple rotate bytes */
        uint8_t t = tmp[0];
        memmove(tmp, tmp+1, 15);
        tmp[15] = t ^ (uint8_t)r;
    }
}

/* F: take 32-bit input as 4 bytes v0..v3 (0..255), map to 0..256 domain for mod257,
   apply 2-stage NTT-inspired butterflies, then fold with round key bytes and return 32-bit */
static uint32_t F_func(uint32_t x, const uint8_t rk[4]){
    uint16_t v[4];
    uint8_t b[4];
    b[0] = (x>>24)&0xFF; b[1] = (x>>16)&0xFF; b[2] = (x>>8)&0xFF; b[3] = x&0xFF;
    for(int i=0;i<4;i++) v[i] = (uint16_t)b[i]; /* in 0..255 domain */

    /* Stage 1: NTT-like butterflies (pairwise) modulo 257 */
    for(int i=0;i<2;i++){
        int a = i*2, c = i*2+1;
        uint16_t u = v[a];
        uint16_t t = v[c];
        uint16_t mul = mod257_mul(t, MIXC[i]);      /* multiply by small constant */
        v[a] = mod257_add(u, mul);                 /* u + mul*t */
        v[c] = (uint16_t)((u + 257 - mul) % 257);  /* u - mul*t (mod 257) */
    }
    /* Stage 2: cross mixing (butterfly across 0 & 2, 1 & 3) */
    for(int i=0;i<2;i++){
        int a = i, c = i+2;
        uint16_t u = v[a];
        uint16_t t = v[c];
        uint16_t mul = mod257_mul(t, MIXC[(i+2)%4]);
        v[a] = mod257_add(u, mul);
        v[c] = (uint16_t)((u + 257 - mul) % 257);
    }

    /* Fold with round key bytes (add and xor-ish combine) and compress back to 32-bit */
    for(int i=0;i<4;i++){
        uint16_t k = (uint16_t)rk[i];
        /* mix: multiply by (k+1) mod 257, then add k */
        v[i] = mod257_add(mod257_mul(v[i], (uint16_t)((k+1)%257)), (uint16_t)(k%257));
        /* compress: map 0..256 back to 0..255 via (value % 256) */
        b[i] = (uint8_t)(v[i] % 256);
    }
    return ((uint32_t)b[0]<<24) | ((uint32_t)b[1]<<16) | ((uint32_t)b[2]<<8) | b[3];
}

/* Encrypt block (8 bytes) */
void fntt64_encrypt(const uint8_t plaintext[8], uint8_t ciphertext[8], const uint8_t masterkey[16]){
    uint8_t subk[ROUNDS_F][4];
    key_schedule(masterkey, subk);
    uint32_t L = read_u32_be(plaintext);
    uint32_t R = read_u32_be(plaintext+4);
    for(int r=0;r<ROUNDS_F;r++){
        uint32_t F = F_func(R, subk[r]);
        uint32_t newL = R;
        uint32_t newR = L ^ F;
        L = newL; R = newR;
    }
    /* combine (no final swap to keep simple) */
    write_u32_be(ciphertext, L);
    write_u32_be(ciphertext+4, R);
}

/* Decrypt block (Feistel inversion) */
void fntt64_decrypt(const uint8_t ciphertext[8], uint8_t plaintext[8], const uint8_t masterkey[16]){
    uint8_t subk[ROUNDS_F][4];
    key_schedule(masterkey, subk);
    uint32_t L = read_u32_be(ciphertext);
    uint32_t R = read_u32_be(ciphertext+4);
    for(int r=ROUNDS_F-1; r>=0; r--){
        uint32_t newR = L;
        uint32_t F = F_func(newR, subk[r]);
        uint32_t newL = R ^ F;
        L = newL; R = newR;
    }
    write_u32_be(plaintext, L);
    write_u32_be(plaintext+4, R);
}

/* hex print */
static void print_hex(const uint8_t *d, int n){
    for(int i=0;i<n;i++) printf("%02X", d[i]);
    printf("\n");
}

/* Test harness */
int main(void){
    uint8_t key[16] = {
        0x0F,0x1E,0x2D,0x3C,0x4B,0x5A,0x69,0x78,
        0x87,0x96,0xA5,0xB4,0xC3,0xD2,0xE1,0xF0
    };
    uint8_t pt[8] = {0xDE,0xAD,0xBE,0xEF,0x00,0x11,0x22,0x33};
    uint8_t ct[8], rec[8];
    fntt64_encrypt(pt, ct, key);
    fntt64_decrypt(ct, rec, key);
    printf("FNTT-64 test\nPlain : "); print_hex(pt,8);
    printf("Cipher: "); print_hex(ct,8);
    printf("Decrypt: "); print_hex(rec,8);
    return 0;
}
