
/* cspn64.c
   CSPN-64: experimental SPN-style cipher
   - 64-bit block, 128-bit key (16 bytes)
   - 8 rounds: SubNibble (4-bit sbox) -> AddRoundKey -> Permute bits (P-box)
   - final round uses only SubNibble + AddRoundKey (no P-box)
   Compile: gcc -std=c11 -O2 -o cspn64 cspn64.c
*/

#include <stdio.h>
#include <stdint.h>
#include <string.h>

/* 4-bit S-box (invented; NOT AES). Must be invertible. */
static const uint8_t SBOX[16]  = {0x6,0x4,0xC,0x5,0x0,0x7,0x2,0xE,0x1,0xF,0x3,0xD,0x8,0xA,0x9,0xB};
static const uint8_t SBOX_INV[16] = {4,8,6,10,1,3,0,5,12,14,13,15,2,11,7,9};

/* 64-bit P-box permutation: index->target position (bit indices 0..63)
   This is a fixed permutation chosen to mix across bytes; invertible. */
static const uint8_t PBOX[64] = {
  0,9,18,27,36,45,54,63,
  1,10,19,28,37,46,55,56,
  2,11,20,29,38,47,48,57,
  3,12,21,30,39,40,49,58,
  4,13,22,31,32,41,50,59,
  5,14,23,24,33,42,51,60,
  6,15,16,25,34,43,52,61,
  7,8,17,26,35,44,53,62
};
static uint8_t PBOX_INV[64];

#define ROUNDS 8

/* Rotate 128-bit key left by n bits (n < 128) - stored in 16-byte array */
static void rot128_left(uint8_t k[16], int n){
    if(n<=0) return;
    n &= 127;
    uint8_t tmp[16];
    for(int i=0;i<16;i++){
        int bit_index = (i*8);
        int src_bit = (bit_index - n);
        /* Build byte by byte */
    }
    /* simple bit-rotation implementation: convert to two 64-bit words */
    uint64_t a=0,b=0;
    for(int i=0;i<8;i++) a = (a<<8)|k[i];
    for(int i=8;i<16;i++) b = (b<<8)|k[i];
    __uint128_t whole = ((__uint128_t)a<<64) | b;
const __uint128_t MASK128 = ~((__uint128_t)0);

whole = ((whole << n) | (whole >> (128 - n))) & MASK128;    uint64_t hi = (uint64_t)(whole>>64);
    uint64_t lo = (uint64_t)(whole & 0xFFFFFFFFFFFFFFFFULL);
    for(int i=7;i>=0;i--){ k[i] = hi & 0xFF; hi >>= 8; }
    for(int i=15;i>=8;i--){ k[i] = lo & 0xFF; lo >>= 8; }
}

/* Derive round key i (8 rounds) by rotating master key and XORing some pattern */
static void round_key(const uint8_t master[16], uint8_t rk[ROUNDS][8]){
    uint8_t tmp[16];
    memcpy(tmp, master, 16);
    for(int r=0;r<ROUNDS;r++){
        /* take first 8 bytes as round key */
        for(int i=0;i<8;i++) rk[r][i] = tmp[i] ^ (uint8_t)(r*0x0F + i*0x13);
        rot128_left(tmp, 13); /* rotate for next round */
    }
}

/* apply 4-bit S-box to each nibble in 8-byte block */
static void sub_nibble(uint8_t b[8]){
    for(int i=0;i<8;i++){
        uint8_t hi = b[i] >> 4, lo = b[i] & 0x0F;
        b[i] = (SBOX[hi]<<4) | (SBOX[lo]);
    }
}
static void sub_nibble_inv(uint8_t b[8]){
    for(int i=0;i<8;i++){
        uint8_t hi = b[i] >> 4, lo = b[i] & 0x0F;
        b[i] = (SBOX_INV[hi]<<4) | (SBOX_INV[lo]);
    }
}

/* P-box: permute 64 bits according to PBOX */
static void pbox(uint8_t b[8]){
    uint8_t out[8] = {0};
    for(int bit=0; bit<64; ++bit){
        int src_byte = bit >> 3;
        int src_bit = bit & 7;
        int bitval = (b[src_byte] >> (7-src_bit)) & 1;
        int dst = PBOX[bit];
        int dst_byte = dst >> 3;
        int dst_bit = dst & 7;
        out[dst_byte] |= (bitval << (7-dst_bit));
    }
    memcpy(b, out, 8);
}
static void pbox_inv(uint8_t b[8]){
    uint8_t out[8] = {0};
    for(int bit=0; bit<64; ++bit){
        int src_byte = bit >> 3;
        int src_bit = bit & 7;
        int bitval = (b[src_byte] >> (7-src_bit)) & 1;
        int dst = PBOX_INV[bit];
        int dst_byte = dst >> 3;
        int dst_bit = dst & 7;
        out[dst_byte] |= (bitval << (7-dst_bit));
    }
    memcpy(b, out, 8);
}

/* XOR round key (8 bytes) into state */
static void add_round_key(uint8_t s[8], const uint8_t rk[8]){
    for(int i=0;i<8;i++) s[i] ^= rk[i];
}

/* Encryption */
void cspn64_encrypt(const uint8_t plaintext[8], uint8_t ciphertext[8], const uint8_t masterkey[16]){
    uint8_t state[8];
    uint8_t rk[ROUNDS][8];
    memcpy(state, plaintext, 8);
    round_key(masterkey, rk);
    for(int r=0;r<ROUNDS-1;r++){
        sub_nibble(state);
        add_round_key(state, rk[r]);
        pbox(state);
    }
    /* final round */
    sub_nibble(state);
    add_round_key(state, rk[ROUNDS-1]);
    memcpy(ciphertext, state, 8);
}

/* Decryption */
void cspn64_decrypt(const uint8_t ciphertext[8], uint8_t plaintext[8], const uint8_t masterkey[16]){
    uint8_t state[8];
    uint8_t rk[ROUNDS][8];
    memcpy(state, ciphertext, 8);
    round_key(masterkey, rk);
    /* inverse final round */
    add_round_key(state, rk[ROUNDS-1]);
    sub_nibble_inv(state);
    for(int r=ROUNDS-2; r>=0; r--){
        pbox_inv(state);
        add_round_key(state, rk[r]);
        sub_nibble_inv(state);
    }
    memcpy(plaintext, state, 8);
}

/* Build PBOX inverse table */
static void build_pbox_inv(){
    for(int i=0;i<64;i++) PBOX_INV[PBOX[i]] = i;
}

/* simple hex print */
static void print_hex(const uint8_t *d, int n){
    for(int i=0;i<n;i++) printf("%02X", d[i]);
    printf("\n");
}

/* Test harness */
int main(void){
    build_pbox_inv();
    uint8_t key[16] = {
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
        0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF
    };
    uint8_t pt[8] = {0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF};
    uint8_t ct[8], rec[8];
    cspn64_encrypt(pt, ct, key);
    cspn64_decrypt(ct, rec, key);

    printf("CSPN-64 test\nPlain : "); print_hex(pt,8);
    printf("Cipher: "); print_hex(ct,8);
    printf("Decrypt: "); print_hex(rec,8);
    return 0;
}
