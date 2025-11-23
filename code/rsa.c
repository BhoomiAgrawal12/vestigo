#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// RSA Implementation with 64-bit integers (simplified for demonstration)
// For production, use larger bit sizes with libraries like GMP

typedef unsigned long long uint64;

// Modular exponentiation: (base^exp) % mod
uint64 mod_exp(uint64 base, uint64 exp, uint64 mod) {
    uint64 result = 1;
    base = base % mod;
    
    while (exp > 0) {
        if (exp % 2 == 1) {
            result = (result * base) % mod;
        }
        exp = exp >> 1;
        base = (base * base) % mod;
    }
    
    return result;
}

// Extended Euclidean Algorithm
int64_t extended_gcd(int64_t a, int64_t b, int64_t *x, int64_t *y) {
    if (a == 0) {
        *x = 0;
        *y = 1;
        return b;
    }
    
    int64_t x1, y1;
    int64_t gcd = extended_gcd(b % a, a, &x1, &y1);
    
    *x = y1 - (b / a) * x1;
    *y = x1;
    
    return gcd;
}

// Compute modular multiplicative inverse
uint64 mod_inverse(uint64 a, uint64 m) {
    int64_t x, y;
    int64_t g = extended_gcd(a, m, &x, &y);
    
    if (g != 1) {
        return 0; // Inverse doesn't exist
    }
    
    return (x % m + m) % m;
}

// Simple primality test (Miller-Rabin would be better for production)
int is_prime(uint64 n, int k) {
    if (n <= 1 || n == 4) return 0;
    if (n <= 3) return 1;
    
    for (int i = 0; i < k; i++) {
        uint64 a = 2 + rand() % (n - 3);
        if (mod_exp(a, n - 1, n) != 1) {
            return 0;
        }
    }
    
    return 1;
}

// Generate a random prime (simplified)
uint64 generate_prime(uint64 min, uint64 max) {
    uint64 candidate;
    do {
        candidate = min + rand() % (max - min);
        if (candidate % 2 == 0) candidate++;
    } while (!is_prime(candidate, 5));
    
    return candidate;
}

typedef struct {
    uint64 e; // Public exponent
    uint64 n; // Modulus
} RSA_PublicKey;

typedef struct {
    uint64 d; // Private exponent
    uint64 n; // Modulus
} RSA_PrivateKey;

typedef struct {
    RSA_PublicKey public_key;
    RSA_PrivateKey private_key;
} RSA_KeyPair;

// Generate RSA key pair
RSA_KeyPair rsa_generate_keypair() {
    RSA_KeyPair keypair;
    
    // Generate two distinct primes
    uint64 p = generate_prime(1000, 5000);
    uint64 q = generate_prime(5000, 10000);
    
    // Ensure p != q
    while (p == q) {
        q = generate_prime(5000, 10000);
    }
    
    // Calculate n = p * q
    uint64 n = p * q;
    
    // Calculate Euler's totient: φ(n) = (p-1)(q-1)
    uint64 phi = (p - 1) * (q - 1);
    
    // Choose public exponent e (commonly 65537)
    uint64 e = 65537;
    
    // Ensure e < phi and gcd(e, phi) = 1
    while (e < phi) {
        int64_t x, y;
        if (extended_gcd(e, phi, &x, &y) == 1) {
            break;
        }
        e += 2;
    }
    
    // Calculate private exponent d = e^(-1) mod φ(n)
    uint64 d = mod_inverse(e, phi);
    
    // Set up keypair
    keypair.public_key.e = e;
    keypair.public_key.n = n;
    keypair.private_key.d = d;
    keypair.private_key.n = n;
    
    printf("RSA Key Generation:\n");
    printf("  p = %llu\n", p);
    printf("  q = %llu\n", q);
    printf("  n = %llu\n", n);
    printf("  phi(n) = %llu\n", phi);
    printf("  e = %llu\n", e);
    printf("  d = %llu\n", d);
    
    return keypair;
}

// RSA Encryption: ciphertext = plaintext^e mod n
uint64 rsa_encrypt(uint64 plaintext, RSA_PublicKey public_key) {
    return mod_exp(plaintext, public_key.e, public_key.n);
}

// RSA Decryption: plaintext = ciphertext^d mod n
uint64 rsa_decrypt(uint64 ciphertext, RSA_PrivateKey private_key) {
    return mod_exp(ciphertext, private_key.d, private_key.n);
}

// RSA Signature: signature = hash^d mod n
uint64 rsa_sign(uint64 message_hash, RSA_PrivateKey private_key) {
    return mod_exp(message_hash, private_key.d, private_key.n);
}

// RSA Verify: check if hash == signature^e mod n
int rsa_verify(uint64 message_hash, uint64 signature, RSA_PublicKey public_key) {
    uint64 decrypted = mod_exp(signature, public_key.e, public_key.n);
    return decrypted == message_hash;
}

int main() {
    srand(12345); // Fixed seed for reproducibility
    
    // Generate RSA keypair
    RSA_KeyPair keypair = rsa_generate_keypair();
    
    // Test encryption/decryption
    uint64 message = 42424242;
    printf("\nOriginal message: %llu\n", message);
    
    uint64 encrypted = rsa_encrypt(message, keypair.public_key);
    printf("Encrypted: %llu\n", encrypted);
    
    uint64 decrypted = rsa_decrypt(encrypted, keypair.private_key);
    printf("Decrypted: %llu\n", decrypted);
    
    // Test signing/verification
    uint64 msg_hash = 999999;
    uint64 signature = rsa_sign(msg_hash, keypair.private_key);
    printf("\nMessage hash: %llu\n", msg_hash);
    printf("Signature: %llu\n", signature);
    
    int valid = rsa_verify(msg_hash, signature, keypair.public_key);
    printf("Signature valid: %s\n", valid ? "YES" : "NO");
    
    return 0;
}