#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// ECC Implementation using secp256k1-like curve (simplified)
// y^2 = x^3 + ax + b (mod p)

typedef struct {
    uint64_t x;
    uint64_t y;
    int is_infinity;
} ECPoint;

typedef struct {
    uint64_t p;  // Prime modulus
    uint64_t a;  // Curve parameter a
    uint64_t b;  // Curve parameter b
    ECPoint G;   // Generator point
    uint64_t n;  // Order of G
} ECCurve;

// Modular arithmetic helper
uint64_t mod_add(uint64_t a, uint64_t b, uint64_t mod) {
    return ((a % mod) + (b % mod)) % mod;
}

uint64_t mod_sub(uint64_t a, uint64_t b, uint64_t mod) {
    return ((a % mod) - (b % mod) + mod) % mod;
}

uint64_t mod_mul(uint64_t a, uint64_t b, uint64_t mod) {
    return ((a % mod) * (b % mod)) % mod;
}

// Extended Euclidean Algorithm for modular inverse
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

uint64_t mod_inverse(uint64_t a, uint64_t m) {
    int64_t x, y;
    extended_gcd(a, m, &x, &y);
    return (x % m + m) % m;
}

// Modular exponentiation
uint64_t mod_pow(uint64_t base, uint64_t exp, uint64_t mod) {
    uint64_t result = 1;
    base = base % mod;
    
    while (exp > 0) {
        if (exp % 2 == 1) {
            result = mod_mul(result, base, mod);
        }
        exp = exp >> 1;
        base = mod_mul(base, base, mod);
    }
    
    return result;
}

// Initialize curve (simplified parameters for demonstration)
ECCurve ec_init_curve() {
    ECCurve curve;
    curve.p = 223;  // Small prime for demonstration
    curve.a = 0;
    curve.b = 7;    // y^2 = x^3 + 7 (mod 223)
    
    // Generator point
    curve.G.x = 47;
    curve.G.y = 71;
    curve.G.is_infinity = 0;
    
    curve.n = 223; // Order (simplified)
    
    return curve;
}

// Point doubling: 2P
ECPoint ec_point_double(ECPoint P, ECCurve curve) {
    ECPoint R;
    
    if (P.is_infinity || P.y == 0) {
        R.is_infinity = 1;
        return R;
    }
    
    // Lambda = (3x^2 + a) / (2y)
    uint64_t numerator = mod_add(mod_mul(3, mod_mul(P.x, P.x, curve.p), curve.p), curve.a, curve.p);
    uint64_t denominator = mod_mul(2, P.y, curve.p);
    uint64_t lambda = mod_mul(numerator, mod_inverse(denominator, curve.p), curve.p);
    
    // x_r = lambda^2 - 2x
    R.x = mod_sub(mod_mul(lambda, lambda, curve.p), mod_mul(2, P.x, curve.p), curve.p);
    
    // y_r = lambda(x - x_r) - y
    R.y = mod_sub(mod_mul(lambda, mod_sub(P.x, R.x, curve.p), curve.p), P.y, curve.p);
    
    R.is_infinity = 0;
    
    return R;
}

// Point addition: P + Q
ECPoint ec_point_add(ECPoint P, ECPoint Q, ECCurve curve) {
    ECPoint R;
    
    if (P.is_infinity) return Q;
    if (Q.is_infinity) return P;
    
    // If same point, use doubling
    if (P.x == Q.x && P.y == Q.y) {
        return ec_point_double(P, curve);
    }
    
    // If x coordinates same but y different, result is point at infinity
    if (P.x == Q.x) {
        R.is_infinity = 1;
        return R;
    }
    
    // Lambda = (y_q - y_p) / (x_q - x_p)
    uint64_t numerator = mod_sub(Q.y, P.y, curve.p);
    uint64_t denominator = mod_sub(Q.x, P.x, curve.p);
    uint64_t lambda = mod_mul(numerator, mod_inverse(denominator, curve.p), curve.p);
    
    // x_r = lambda^2 - x_p - x_q
    R.x = mod_sub(mod_sub(mod_mul(lambda, lambda, curve.p), P.x, curve.p), Q.x, curve.p);
    
    // y_r = lambda(x_p - x_r) - y_p
    R.y = mod_sub(mod_mul(lambda, mod_sub(P.x, R.x, curve.p), curve.p), P.y, curve.p);
    
    R.is_infinity = 0;
    
    return R;
}

// Scalar multiplication: k*P (double-and-add algorithm)
ECPoint ec_scalar_mult(uint64_t k, ECPoint P, ECCurve curve) {
    ECPoint result;
    result.is_infinity = 1;
    
    ECPoint temp = P;
    
    while (k > 0) {
        if (k & 1) {
            result = ec_point_add(result, temp, curve);
        }
        temp = ec_point_double(temp, curve);
        k >>= 1;
    }
    
    return result;
}

// ECDH Key Exchange
typedef struct {
    uint64_t private_key;
    ECPoint public_key;
} ECDHKeyPair;

ECDHKeyPair ecdh_generate_keypair(ECCurve curve) {
    ECDHKeyPair keypair;
    
    // Generate random private key (1 to n-1)
    keypair.private_key = 1 + (rand() % (curve.n - 1));
    
    // Public key = private_key * G
    keypair.public_key = ec_scalar_mult(keypair.private_key, curve.G, curve);
    
    return keypair;
}

ECPoint ecdh_compute_shared_secret(uint64_t private_key, ECPoint public_key, ECCurve curve) {
    return ec_scalar_mult(private_key, public_key, curve);
}

// ECDSA Signature
typedef struct {
    uint64_t r;
    uint64_t s;
} ECDSASignature;

ECDSASignature ecdsa_sign(uint64_t message_hash, uint64_t private_key, ECCurve curve) {
    ECDSASignature sig;
    
    // Generate random k
    uint64_t k = 1 + (rand() % (curve.n - 1));
    
    // R = k*G
    ECPoint R = ec_scalar_mult(k, curve.G, curve);
    sig.r = R.x % curve.n;
    
    // s = k^(-1) * (hash + r * private_key) mod n
    uint64_t k_inv = mod_inverse(k, curve.n);
    uint64_t temp = mod_add(message_hash, mod_mul(sig.r, private_key, curve.n), curve.n);
    sig.s = mod_mul(k_inv, temp, curve.n);
    
    return sig;
}

int ecdsa_verify(uint64_t message_hash, ECDSASignature sig, ECPoint public_key, ECCurve curve) {
    if (sig.r == 0 || sig.r >= curve.n || sig.s == 0 || sig.s >= curve.n) {
        return 0;
    }
    
    // w = s^(-1) mod n
    uint64_t w = mod_inverse(sig.s, curve.n);
    
    // u1 = hash * w mod n
    uint64_t u1 = mod_mul(message_hash, w, curve.n);
    
    // u2 = r * w mod n
    uint64_t u2 = mod_mul(sig.r, w, curve.n);
    
    // P = u1*G + u2*public_key
    ECPoint P1 = ec_scalar_mult(u1, curve.G, curve);
    ECPoint P2 = ec_scalar_mult(u2, public_key, curve);
    ECPoint P = ec_point_add(P1, P2, curve);
    
    // Verify r == P.x mod n
    return (sig.r == (P.x % curve.n));
}

int main() {
    srand(54321);
    
    // Initialize curve
    ECCurve curve = ec_init_curve();
    printf("ECC Curve initialized (y^2 = x^3 + %llux + %llu mod %llu)\n", 
           curve.a, curve.b, curve.p);
    printf("Generator G = (%llu, %llu)\n\n", curve.G.x, curve.G.y);
    
    // ECDH Key Exchange Example
    printf("=== ECDH Key Exchange ===\n");
    ECDHKeyPair alice = ecdh_generate_keypair(curve);
    ECDHKeyPair bob = ecdh_generate_keypair(curve);
    
    printf("Alice private: %llu, public: (%llu, %llu)\n", 
           alice.private_key, alice.public_key.x, alice.public_key.y);
    printf("Bob private: %llu, public: (%llu, %llu)\n", 
           bob.private_key, bob.public_key.x, bob.public_key.y);
    
    ECPoint alice_shared = ecdh_compute_shared_secret(alice.private_key, bob.public_key, curve);
    ECPoint bob_shared = ecdh_compute_shared_secret(bob.private_key, alice.public_key, curve);
    
    printf("Alice shared secret: (%llu, %llu)\n", alice_shared.x, alice_shared.y);
    printf("Bob shared secret: (%llu, %llu)\n", bob_shared.x, bob_shared.y);
    printf("Match: %s\n\n", (alice_shared.x == bob_shared.x && alice_shared.y == bob_shared.y) ? "YES" : "NO");
    
    // ECDSA Signature Example
    printf("=== ECDSA Signature ===\n");
    uint64_t message_hash = 123456;
    ECDSASignature sig = ecdsa_sign(message_hash, alice.private_key, curve);
    
    printf("Message hash: %llu\n", message_hash);
    printf("Signature: (r=%llu, s=%llu)\n", sig.r, sig.s);
    
    int valid = ecdsa_verify(message_hash, sig, alice.public_key, curve);
    printf("Signature valid: %s\n", valid ? "YES" : "NO");
    
    return 0;
}