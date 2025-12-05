# Quick Classification Reference

## Key/Nonce Size → Algorithm Mapping

| Size | Likely Algorithms | Ruled Out |
|------|------------------|-----------|
| ≤ 8 bytes | XOR-based, PRNG, Custom cipher, Toy Feistel | **AES, ChaCha20, RSA, Modern crypto** |
| 16 bytes | AES-128, MD5 hash (not encryption) | ChaCha20 (needs 32 bytes) |
| 24 bytes | AES-192 | - |
| 32 bytes | AES-256, ChaCha20 (+ 12-byte nonce), SHA-256 hash | - |
| > 64 bytes | RSA/ECC candidates | Simple ciphers |

## I/O Pattern → Cipher Type

| Pattern | Indicates | Examples |
|---------|-----------|----------|
| `len(output) == len(input)` | Stream cipher or XOR | XOR, ChaCha20, RC4, Custom PRNG |
| `len(output) > len(input)` | Block cipher with padding | AES-CBC, DES |
| `len(output) >> len(input)` | Asymmetric encryption | RSA, ECC |
| Repeating XOR pattern | Weak XOR cipher | Simple XOR with short key |
| 16-byte blocks | AES-like | AES (ECB, CBC, etc.) |
| 8-byte blocks | DES-like | DES, 3DES, Blowfish |

## Decision Tree

```
START: Analyze binary
│
├─→ getrandom(8 bytes)?
│   ├─ YES → ⚠️ PROPRIETARY cipher (key too small)
│   └─ NO → Continue analysis
│
├─→ Known crypto constants found?
│   ├─ YES (AES S-box) → Likely AES
│   ├─ YES (ChaCha) → Likely ChaCha20
│   └─ NO → Likely PROPRIETARY
│
├─→ Input/Output same length?
│   ├─ YES + No padding → Stream/XOR cipher
│   └─ NO + Blocks → Block cipher
│
└─→ XOR pattern detected?
    ├─ YES → ⚠️ PROPRIETARY: XOR-based
    └─ NO → Further analysis needed
```

## Standard Algorithm Requirements

### AES
- ✓ **Key size**: 16, 24, or 32 bytes
- ✓ **Constants**: S-box table (256 bytes)
- ✓ **Rounds**: 10, 12, or 14 rounds
- ✓ **Block size**: 16 bytes
- ✓ **Operations**: SubBytes, ShiftRows, MixColumns, AddRoundKey

### ChaCha20
- ✓ **Key size**: 32 bytes
- ✓ **Nonce**: 12 bytes
- ✓ **Constants**: "expand 32-byte k"
- ✓ **Rounds**: 20 rounds (double rounds)
- ✓ **Operations**: ARX (Add, Rotate, XOR)

### RSA
- ✓ **Key size**: ≥ 2048 bits (256 bytes)
- ✓ **Operations**: Modular exponentiation
- ✓ **Syscalls**: Heavy memory allocation
- ✓ **Pattern**: Output >> input (encryption)

### DES/3DES
- ✓ **Key size**: 8 bytes (DES), 24 bytes (3DES)
- ✓ **Block size**: 8 bytes
- ✓ **Rounds**: 16 Feistel rounds
- ✓ **Constants**: P-boxes, S-boxes

## Proprietary Indicators

### High Confidence (3+ indicators)
- ⚠️ Key/nonce ≤ 8 bytes
- ⚠️ No known constants
- ⚠️ XOR-heavy operations
- ⚠️ Few rounds (< 5)
- ⚠️ No block alignment

### Medium Confidence (1-2 indicators)
- ~ Small key but has some constants
- ~ Custom constants (not in database)
- ~ Unusual round count

### Classification Types
1. **XOR-based**: Repeating XOR pattern, small key
2. **PRNG-based**: Small seed, generates keystream
3. **Toy Feistel**: Few rounds, simple operations
4. **Custom SPN**: Substitution-permutation, non-standard

## Example Classifications

### Case 1: Standard AES
```
✓ getrandom(16 bytes)     → AES-128 key size
✓ AES S-box detected      → Known constants
✓ 10 crypto loops         → 10 rounds (AES-128)
✓ 16-byte blocks          → Block cipher

VERDICT: STANDARD: AES-128 (HIGH confidence)
```

### Case 2: XOR Cipher
```
⚠️ getrandom(8 bytes)     → Too small for standard
⚠️ No constants found     → Not standard algorithm
⚠️ Same length I/O        → Stream cipher pattern
⚠️ XOR pattern detected   → Simple XOR

VERDICT: PROPRIETARY: XOR-based cipher (HIGH confidence)
Rules out: AES, ChaCha20, RSA, DES
```

### Case 3: PRNG Stream Cipher
```
⚠️ getrandom(8 bytes)     → Small seed
⚠️ No constants           → Custom algorithm
✓ High entropy output     → Good diffusion
~ 3 crypto loops          → Simple rounds

VERDICT: PROPRIETARY: PRNG-based stream cipher (MEDIUM confidence)
```

## Command Examples

```bash
# Analyze binary with full classification
python3 verify_crypto.py test_binary

# Expected output:
# [SYSCALL] getrandom() called: 8 bytes
#           Likely: XOR-based cipher (8-byte key)
#
# PRIMARY CLASSIFICATION: PROPRIETARY: XOR-based cipher
# Confidence: HIGH
#
# Algorithms RULED OUT:
#   ❌ AES (needs 16/24/32-byte key)
#   ❌ ChaCha20 (needs 32-byte key + 12-byte nonce)
```

## Security Implications

### Standard Algorithms
- ✅ **Well-studied**: Extensive cryptanalysis
- ✅ **Proven security**: If implemented correctly
- ✅ **Industry standard**: Widely accepted
- ⚠️ **Implementation matters**: Side-channels, padding oracles

### Proprietary Algorithms
- ❌ **Unknown security**: Not peer-reviewed
- ❌ **Likely weak**: Custom crypto usually broken
- ❌ **XOR-based**: Extremely weak (known plaintext attack)
- ❌ **PRNG-based**: Predictable if seed is known

### Recommendations
- **Found PROPRIETARY** → Replace with AES-256-GCM or ChaCha20-Poly1305
- **Found weak key** → Increase to 128/256 bits minimum
- **Found XOR** → Critical vulnerability, fix immediately
