# Crypto Algorithm Classification Methodology

## Overview
The enhanced `verify_crypto.py` (v4.0) now implements a sophisticated multi-phase detection and classification system that can distinguish between **standard cryptographic algorithms** (AES, ChaCha20, RSA, etc.) and **proprietary/custom ciphers** (XOR-based, PRNG-based, toy ciphers).

## Detection Phases

### Phase 0: YARA Static Analysis
- **Speed**: < 1 second
- **Works on**: Stripped binaries, obfuscated code
- **Detection**: Pattern matching for known crypto signatures

### Phase 1: Syscall Monitoring ⭐ NEW
- **Critical Feature**: Hooks `getrandom()` and `/dev/random` reads
- **Key Detection**: Analyzes size of random data requests
- **Classification**: 
  - **8 bytes (64 bits)** → ⚠️ TOO SMALL for standard crypto
    - Likely: XOR-based, PRNG-based, custom cipher
    - Rules out: AES, ChaCha20, RSA, DES
  - **16 bytes** → Possible AES-128
  - **32 bytes** → Possible AES-256 or ChaCha20

### Phase 2: Constant Detection (FindCrypt)
- Scans for known crypto constants (S-boxes, round constants, etc.)
- Presence = likely standard algorithm
- Absence = likely proprietary/custom

### Phase 3: Pattern Analysis
- **I/O Pattern Detection**:
  - Same length input/output → Stream cipher
  - Repeating XOR pattern → XOR-based cipher
  - Block alignment (16-byte) → AES-like
  - No alignment → Custom/stream cipher

### Phase 4: Algorithm Classification
Comprehensive analysis combining all evidence to produce:
- Primary classification (STANDARD vs PROPRIETARY)
- Confidence score (0-100)
- Evidence list
- Ruled-out algorithms

## Classification Logic

### Standard Algorithm Detection
Score based on:
- ✓ Known constants detected (40 pts)
- ✓ Appropriate key/nonce size (30 pts)
- ✓ Multiple crypto rounds/loops (20 pts)
- ✓ Strong function names (30 pts)

**Score ≥ 70** → HIGH confidence standard crypto

### Proprietary Cipher Detection
Indicators:
- ⚠️ Small key/nonce (≤ 8 bytes)
- ⚠️ No known constants
- ⚠️ XOR patterns in I/O
- ⚠️ Few crypto loops
- ⚠️ Output length == input length (no padding)

**3+ indicators** → HIGH confidence proprietary

## Example: Analyzing Your Trace

```
getrandom("\x6b\x8f\xbc\xed\x31\x93\xaf\x47", 8, GRND_NONBLOCK)
Original: 50 52 4f 50 52 49 45 5 ...
Encrypted: fd 9a 8b 10 16 f5 28 ...
```

### Analysis:
1. **Syscall**: 8-byte random key → ⚠️ Too small for AES/ChaCha20
2. **Pattern**: Length(output) == length(input) → Stream cipher
3. **No constants**: No AES S-box, ChaCha constants detected
4. **Conclusion**: PROPRIETARY cipher (likely XOR-based or PRNG)

### Ruled Out:
- ❌ **AES**: Needs 16/24/32-byte key
- ❌ **ChaCha20**: Needs 32-byte key + 12-byte nonce
- ❌ **RSA/ECC**: No multiprecision operations
- ❌ **SHA/MD5**: Hash functions, not encryption
- ❌ **DES/3DES**: Still needs proper key schedule

### Likely Classification:
**PROPRIETARY: XOR-based or PRNG stream cipher**

## Output Format

```
======================================================================
   ALGORITHM CLASSIFICATION REPORT
======================================================================

[*] PRIMARY CLASSIFICATION: PROPRIETARY: XOR-based cipher
    Confidence: HIGH

[*] Proprietary/Custom Cipher Indicators:
      ⚠ Small random key/nonce (8 bytes) - too small for standard crypto
      ⚠ No known crypto constants detected
      ⚠ Output length == input length (stream cipher pattern)
      ⚠ XOR-based cipher detected

[*] Algorithms RULED OUT:
      ❌ AES (needs 16/24/32-byte key)
      ❌ ChaCha20 (needs 32-byte key + 12-byte nonce)
      ❌ DES/3DES (needs proper key schedule, not just 8 bytes)
      ❌ RSA/ECC (needs much larger keys)

[*] Analysis Summary:
      → Binary uses CUSTOM/PROPRIETARY cipher
      → ⚠ Custom crypto is often WEAK and vulnerable
      → Recommend replacing with standard algorithms (AES, ChaCha20)
      → ⚠ XOR-based ciphers are particularly weak
======================================================================
```

## Key Improvements

### 1. Syscall Hooking
- **Before**: Only monitored instructions
- **After**: Captures actual `getrandom()` calls
- **Benefit**: Immediate detection of key/nonce sizes

### 2. Evidence-Based Classification
- **Before**: Simple heuristics
- **After**: Multi-factor scoring system
- **Benefit**: Higher accuracy, fewer false positives

### 3. Explicit Ruling Out
- **Before**: Only reported what was found
- **After**: Lists what algorithms are impossible
- **Benefit**: Clearer conclusions

### 4. Security Recommendations
- **Before**: Generic "crypto detected"
- **After**: Specific warnings about custom crypto weaknesses
- **Benefit**: Actionable security guidance

## Usage

```bash
# Analyze any binary
python3 verify_crypto.py /path/to/binary

# The script will:
# 1. Detect packer (if any) and unpack
# 2. Run YARA static analysis
# 3. Scan for crypto constants
# 4. Hook syscalls (getrandom, read)
# 5. Monitor execution with basic block profiling
# 6. Classify algorithm (STANDARD vs PROPRIETARY)
# 7. Generate detailed report
```

## Technical Details

### Syscall Hook Implementation
```python
def syscall_getrandom(ql, buf, buflen, flags):
    random_data = os.urandom(buflen)
    ql.mem.write(buf, random_data)
    
    # Classify based on size
    likely, ruled_out = classify_by_key_size(buflen)
    
    if buflen <= 8:
        # TOO SMALL for standard crypto
        report['proprietary_likely'] = True
        report['ruled_out'].extend(['AES', 'ChaCha20', 'RSA'])
```

### Pattern Detection
```python
def detect_cipher_patterns(input_data, output_data):
    patterns = []
    
    # Same length = stream cipher or XOR
    if len(input_data) == len(output_data):
        patterns.append("SAME_LENGTH")
    
    # Check for XOR with repeating key
    xor_result = [a ^ b for a, b in zip(input_data, output_data)]
    if get_entropy(xor_result) < 1.5:  # Low entropy = repeating
        patterns.append("REPEATING_XOR_KEY")
    
    return patterns
```

## Conclusion

The enhanced script now provides **forensic-level analysis** that can:
- ✓ Detect both standard and proprietary crypto
- ✓ Distinguish between algorithm types
- ✓ Provide evidence-based classifications
- ✓ Rule out impossible algorithms
- ✓ Offer security recommendations

This methodology matches real-world crypto analysis workflows used by security researchers and reverse engineers.
