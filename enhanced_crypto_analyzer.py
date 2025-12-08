#!/usr/bin/env python3
"""
Enhanced Crypto Pattern Detector
Analyzes execution traces to identify cryptographic operations
"""
import json
import sys
import math
from collections import Counter, defaultdict

class EnhancedCryptoDetector:
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.stats = {
            "total_instructions": 0,
            "phases": Counter(),
            "mnemonics": Counter(),
            "registers": Counter(),
            "memory_accesses": 0,
            "function_calls": 0,
            "loops_detected": 0
        }
        self.window_size = 50
        self.history = []
        self.crypto_candidates = []
        self.address_frequency = Counter()
        self.loop_heads = set()
        
    def entropy(self, data):
        """Calculate Shannon entropy of data"""
        if not data: return 0
        counts = Counter(data)
        total = len(data)
        return -sum((c/total) * math.log2(c/total) for c in counts.values())

    def detect_loops(self):
        """Identify potential loop structures from address frequency"""
        # Addresses visited more than 10 times are likely loop heads
        for addr, count in self.address_frequency.items():
            if count > 10:
                self.loop_heads.add(addr)
                self.stats["loops_detected"] += 1

    def analyze_window(self, window):
        """
        Micro-analysis of a 50-instruction window for crypto patterns
        """
        mnems = [w['mnemonic'] for w in window]
        addrs = [w['address'] for w in window]
        
        # 1. Bitwise Operations (Common in Block Ciphers)
        xors = mnems.count('xor') + mnems.count('pxor') + mnems.count('xorps') + mnems.count('pxord')
        ands = mnems.count('and') + mnems.count('pand')
        ors = mnems.count('or') + mnems.count('por')
        nots = mnems.count('not')
        
        # 2. Shift/Rotate Operations (Bit Mixing)
        shifts = sum(1 for m in mnems if m in ['shl', 'shr', 'sal', 'sar', 'shld', 'shrd'])
        rotates = sum(1 for m in mnems if m in ['rol', 'ror', 'rcl', 'rcr'])
        
        # 3. Arithmetic Operations (Modular Arithmetic / BigInt)
        adds = mnems.count('add') + mnems.count('adc')
        subs = mnems.count('sub') + mnems.count('sbb')
        muls = mnems.count('mul') + mnems.count('imul')
        divs = mnems.count('div') + mnems.count('idiv')
        math_ops = adds + subs + muls + divs
        
        # 4. Memory Access Patterns
        movs = sum(1 for m in mnems if 'mov' in m)
        
        # 5. SIMD Operations (Common in optimized crypto)
        simd_ops = sum(1 for m in mnems if any(x in m for x in ['xmm', 'ymm', 'zmm', 'ps', 'pd', 'ss', 'sd']))
        
        # Calculate instruction entropy (high entropy = diverse operations)
        mnem_entropy = self.entropy(mnems)
        
        # 6. Heuristic Scoring
        is_crypto = False
        reason = ""
        confidence = 0
        
        # Rule A: Strong Block Cipher Pattern (AES-like)
        if xors > 5 and shifts > 3 and mnem_entropy > 2.0:
            is_crypto = True
            reason = "Block Cipher Pattern (High XOR + Shifts + Diverse Ops)"
            confidence = min(100, (xors + shifts) * 5)
            
        # Rule B: SIMD-Optimized Crypto (Modern AES/ChaCha)
        elif simd_ops > 10 and xors > 3:
            is_crypto = True
            reason = "SIMD-Optimized Crypto (Vectorized Operations)"
            confidence = min(100, simd_ops * 8)
            
        # Rule C: High Arithmetic Density (RSA/ECC/BigInt)
        elif math_ops > 15 and mnem_entropy > 2.5:
            is_crypto = True
            reason = "Public Key Crypto / BigInt Operations"
            confidence = min(100, math_ops * 4)
            
        # Rule D: Moderate Crypto Pattern (Hash Functions)
        elif (xors + rotates + shifts) > 10 and math_ops > 5:
            is_crypto = True
            reason = "Hash Function Pattern (Mixed Bitwise + Arithmetic)"
            confidence = min(100, (xors + rotates + shifts + math_ops) * 3)
            
        # Rule E: Substitution-Permutation Network
        elif (xors + ands + ors) > 10 and shifts > 5:
            is_crypto = True
            reason = "SPN Structure (Substitution-Permutation Network)"
            confidence = min(100, (xors + ands + ors + shifts) * 3)
            
        return is_crypto, reason, confidence, {
            'xors': xors,
            'shifts': shifts,
            'rotates': rotates,
            'math_ops': math_ops,
            'simd_ops': simd_ops,
            'entropy': mnem_entropy
        }

    def process_trace(self, filename):
        print(f"[*] Analyzing trace: {filename}...")
        print(f"[*] Window size: {self.window_size} instructions")
        print(f"[*] Scanning for crypto patterns...\n")
        
        crypto_windows = []
        
        with open(filename, 'r') as f:
            for line in f:
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                
                self.stats["total_instructions"] += 1
                phase = event.get("phase", "unknown")
                self.stats["phases"][phase] += 1
                
                mnem = event.get("mnemonic", "")
                self.stats["mnemonics"][mnem] += 1
                
                addr = event.get("address", "")
                self.address_frequency[addr] += 1
                
                # Count function calls
                if mnem in ['call', 'callq']:
                    self.stats["function_calls"] += 1
                
                # Add to history window
                self.history.append(event)
                if len(self.history) > self.window_size:
                    self.history.pop(0)
                    
                # Analyze sliding window
                if len(self.history) == self.window_size:
                    is_crypto, reason, confidence, metrics = self.analyze_window(self.history)
                    if is_crypto:
                        start_addr = self.history[0]['address']
                        end_addr = self.history[-1]['address']
                        
                        crypto_windows.append({
                            'start_addr': start_addr,
                            'end_addr': end_addr,
                            'reason': reason,
                            'confidence': confidence,
                            'metrics': metrics,
                            'phase': phase
                        })
                        
                        print(f"[!] CRYPTO PATTERN DETECTED")
                        print(f"    Address Range: {start_addr} - {end_addr}")
                        print(f"    Phase: {phase}")
                        print(f"    Pattern: {reason}")
                        print(f"    Confidence: {confidence}%")
                        print(f"    Metrics: XORs={metrics['xors']}, Shifts={metrics['shifts']}, "
                              f"Rotates={metrics['rotates']}, Math={metrics['math_ops']}, "
                              f"SIMD={metrics['simd_ops']}, Entropy={metrics['entropy']:.2f}")
                        print()
                        
                        # Skip forward to avoid duplicate alerts
                        self.history = []

        # Post-processing
        self.detect_loops()
        self.print_summary(crypto_windows)
        
        return crypto_windows

    def print_summary(self, crypto_windows):
        print("\n" + "="*80)
        print("ANALYSIS SUMMARY")
        print("="*80)
        
        print(f"\n📊 EXECUTION STATISTICS:")
        print(f"  Total Instructions:    {self.stats['total_instructions']:,}")
        print(f"  Function Calls:        {self.stats['function_calls']}")
        print(f"  Loop Structures:       {self.stats['loops_detected']}")
        
        print(f"\n📍 PHASES OBSERVED:")
        for p, c in sorted(self.stats['phases'].items(), key=lambda x: -x[1]):
            print(f"  {p:20s}: {c:,} instructions ({c*100/self.stats['total_instructions']:.1f}%)")
        
        print(f"\n🔧 TOP INSTRUCTIONS:")
        for m, c in self.stats['mnemonics'].most_common(15):
            print(f"  {m:10s}: {c:5,} ({c*100/self.stats['total_instructions']:5.1f}%)")
        
        # Categorize instructions
        bitwise = sum(self.stats['mnemonics'][m] for m in ['xor', 'and', 'or', 'not', 'pxor', 'pand', 'por'])
        shifts = sum(self.stats['mnemonics'][m] for m in ['shl', 'shr', 'sal', 'sar', 'rol', 'ror'])
        arithmetic = sum(self.stats['mnemonics'][m] for m in ['add', 'sub', 'mul', 'imul', 'div', 'idiv', 'adc', 'sbb'])
        
        print(f"\n📈 INSTRUCTION CATEGORIES:")
        print(f"  Bitwise Operations:    {bitwise:,}")
        print(f"  Shift/Rotate:          {shifts:,}")
        print(f"  Arithmetic:            {arithmetic:,}")
        
        print(f"\n🔐 CRYPTO PATTERN DETECTION:")
        if crypto_windows:
            print(f"  ✅ {len(crypto_windows)} crypto pattern(s) detected!")
            print(f"\n  Detected Patterns:")
            for i, cw in enumerate(crypto_windows, 1):
                print(f"    {i}. {cw['reason']} (Confidence: {cw['confidence']}%)")
                print(f"       Range: {cw['start_addr']} - {cw['end_addr']}")
                print(f"       Phase: {cw['phase']}")
        else:
            print(f"  ❌ No crypto patterns detected in this trace.")
            print(f"\n  Possible reasons:")
            print(f"    - Trace captured only initialization code")
            print(f"    - Crypto operations occur in different phase")
            print(f"    - Need longer execution to reach crypto code")
            print(f"    - Binary uses library calls (externally linked crypto)")
        
        print("\n" + "="*80)
        
        # Provide recommendations
        self.print_recommendations(crypto_windows)

    def print_recommendations(self, crypto_windows):
        print("\n💡 RECOMMENDATIONS:")
        
        if not crypto_windows:
            print("\n  To improve detection:")
            print("  1. Ensure trace captures full execution (not just init)")
            print("  2. Inject input that triggers protocol processing")
            print("  3. Look for 'handshake' or 'key_exchange' phases")
            print("  4. Check if crypto is in external libraries (not traced)")
            print("\n  Next steps:")
            print("  • Run: python3 harness.py <binary> --verbose")
            print("  • Check for recv() or network I/O functions")
            print("  • Ensure symbolic solver generated valid input")
        else:
            print("\n  ✅ Crypto patterns detected! Next steps:")
            print("  1. Extract instructions in detected ranges for ML training")
            print("  2. Label these regions as 'crypto' in your dataset")
            print("  3. Build LSTM model on these instruction sequences")
            print("  4. Use for automated crypto identification in unknown binaries")
        
        print("\n" + "="*80 + "\n")

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 enhanced_crypto_analyzer.py <trace.jsonl> [--verbose]")
        print("\nAnalyzes execution traces to detect cryptographic operations")
        print("\nExamples:")
        print("  python3 enhanced_crypto_analyzer.py full_harness_trace.jsonl")
        print("  python3 enhanced_crypto_analyzer.py trace.jsonl --verbose")
        sys.exit(1)
    
    filename = sys.argv[1]
    verbose = '--verbose' in sys.argv
    
    detector = EnhancedCryptoDetector(verbose=verbose)
    crypto_windows = detector.process_trace(filename)
    
    # Exit with appropriate code
    sys.exit(0 if crypto_windows else 1)

if __name__ == "__main__":
    main()
