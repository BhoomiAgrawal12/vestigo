#!/usr/bin/env python3
import json
import sys
import math
from collections import Counter

class CryptoDetector:
    def __init__(self):
        self.stats = {
            "total_instructions": 0,
            "phases": Counter(),
            "mnemonics": Counter(),
            "registers": Counter(),
            "memory_accesses": 0
        }
        self.window_size = 50
        self.history = []

    def entropy(self, data):
        if not data: return 0
        counts = Counter(data)
        total = len(data)
        return -sum((c/total) * math.log2(c/total) for c in counts.values())

    def analyze_window(self, window):
        """
        Micro-analysis of a 50-instruction window
        """
        mnems = [w['mnemonic'] for w in window]
        
        # 1. Structure Detection
        xors = mnems.count('xor') + mnems.count('pxor')
        shifts = sum(1 for m in mnems if m.startswith('sh') or m.startswith('ro'))
        math_ops = sum(1 for m in mnems if m in ['add', 'sub', 'mul', 'imul'])
        
        # 2. Heuristic Scoring
        is_crypto = False
        reason = ""
        
        # Rule A: High Bitwise Mixing (Block Cipher)
        if xors > 5 and shifts > 5:
            is_crypto = True
            reason = "High Bitwise Mixing (SPN/Block Cipher)"
            
        # Rule B: High Math Density (BigInt / Public Key)
        elif math_ops > 15:
            is_crypto = True
            reason = "High Arithmetic Density (BigInt/Key Exchange)"
            
        return is_crypto, reason

    def process_trace(self, filename):
        print(f"[*] Analyzing trace: {filename}...")
        
        with open(filename, 'r') as f:
            for line in f:
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                
                self.stats["total_instructions"] += 1
                self.stats["phases"][event.get("phase", "unknown")] += 1
                self.stats["mnemonics"][event.get("mnemonic")] += 1
                
                # Add to history window
                self.history.append(event)
                if len(self.history) > self.window_size:
                    self.history.pop(0)
                    
                # Analyze sliding window
                if len(self.history) == self.window_size:
                    is_crypto, reason = self.analyze_window(self.history)
                    if is_crypto:
                        start_addr = self.history[0]['address']
                        print(f"[!] CRYPTO PATTERN DETECTED at {start_addr}: {reason}")
                        # Don't spam: Skip forward a bit or just flag it
                        self.history = [] # Reset window to avoid duplicate alerts

        self.print_summary()

    def print_summary(self):
        print("\n=== Analysis Summary ===")
        print(f"Total Instructions: {self.stats['total_instructions']}")
        print("Phases Seen:")
        for p, c in self.stats['phases'].items():
            print(f"  - {p}: {c}")
        
        print("\nTop Mnemonics:")
        for m, c in self.stats['mnemonics'].most_common(5):
            print(f"  - {m}: {c}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 analyze_trace.py <trace.jsonl>")
        sys.exit(1)
    
    detector = CryptoDetector()
    detector.process_trace(sys.argv[1])
