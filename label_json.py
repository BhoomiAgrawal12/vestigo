import os
import json
import re
import sys
import math
import argparse

# --- Configuration ---
YARA_FILE = "qiling_analysis/tests/crypto.yar"
JSON_DIR = "filtered_json"
NEGATIVE_DIR = os.path.join(JSON_DIR, "negative")

# --- YARA & Helper Functions ---

def parse_yara_rules(yara_path):
    rules = []
    try:
        with open(yara_path, 'r') as f: content = f.read()
        content = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)
        content = re.sub(r'//.*', '', content)
        pos = 0
        while True:
            match = re.search(r'\brule\s+(\w+)\s*\{', content[pos:])
            if not match: break
            rule_name = match.group(1)
            start_brace = pos + match.end() - 1 
            brace_count = 1
            i = start_brace + 1
            while i < len(content) and brace_count > 0:
                if content[i] == '{': brace_count += 1
                elif content[i] == '}': brace_count -= 1
                i += 1
            if brace_count == 0:
                rule_body = content[start_brace + 1: i - 1]
                pos = i 
                algo_match = re.search(r'algorithm\s*=\s*"(.*?)"', rule_body)
                algorithm = algo_match.group(1) if algo_match else rule_name
                signatures = []
                hex_str_pattern = re.compile(r'\$\w+\s*=\s*\{(.*?)\}', re.DOTALL)
                for hex_match in hex_str_pattern.finditer(rule_body):
                    hex_content = hex_match.group(1)
                    hex_bytes = [int(b, 16) for b in hex_content.split() if re.match(r'^[0-9a-fA-F]{2}$', b)]
                    if hex_bytes: signatures.append(hex_bytes)
                text_str_pattern = re.compile(r'\$\w+\s*=\s*"(.*?)"')
                for text_match in text_str_pattern.finditer(rule_body):
                    signatures.append([ord(c) for c in text_match.group(1)])
                if signatures: rules.append({'name': rule_name, 'algorithm': algorithm, 'signatures': signatures})
            else: break
    except Exception: pass
    return rules

def check_yara_match(immediates, rules):
    if not immediates or not rules: return None
    try: imm_bytes = bytes([b for b in immediates if 0 <= b <= 255])
    except: return None
    for rule in rules:
        for sig in rule['signatures']:
            if bytes(sig) in imm_bytes: return rule['algorithm']
    return None

def infer_algo_from_name(filename, func_name):
    # Order matters: Specific > Generic
    crypto_patterns = [
        ("chacha20", "ChaCha20"), ("chacha", "ChaCha20"), ("poly1305", "Poly1305"),
        ("sha3", "SHA-3"), ("sha512", "SHA-512"), ("sha256", "SHA-256"), ("sha1", "SHA-1"),
        ("aes", "AES"), ("rijndael", "AES"), 
        ("des", "DES"), ("md5", "MD5"), ("rc4", "RC4"),
        ("hmac", "HMAC"), ("ecdsa", "ECC"), ("curve25519", "ECC")
    ]
    
    name_lower = (func_name or "").lower()
    file_lower = (filename or "").lower()

    for pattern, algo in crypto_patterns:
        if pattern in name_lower: return algo
    for pattern, algo in crypto_patterns:
        if pattern in file_lower: return algo
    
    # RSA Check - Only if strictly named
    if "rsa" in name_lower and any(x in name_lower for x in ["enc", "dec", "sign", "ver", "pkcs", "oaep", "crt"]):
        return "RSA"
        
    return None

# --- SCORING LOGIC ---

def get_structural_score(func):
    score = 0.0
    reasons = []

    op_counts = func.get("op_category_counts", {})
    bitwise_ops = op_counts.get("bitwise_ops", 0)
    total_ops = sum(op_counts.values()) if op_counts else 0
    entropy = func.get("entropy_metrics", {}).get("function_byte_entropy", 0.0)

    # 1. Bitwise Density
    if total_ops > 15:
        density = bitwise_ops / total_ops
        if density > 0.30:
            score += 35.0
            reasons.append(f"Very High bitwise density ({density:.2f})")
        elif density > 0.15:
            score += 15.0
            reasons.append(f"Moderate bitwise density ({density:.2f})")

    # 2. Entropy
    if entropy > 6.4:
        score += 30.0
        reasons.append(f"High Code Entropy ({entropy:.2f})")
    
    return score, reasons, entropy

def get_signature_score(func, yara_algo, name_hint, entropy):
    score = 0.0
    reasons = []
    hint = None

    sigs = func.get("crypto_signatures", {})
    
    # --- AES SIGNALS ---
    # Only trust AES S-box if we aren't already sure it's ChaCha/Poly/Something else
    # ChaCha uses 0x00-0xFF constants that often collide with S-box checks.
    if sigs.get("has_aes_sbox") or any(n.get("constant_flags", {}).get("AES_SBOX_BYTES") for n in func.get("node_level", [])):
        if name_hint and name_hint not in ["AES", "Unknown", None]:
            # Ignoring AES signal because name strongly says otherwise
            reasons.append(f"Ignored AES collision in {name_hint} function")
        else:
            score += 50.0
            reasons.append("AES S-Box identified")
            hint = "AES"

    # --- SHA SIGNALS ---
    if sigs.get("has_sha_constants"):
        score += 60.0
        reasons.append("SHA constants identified")
        hint = "SHA"
    
    # --- RSA / BIGINT SIGNALS ---
    if sigs.get("rsa_bigint_detected"):
        # Poly1305 and RSA both use BigInt. How to distinguish?
        # 1. Name: If name is 'poly1305', it's Poly.
        # 2. Entropy: RSA keys have high entropy (>6.0). Poly1305 code/math has lower entropy (<5.5).
        
        if name_hint == "Poly1305" or name_hint == "ChaCha20":
            # It's BigInt because it's Poly1305
            reasons.append("BigInt arithmetic (Poly1305 context)")
            # Do NOT set hint to RSA
        elif entropy < 5.8:
            # Low entropy BigInt -> Generic Math or Stream Cipher MAC
            reasons.append("BigInt detected but low entropy (Generic Math/Poly1305)")
            score -= 10.0 # Reduce score to avoid false positive
        else:
            # High Entropy BigInt -> Likely RSA Key operations
            score += 30.0
            reasons.append("High-Entropy BigInt (Likely RSA)")
            hint = hint or "RSA"

    # --- YARA ---
    if yara_algo and yara_algo != "COMPRESSION":
        if name_hint and name_hint != yara_algo and name_hint != "Unknown":
             reasons.append(f"Ignored YARA {yara_algo} vs Name {name_hint}")
        else:
            score += 40.0
            reasons.append(f"YARA Match: {yara_algo}")
            hint = hint or yara_algo

    return score, reasons, hint

def classify_function(func, filename, yara_algo):
    total_score = 0.0
    all_reasons = []
    
    # 1. Name Check (Highest Priority)
    name_hint = infer_algo_from_name(filename, func.get("name", ""))
    if name_hint:
        total_score += 40.0 # Boost name score
        all_reasons.append(f"Name implies {name_hint}")

    # 2. Structure
    struct_score, struct_reasons, entropy = get_structural_score(func)
    total_score += struct_score
    all_reasons.extend(struct_reasons)

    # 3. Signatures
    sig_score, sig_reasons, sig_hint = get_signature_score(func, yara_algo, name_hint, entropy)
    total_score += sig_score
    all_reasons.extend(sig_reasons)
    
    # --- Final Logic ---
    final_score = min(100.0, total_score)
    confidence = "Low"
    label = "non-crypto"
    
    # The Decision
    detected_algo = name_hint if name_hint else sig_hint

    if detected_algo:
        if final_score >= 40.0:
            label = detected_algo
            confidence = "High" if final_score > 60 else "Medium"
        else:
            label = f"{detected_algo}-candidate"
            confidence = "Low"
    elif final_score >= 60.0:
        label = "crypto-generic"
        confidence = "Medium"
    elif "BigInt" in str(all_reasons) and final_score < 40:
        label = "math-bigint" # Generic math fallback
        confidence = "Medium"

    func["label"] = label
    func["confidence_score"] = final_score
    func["confidence_level"] = confidence
    func["detection_reasons"] = all_reasons
    
    return func

# --- Main Processing ---

def load_json_safe(file_path):
    try:
        with open(file_path, 'r') as f: return json.loads(re.sub(r',\s*([\]}])', r'\1', f.read()))
    except: return None

def process_files():
    print(f"[*] Loading YARA rules from {YARA_FILE}...")
    yara_rules = parse_yara_rules(YARA_FILE)
    
    all_files = []
    for root, _, files in os.walk(JSON_DIR):
        for f in files: 
            if f.endswith(".json"): all_files.append(os.path.join(root, f))
    
    total_files = len(all_files)
    print(f"[*] Found {total_files} files.")
    stats = {"crypto": 0, "non-crypto": 0, "math-bigint": 0}

    for i, file_path in enumerate(all_files, 1):
        pct = (i / total_files) * 100
        sys.stdout.write(f"\r[{i}/{total_files}] {pct:.1f}% | {os.path.basename(file_path)[:30]:<30}")
        sys.stdout.flush()

        is_negative = "negative" in file_path
        try:
            data = load_json_safe(file_path)
            if not data or "functions" not in data: continue

            updated = False
            for func in data["functions"]:
                if is_negative:
                    if func.get("label") != "non-crypto":
                        func["label"] = "non-crypto"
                        updated = True
                    stats["non-crypto"] += 1
                    continue

                imms = []
                for node in func.get("node_level", []): imms.extend(node.get("immediates", []))
                yara_match = check_yara_match(imms, yara_rules)
                
                old_label = func.get("label")
                func = classify_function(func, os.path.basename(file_path), yara_match)
                
                if func["label"] != old_label: updated = True
                
                if "non-crypto" in func["label"]: stats["non-crypto"] += 1
                elif "math-bigint" in func["label"]: stats["math-bigint"] += 1
                else: stats["crypto"] += 1

            if updated:
                with open(file_path, 'w') as f: json.dump(data, f, indent=4)
        except Exception: pass

    print(f"\n\n[*] Done.")
    print(f"    Crypto: {stats['crypto']}")
    print(f"    Non-Crypto: {stats['non-crypto']}")
    print(f"    Math/BigInt: {stats['math-bigint']}")

if __name__ == "__main__":
    process_files()
