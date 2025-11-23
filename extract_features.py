# import json
# import math
# from collections import Counter

# # -----------------------------
# #  CRYPTO CONSTANT SIGNATURES
# # -----------------------------

# AES_SBOX = bytes([
#     0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
#     0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76
# ])

# AES_INVSBOX = bytes([
#     0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
#     0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb
# ])

# AES_RCON = bytes([0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80])

# DES_SBOX_FRAGMENT = bytes([0x0e, 0x04, 0x0d, 0x01])  # common in DES sboxes

# CHACHA20_CONST = b"expand 32-byte k"

# SHA256_K = [
#     0x428a2f98, 0x71374491, 0xb5c0fbcf
# ]

# MD5_T = [
#     0xd76aa478, 0xe8c7b756, 0x242070db
# ]

# SHA1_K_FRAGMENT = bytes([0x5A, 0x82, 0x79, 0x99])


# # -----------------------------
# # HELPERS
# # -----------------------------

# def contains(blob, constant):
#     return 1 if bytes(constant) in blob else 0


# def entropy(data):
#     if not data:
#         return 0
#     freq = Counter(data)
#     e = 0.0
#     for c in freq.values():
#         p = c / len(data)
#         e -= p * math.log2(p)
#     return e


# # -----------------------------
# # FEATURE EXTRACTION FUNCTION
# # -----------------------------

# def extract_features(binary_path, ghidra_json):
#     with open(binary_path, "rb") as f:
#         blob = f.read()

#     with open(ghidra_json, "r") as f:
#         gh = json.load(f)

#     features = {}

#     # -----------------------------
#     # A. BINARY SIGNATURES
#     # -----------------------------
#     features["has_aes_sbox"] = contains(blob, AES_SBOX)
#     features["has_aes_invsbox"] = contains(blob, AES_INVSBOX)
#     features["has_aes_rcon"] = contains(blob, AES_RCON)
#     features["has_des_sbox"] = contains(blob, DES_SBOX_FRAGMENT)
#     features["has_chacha_const"] = contains(blob, CHACHA20_CONST)
#     features["has_sha1_k"] = contains(blob, SHA1_K_FRAGMENT)
#     features["has_sha256_k"] = contains(blob, bytes.fromhex("428a2f98"))
#     features["has_md5_t"] = contains(blob, bytes.fromhex("d76aa478"))
#     features["rsa_bigint_detected"] = 1 if b"\x00\x01\x00\x01" in blob or b"\x30\x82" in blob else 0

#     features["file_size"] = len(blob)
#     features["entropy_full"] = entropy(blob)

#     # Sliding-window entropy (strong crypto → high & stable)
#     window = 2048
#     ent_windows = []
#     for i in range(0, len(blob), window):
#         ent_windows.append(entropy(blob[i:i+window]))

#     features["entropy_mean"] = sum(ent_windows)/len(ent_windows)
#     features["entropy_max"] = max(ent_windows)
#     features["entropy_min"] = min(ent_windows)

#     # -----------------------------
#     # B. INSTRUCTION HISTOGRAM
#     # -----------------------------
#     instr_counts = Counter()

#     for fn in gh["functions"]:
#         for bb in fn["basicBlocks"]:
#             for ins in bb["instructions"]:
#                 op = ins["op"].lower()
#                 instr_counts[op] += 1

#     # collapse into crypto-relevant groups
#     def count_ops(substrs):
#         return sum(count for op, count in instr_counts.items()
#                    if any(s in op for s in substrs))

#     features.update({
#         "op_xor": count_ops(["xor", "eor"]),
#         "op_and": count_ops(["and"]),
#         "op_or":  count_ops(["orr"]),
#         "op_shift": count_ops(["lsl", "lsr", "asr", "ror"]),
#         "op_load": count_ops(["ldr"]),
#         "op_store": count_ops(["str"]),
#         "op_add": count_ops(["add"]),
#         "op_sub": count_ops(["sub"]),
#         "op_mul": count_ops(["mul", "smull", "umull"]),
#         "op_table_lookup": count_ops(["ldr", "[pc"])  # table accesses
#     })

#     # -----------------------------
#     # C. STRUCTURAL FEATURES
#     # -----------------------------
#     features["num_functions"] = len(gh["functions"])
#     features["num_basic_blocks"] = sum(len(fn["basicBlocks"]) for fn in gh["functions"])

#     # Loop count (simple heuristic)
#     loop_count = 0
#     for fn in gh["functions"]:
#         for bb in fn["basicBlocks"]:
#             for ins in bb["instructions"]:
#                 if "bne" in ins["op"].lower() or "beq" in ins["op"].lower():
#                     loop_count += 1
#     features["loop_count"] = loop_count

#     return features


# # -----------------------------
# # MAIN
# # -----------------------------
# if __name__ == "__main__":
#     feat = extract_features(
#         "bin/aes_128_arm_gcc_O0.elf",
#         "ghidra_output.json"
#     )

#     with open("features.json", "w") as f:
#         json.dump(feat, f, indent=2)

#     print("[+] Full crypto feature set extracted → features.json")

#!/usr/bin/env python3
"""
extract_features.py

Usage:
  python extract_features.py --binary /path/to/a.out --ghidra_json ghidra_output.json --out features.json

Generates a comprehensive feature vector for crypto/architecture detection:
 - raw opcode counts, opcode ratios, opcode category buckets
 - immediates stats and immediate entropy
 - crypto-constant hits (AES, SHA, MD5, ChaCha)
 - entropy features (text/rodata/data/opcode)
 - n-gram features (unigrams, bigrams, trigrams)
 - CFG summary features (num_basic_blocks, num_edges, cyclomatic complexity, loop_count, avg_block_size, branch_density)
 - binary metadata (.text/.rodata sizes, table counts, string_count, string_density)
 - architecture encoding (arch_arm, arch_avr, arch_riscv, arch_mips, arch_z80)
 - normalization fields (total_instructions)
"""

import argparse
import json
import math
import re
from collections import Counter, defaultdict
from itertools import islice
from pathlib import Path

# optional imports
try:
    from elftools.elf.elffile import ELFFile
except Exception as e:
    print("ERROR: pyelftools not found. Install with `pip install pyelftools`")
    raise

try:
    import networkx as nx
except Exception:
    nx = None

# -----------------------
# Crypto constants
# -----------------------
AES_SBOX = bytes([
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76
])
AES_INVSBOX = bytes([
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
    0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb
])
AES_RCON = bytes([0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80])
DES_SBOX_FRAGMENT = bytes([0x0e, 0x04, 0x0d, 0x01])
CHACHA20_CONST = b"expand 32-byte k"
SHA256_K_WORD0 = bytes.fromhex("428a2f98")
MD5_T0 = bytes.fromhex("d76aa478")
SHA1_FRAG = bytes([0x5A, 0x82, 0x79, 0x99])

# -----------------------
# Helpers
# -----------------------
def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    cnt = Counter(data)
    L = len(data)
    e = 0.0
    for v in cnt.values():
        p = v / L
        e -= p * math.log2(p)
    return e

def contains(blob: bytes, pat: bytes) -> int:
    return 1 if pat in blob else 0

# def read_elf_sections(path: Path):
#     """Return dict with section name -> (addr, size, data bytes)"""
#     sections = {}
#     with path.open("rb") as f:
#         elffile = ELFFile(f)
#         for sec in elffile.iter_sections():
#             try:
#                 name = sec.name
#             except Exception:
#                 name = "<noname>"
#             data = sec.data() if hasattr(sec, "data") else b""
#             addr = sec["sh_addr"] if hasattr(sec, "__getitem__") and "sh_addr" in sec else 0
#             sections[name] = {
#                 "addr": addr,
#                 "size": sec["sh_size"] if hasattr(sec, "__getitem__") and "sh_size" in sec else len(data),
#                 "data": data
#             }
#     return sections

def read_elf_sections(path):
    from elftools.elf.elffile import ELFFile
    secinfo = {}

    with open(path, "rb") as f:
        elf = ELFFile(f)

        for sec in elf.iter_sections():
            name = sec.name
            header = sec.header

            secinfo[name] = {
                "addr": header["sh_addr"],
                "size": header["sh_size"],
                "type": header["sh_type"],
            }

    return secinfo


# regex for immediates in assembly (Ghidra 'full' field style often includes '#0x..' or '#number')
IMM_RE = re.compile(r"#(?:0x[a-fA-F0-9]+|\d+)")
HEX_RE = re.compile(r"0x[0-9a-fA-F]+")

# branch mnemonics to detect (ARM-style & generic)
BRANCH_OPS = {"b", "bne", "beq", "bl", "bx", "blx", "cbz", "cbnz", "b.w", "bne.w", "b.eq", "b.gt"}

# maps of mnemonic -> normalized token (for unigrams)
def normalize_op(op: str) -> str:
    # lowercase and strip conditional suffixes for ARM (e.g., "bne.w" -> "bne")
    o = op.lower()
    o = o.split('.')[0]
    o = re.sub(r'(?:\.[a-z0-9]+)$', '', o)
    return o

# architecture heuristics
def detect_architecture(mnemonics):
    arch = {
        "arch_arm": 0,
        "arch_avr": 0,
        "arch_riscv": 0,
        "arch_mips": 0,
        "arch_z80": 0,
        "arch_x86": 0
    }
    ops = set(mnemonics)
    # ARM heuristics
    if any(x in ops for x in ("ldr","str","eor","ldrb","strb","lsls","uxth","uadd8")):
        arch["arch_arm"] = 1
    # AVR heuristics
    if any(x in ops for x in ("ldi","out","in","rjmp","ijmp","sts")):
        arch["arch_avr"] = 1
    # RISC-V heuristics
    if any(x in ops for x in ("addi","auipc","lw","sw","jal","jalr")):
        arch["arch_riscv"] = 1
    # MIPS heuristics
    if any(x in ops for x in ("addu","subu","lw","sw","j","jal","sll","srl")):
        arch["arch_mips"] = 1
    # Z80 heuristics
    if any(x in ops for x in ("ld","jp","jr","rrca","srl","sla")):
        arch["arch_z80"] = 1
    # x86 heuristic
    if any(x in ops for x in ("mov","xor","add","sub","call","ret","push","pop","jmp")):
        arch["arch_x86"] = 1
    return arch

# -----------------------
# Feature extraction
# -----------------------
def parse_immediates_from_text(instr_text):
    """Return list of immediate integer values found in instruction text."""
    if not instr_text:
        return []
    found = IMM_RE.findall(instr_text)
    out = []
    for tok in found:
        tok = tok.lstrip('#')
        try:
            if tok.startswith("0x") or tok.startswith("0X"):
                out.append(int(tok, 16))
            else:
                out.append(int(tok, 10))
        except Exception:
            continue
    return out

def immediate_size_bytes(x: int) -> int:
    if x == 0:
        return 1
    b = (x.bit_length() + 7) // 8
    return b

def build_ngrams(seq, n):
    return zip(*[seq[i:] for i in range(n)])

def top_k_from_counter(counter: Counter, k=100):
    return [item for item, _ in counter.most_common(k)]

def compute_sbox_similarity(rodata: bytes):
    """Return metrics:
       - exact_presence: 1 if AES_SBOX exists exactly
       - best_match_fraction: best fraction of matching bytes for sliding window length 16 or full 256 (if table lengths)"""
    if not rodata:
        return {"aes_sbox_present":0, "aes_sbox_best_fraction":0.0}
    present = 1 if AES_SBOX in rodata else 0
    best_frac = 0.0
    L = len(AES_SBOX)
    # If rodata contains 256-length tables, check sliding comparisons for 256-length similarity
    if len(rodata) >= L:
        for i in range(0, max(1, len(rodata)-L+1), 1):
            seg = rodata[i:i+L]
            matches = sum(1 for a,b in zip(seg, AES_SBOX) if a==b)
            frac = matches / L
            if frac > best_frac:
                best_frac = frac
    return {"aes_sbox_present": present, "aes_sbox_best_fraction": round(best_frac, 4)}

def compute_similarity_to_word_sequence(blob: bytes, word_bytes: bytes):
    return 1 if word_bytes in blob else 0

# -----------------------
# Main extractor
# -----------------------
def extract_features(binary_path, ghidra_json_path):
    binary_path = Path(binary_path)
    ghidra_json_path = Path(ghidra_json_path)

    # load binary bytes and sections
    sections = read_elf_sections(binary_path)
    all_bytes = binary_path.read_bytes()
    text_bytes = sections.get(".text", {}).get("data", b"")
    rodata_bytes = sections.get(".rodata", {}).get("data", b"")
    data_bytes = sections.get(".data", {}).get("data", b"")

    # load ghidra JSON
    with ghidra_json_path.open("r", encoding="utf-8") as f:
        gh = json.load(f)

    features = {}
    # Binary signature hits
    features["has_aes_sbox"] = contains(all_bytes, AES_SBOX)
    features["has_aes_invsbox"] = contains(all_bytes, AES_INVSBOX)
    features["has_aes_rcon"] = contains(all_bytes, AES_RCON)
    features["has_des_sbox"] = contains(all_bytes, DES_SBOX_FRAGMENT)
    features["has_chacha_const"] = contains(all_bytes, CHACHA20_CONST)
    features["has_sha1_k"] = contains(all_bytes, SHA1_FRAG)
    features["has_sha256_k_word0"] = contains(all_bytes, SHA256_K_WORD0)
    features["has_md5_t0"] = contains(all_bytes, MD5_T0)
    features["rsa_bigint_detected"] = 1 if b"\x30\x82" in all_bytes or b"\x00\x01\x00\x01" in all_bytes else 0

    # entropy features
    features["file_size"] = len(all_bytes)
    features["entropy_full"] = entropy(all_bytes)
    features["text_entropy"] = entropy(text_bytes)
    features["rodata_entropy"] = entropy(rodata_bytes)
    features["data_entropy"] = entropy(data_bytes)

    # sliding window entropy on file
    window = 2048
    ent_windows = [entropy(all_bytes[i:i+window]) for i in range(0, len(all_bytes), window) if i < len(all_bytes)]
    features["entropy_mean"] = (sum(ent_windows)/len(ent_windows)) if ent_windows else 0.0
    features["entropy_max"] = max(ent_windows) if ent_windows else 0.0
    features["entropy_min"] = min(ent_windows) if ent_windows else 0.0

    # parse instructions and build mnemonics list and per-block info
    total_instructions = 0
    instr_counter = Counter()
    op_sequence = []   # list of normalized ops in file order
    immediate_values = []
    immediate_size_counts = Counter()
    basic_block_sizes = []
    block_starts = []
    # for CFG edges: map block_address -> index and track edges
    blocks_by_start = {}
    block_index = 0
    edges = set()

    # The Ghidra JSON has functions -> basicBlocks -> instructions with 'op' and 'full' keys per your provided sample
    functions = gh.get("functions") if isinstance(gh, dict) else gh
    if functions is None:
        raise RuntimeError("ghidra_output.json format unexpected: top-level 'functions' missing")

    for fn in functions:
        fn_name = fn.get("name", "")
        bbs = fn.get("basicBlocks", [])
        for bb in bbs:
            start = bb.get("start")
            block_starts.append(start)
            blocks_by_start[start] = block_index
            block_index += 1
            instrs = bb.get("instructions", [])
            basic_block_sizes.append(len(instrs))
            # per-basic-block last-instr for branch target parsing
            last_instr = None
            for ins in instrs:
                op = ins.get("op", "") or ""
                full = ins.get("full", "") or ""
                op_norm = normalize_op(op)
                instr_counter[op_norm] += 1
                op_sequence.append(op_norm)
                total_instructions += 1

                # immediate parsing
                imms = parse_immediates_from_text(full)
                for v in imms:
                    immediate_values.append(v)
                    sizeb = immediate_size_bytes(v)
                    if sizeb == 1:
                        immediate_size_counts["count_immediate_1b"] += 1
                    elif sizeb == 2:
                        immediate_size_counts["count_immediate_2b"] += 1
                    elif sizeb == 4:
                        immediate_size_counts["count_immediate_4b"] += 1
                    elif sizeb == 8:
                        immediate_size_counts["count_immediate_8b"] += 1
                    else:
                        immediate_size_counts["count_immediate_large"] += 1

                last_instr = full.lower()

            # attempt get edge(s) from last instruction
            if last_instr:
                # look for hex target in instruction text
                m = HEX_RE.search(last_instr)
                if m:
                    target = m.group(0)
                    # some JSON 'start' and branch targets share address format hex; use simple mapping if possible
                    if target in blocks_by_start:
                        edges.add((start, target))
                    else:
                        # otherwise add edge to target literal (string). We'll treat it as an edge record.
                        edges.add((start, target))
                # fall-through edge heuristics: next block in block_starts list
                # (we'll add edges between sequence of blocks later)
    # normalize counts into features
    # raw opcode counts: attempt to include a set of requested mnemonics
    raw_ops = [
        "mov","add","sub","mul","div","xor","eor","and","or","not","shl","shr","ror","rol",
        "cmp","b","bl","blx","call","ret","ldr","str","push","pop"
    ]
    # map some synonyms
    mapping_synonyms = {"eor":"xor","b":"jmp","bl":"call","blx":"call","bx":"ret"}
    for op in raw_ops:
        normalized = mapping_synonyms.get(op, op)
        features[f"count_{op}"] = instr_counter.get(op, 0) + (instr_counter.get(mapping_synonyms.get(op,""),0) if mapping_synonyms.get(op) else 0)

    # fill any counts not present
    for k in ("count_mov","count_add","count_sub","count_mul","count_div","count_xor","count_and","count_or","count_not",
              "count_shl","count_shr","count_ror","count_rol","count_cmp","count_jmp","count_call","count_ret",
              "count_ldr","count_str","count_push","count_pop"):
        if k not in features:
            features[k] = instr_counter.get(k.replace("count_",""), 0)

    # opcode ratios
    total_instr = total_instructions if total_instructions>0 else 1
    features["total_instructions"] = total_instructions
    features["xor_ratio"] = (instr_counter.get("eor",0)+instr_counter.get("xor",0)) / total_instr
    rotate_count = sum(instr_counter.get(x,0) for x in ("ror","rol"))
    features["rotate_ratio"] = rotate_count / total_instr
    features["mul_ratio"] = instr_counter.get("mul",0)/ total_instr
    branch_count = sum(instr_counter.get(x,0) for x in ("b","bne","beq","bl","bx","jmp"))
    features["branch_ratio"] = branch_count / total_instr
    load_store_count = instr_counter.get("ldr",0) + instr_counter.get("str",0)
    features["load_store_ratio"] = load_store_count / total_instr

    # opcode category buckets
    arithmetic_ops = sum(instr_counter.get(x,0) for x in ("add","sub","mul","div","adc","sbc"))
    logical_ops = sum(instr_counter.get(x,0) for x in ("and","orr","orr","orr","orr"))
    bitwise_ops = sum(instr_counter.get(x,0) for x in ("eor","xor","not","bic","orn"))
    memory_ops = sum(instr_counter.get(x,0) for x in ("ldr","str","ldrb","strb","ldrd","strd"))
    branch_ops = branch_count
    crypto_like_ops = instr_counter.get("eor",0) + instr_counter.get("ror",0) + instr_counter.get("mul",0)
    features.update({
        "arithmetic_ops": arithmetic_ops,
        "logical_ops": logical_ops,
        "bitwise_ops": bitwise_ops,
        "memory_ops": memory_ops,
        "branch_ops": branch_ops,
        "crypto_like_ops": crypto_like_ops
    })

    # immediate constant features
    # compute immediate entropy
    imm_bytes = b"".join((v.to_bytes(immediate_size_bytes(v),"little",signed=False) for v in immediate_values if v is not None and v>=0))
    features["immediate_entropy"] = entropy(imm_bytes)
    # counts
    features["count_immediate_1b"] = int(immediate_size_counts.get("count_immediate_1b",0))
    features["count_immediate_2b"] = int(immediate_size_counts.get("count_immediate_2b",0))
    features["count_immediate_4b"] = int(immediate_size_counts.get("count_immediate_4b",0))
    features["count_immediate_8b"] = int(immediate_size_counts.get("count_immediate_8b",0))
    features["count_immediate_large"] = int(immediate_size_counts.get("count_immediate_large",0))

    # crypto-constant hits and similarity (rodata based)
    sbox_metrics = compute_sbox_similarity(rodata_bytes)
    features.update(sbox_metrics)
    features["sha_k_constant_similarity"] = compute_similarity_to_word_sequence(all_bytes, SHA256_K_WORD0)
    features["md5_sha_iv_hits"] = compute_similarity_to_word_sequence(all_bytes, MD5_T0)
    features["ecc_curve_constant_hits"] = 0  # placeholder: detecting ECC curve constants is complex; can search for "secp" strings in rodata
    features["ecc_curve_constant_hits"] = 1 if b"secp" in rodata_bytes or b"secp" in all_bytes else features["ecc_curve_constant_hits"]

    # opcode entropy (entropy of opcode token stream)
    op_bytes = " ".join(op_sequence).encode("utf-8")
    features["opcode_entropy"] = entropy(op_bytes)

    # N-gram features
    unigram_counter = Counter(op_sequence)
    bigram_counter = Counter(" ".join(b) for b in build_ngrams(op_sequence,2))
    trigram_counter = Counter(" ".join(b) for b in build_ngrams(op_sequence,3))
    features["top_200_unigrams"] = top_k_from_counter(unigram_counter, 200)
    features["top_300_bigrams"] = top_k_from_counter(bigram_counter, 300)
    features["top_200_trigrams"] = top_k_from_counter(trigram_counter, 200)
    features["unique_ngram_count"] = len(set(list(unigram_counter.keys()) + list(bigram_counter.keys()) + list(trigram_counter.keys())))
    # high_frequency_ngram_score: ratio of frequency mass of top 10 bigrams
    total_bigrams = sum(bigram_counter.values()) if bigram_counter else 1
    top10_mass = sum(v for _,v in bigram_counter.most_common(10))
    features["high_frequency_ngram_score"] = top10_mass/total_bigrams if total_bigrams>0 else 0

    # CFG summary
    num_basic_blocks = sum(len(fn.get("basicBlocks",[])) for fn in functions)
    features["num_basic_blocks"] = num_basic_blocks
    # edges: we made some edges earlier; as fallback connect successive blocks
    if not edges:
        # create sequential edges by block order
        all_starts = []
        for fn in functions:
            for bb in fn.get("basicBlocks",[]):
                all_starts.append(bb.get("start"))
        for i in range(len(all_starts)-1):
            edges.add((all_starts[i], all_starts[i+1]))
    features["num_edges"] = len(edges)
    # cyclomatic complexity: E - N + 2P (P=1)
    features["cyclomatic_complexity"] = max(0, features["num_edges"] - features["num_basic_blocks"] + 2)
    features["loop_count"] = sum(1 for fn in functions for bb in fn.get("basicBlocks",[]) for ins in bb.get("instructions",[]) if any(b in (ins.get("op") or "").lower() for b in ("bne","beq","bl","cbz","cbnz")))
    features["avg_block_size"] = (sum(basic_block_sizes)/len(basic_block_sizes)) if basic_block_sizes else 0
    features["branch_density"] = features["branch_ratio"]

    # binary metadata
    features["text_size"] = sections.get(".text", {}).get("size", 0)
    features["rodata_size"] = sections.get(".rodata", {}).get("size", 0)
    features["data_size"] = sections.get(".data", {}).get("size", 0)
    # naive table counts: count occurrences of potential table patterns in rodata
    features["number_of_tables"] = 0
    if rodata_bytes:
        # heuristic: number of long constant runs (>=16 bytes) with non-zero values
        run_count = 0
        threshold = 16
        i = 0
        while i < len(rodata_bytes):
            if rodata_bytes[i] != 0:
                j = i
                while j < len(rodata_bytes) and rodata_bytes[j] != 0:
                    j += 1
                if (j - i) >= threshold:
                    run_count += 1
                i = j
            else:
                i += 1
        features["number_of_tables"] = run_count
    features["large_table_flag"] = 1 if features["number_of_tables"] > 0 else 0

    # strings and density (simple ASCII runs)
    def extract_ascii_strings(b, min_len=4):
        res = []
        cur = bytearray()
        for c in b:
            if 32 <= c < 127:
                cur.append(c)
            else:
                if len(cur) >= min_len:
                    res.append(cur.decode("utf-8", errors="ignore"))
                cur = bytearray()
        if len(cur) >= min_len:
            res.append(cur.decode("utf-8", errors="ignore"))
        return res

    strings = extract_ascii_strings(all_bytes, min_len=4)
    features["string_count"] = len(strings)
    features["string_density"] = len("".join(strings)) / max(1, len(all_bytes))

    # architecture detection
    features.update(detect_architecture(list(instr_counter.keys())))

    # normalization
    features["total_instructions"] = total_instructions

    return features

# -----------------------
# CLI
# -----------------------
def main():
    parser = argparse.ArgumentParser(description="Extract crypto and statistical features from ELF+Ghidra JSON")
    parser.add_argument("--binary", required=True, help="Path to ELF binary")
    parser.add_argument("--ghidra_json", required=True, help="Path to ghidra_output.json")
    parser.add_argument("--out", default="features.json", help="Output path for features JSON")
    args = parser.parse_args()

    feat = extract_features(args.binary, args.ghidra_json)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(feat, f, indent=2)
    print(f"[+] Wrote features to {args.out}")

if __name__ == "__main__":
    main()
