#!/usr/bin/env python3
"""
prng_label.py

Simple PRNG classifier:
 - If function name matches known PRNG names → label = "PRNG"
 - Everything else → label = "Non-Crypto"

Outputs:
 - prng_training_dataset.json
 - prng_crypto_dataset.csv

Range: JSON files 160 → 200
"""

import os
import glob
import json
import csv

# ============================================================
# CONFIG
# ============================================================
TARGET_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "ghidra_output")
)


OUTPUT_JSON = "prng_training_dataset.json"
OUTPUT_CSV  = "prng_crypto_dataset.csv"

START_INDEX = 160
END_INDEX   = 200

# ============================================================
# PRNG FUNCTION SET
# ============================================================
PRNG_FUNCS = {
    "lcg_init", "lcg_next",
    "xorshift128_init", "xorshift128_next",
    "chacha_init", "chacha_block", "chacha_next",
    "mt_init", "mt_next",
    "prng_init", "prng_next", "prng_bytes", "prng_range", "prng_double"
}

# ============================================================
# CLEAN CSV FIELDS
# ============================================================
FIELDNAMES = [
    "architecture","algorithm","compiler","optimization","filename",
    "function_name","function_address","label",

    "num_basic_blocks","num_edges","cyclomatic_complexity","loop_count",
    "loop_depth","branch_density","average_block_size","num_entry_exit_paths",
    "strongly_connected_components",

    "num_conditional_edges","num_unconditional_edges","num_loop_edges",
    "avg_edge_branch_condition_complexplexity",

    "instruction_count","immediate_entropy","bitwise_op_density",
    "crypto_constant_hits","branch_condition_complexity",

    "add_ratio","logical_ratio","load_store_ratio","xor_ratio",
    "multiply_ratio","rotate_ratio",

    "has_aes_sbox","rsa_bigint_detected","has_aes_rcon","has_sha_constants",

    "rodata_refs_count","string_refs_count","stack_frame_size",

    "bitwise_ops","crypto_like_ops","arithmetic_ops","mem_ops_ratio",

    "function_byte_entropy","opcode_entropy","cyclomatic_complexity_density",
    "unique_ngram_count"
]

# ============================================================
# FEATURE EXTRACTION
# ============================================================
def extract_features(func):
    f = {}
    graph = func.get("graph_level", {}) or {}
    nodes = func.get("node_level", []) or []
    op    = func.get("op_category_counts", {}) or {}
    cs    = func.get("crypto_signatures", {}) or {}
    data  = func.get("data_references", {}) or {}
    ent   = func.get("entropy_metrics", {}) or {}
    seq   = func.get("instruction_sequence", {}) or {}

    ncount = max(1, len(nodes))

    # graph-level
    for k in [
        "num_basic_blocks","num_edges","cyclomatic_complexity","loop_count",
        "loop_depth","branch_density","average_block_size","num_entry_exit_paths",
        "strongly_connected_components","num_conditional_edges",
        "num_unconditional_edges","num_loop_edges",
        "avg_edge_branch_condition_complexplexity"
    ]:
        f[k] = graph.get(k, 0)

    # counts
    f["instruction_count"] = sum(n.get("instruction_count", 0) for n in nodes)
    f["immediate_entropy"] = sum(n.get("immediate_entropy", 0) for n in nodes)/ncount
    f["bitwise_op_density"] = sum(n.get("bitwise_op_density", 0) for n in nodes)/ncount
    f["crypto_constant_hits"] = sum(n.get("crypto_constant_hits", 0) for n in nodes)
    f["branch_condition_complexity"] = sum(n.get("branch_condition_complexity", 0) for n in nodes)

    # opcode ratios
    def avg_ratio(k):
        return sum(n.get("opcode_ratios",{}).get(k,0) for n in nodes)/ncount

    for r in ["add_ratio","logical_ratio","load_store_ratio","xor_ratio",
              "multiply_ratio","rotate_ratio"]:
        f[r] = avg_ratio(r)

    # crypto flags (likely all false)
    f["has_aes_sbox"] = bool(cs.get("has_aes_sbox"))
    f["rsa_bigint_detected"] = bool(cs.get("rsa_bigint_detected"))
    f["has_aes_rcon"] = bool(cs.get("has_aes_rcon"))
    f["has_sha_constants"] = bool(cs.get("has_sha_constants"))

    # data references
    f["rodata_refs_count"] = data.get("rodata_refs_count", 0)
    f["string_refs_count"] = data.get("string_refs_count", 0)
    f["stack_frame_size"] = data.get("stack_frame_size", 0)

    # operation categories
    f["bitwise_ops"] = op.get("bitwise_ops", 0)
    f["crypto_like_ops"] = op.get("crypto_like_ops", 0)
    f["arithmetic_ops"] = op.get("arithmetic_ops", 0)
    f["mem_ops_ratio"] = op.get("mem_ops_ratio", 0.0)

    # entropy
    f["function_byte_entropy"] = ent.get("function_byte_entropy", 0.0)
    f["opcode_entropy"] = ent.get("opcode_entropy", 0.0)
    f["cyclomatic_complexity_density"] = ent.get("cyclomatic_complexity_density", 0.0)

    # ngram count
    f["unique_ngram_count"] = seq.get("unique_ngram_count", 0)

    return f

# ============================================================
# LABEL LOGIC — ONLY PRNG OR NON-CRYPTO
# ============================================================
def classify(func_name):
    fn = func_name.lower()
    return "PRNG" if fn in PRNG_FUNCS else "Non-Crypto"

# ============================================================
# PARSE FILENAME METADATA
# ============================================================
def extract_metadata(filename):
    base = os.path.basename(filename).lower().replace(".json", "")
    parts = base.split("_")
    if len(parts) >= 4:
        return parts[-3], parts[-2], parts[-1]
    return "unknown","unknown","unknown"

# ============================================================
# MAIN PIPELINE
# ============================================================
def process():

    files = sorted(glob.glob(os.path.join(TARGET_DIR, "*.json")))
    files = files[START_INDEX:END_INDEX]

    rows = []
    json_out = []

    for jf in files:
        with open(jf,"r") as fh:
            data = json.load(fh)

        binary = data.get("binary", os.path.basename(jf))
        arch, compiler, opt = extract_metadata(binary)

        for func in data.get("functions", []):
            fname = func.get("name","")
            feats = extract_features(func)
            label = classify(fname)

            row = {
                "architecture": arch,
                "algorithm": label,
                "compiler": compiler,
                "optimization": opt,
                "filename": binary,
                "function_name": fname,
                "function_address": func.get("address",""),
                "label": label,
            }
            row.update(feats)
            rows.append(row)

            json_out.append(row)

    # Write JSON
    with open(OUTPUT_JSON,"w") as j:
        json.dump(json_out,j,indent=2)

    # Write CSV
    with open(OUTPUT_CSV,"w",newline="",encoding="utf-8") as cf:
        writer = csv.DictWriter(cf, fieldnames=FIELDNAMES)
        writer.writeheader()
        for r in rows:
            writer.writerow({k: r.get(k,"") for k in FIELDNAMES})

    print("[+] Done:", OUTPUT_JSON, OUTPUT_CSV)

if __name__ == "__main__":
    process()
