#!/usr/bin/env python3
"""
sha_label.py

Labels ONLY SHA functions (SHA-1 / SHA-224).
Everything else → Non-Crypto
"""

import os
import glob
import json
import csv
import math

# ============================================================
# CONFIG
# ============================================================

TARGET_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "test_dataset_json")
)

OUTPUT_JSON = "sha_training_dataset.json"
OUTPUT_CSV  = "sha_crypto_dataset.csv"

START_INDEX = 220
END_INDEX   = 310


# ============================================================
# NEW SHA FUNCTION SETS (FROM YOUR DATA)
# ============================================================

SHA1_FUNCS = {
    "sha1_init_alt",
    "sha1_update_alt",
    "sha1_final_alt",
    "sha1_compress",
}

SHA224_FUNCS = {
    "sha224_alt_init",
    "sha224_alt_update",
    "sha224_alt_final",
    "do_block",
}


# ============================================================
# STRINGIFY
# ============================================================

def stringify(func):
    try:
        return json.dumps(func, sort_keys=True).lower()
    except:
        return str(func).lower()


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

    # graph features
    for k in [
        "num_basic_blocks","num_edges","cyclomatic_complexity","loop_count",
        "loop_depth","branch_density","average_block_size",
        "num_entry_exit_paths","strongly_connected_components",
        "num_conditional_edges","num_unconditional_edges",
        "num_loop_edges","avg_edge_branch_condition_complexplexity"
    ]:
        f[k] = graph.get(k, 0)

    # instruction-level
    f["instruction_count"] = sum(n.get("instruction_count",0) for n in nodes)
    f["immediate_entropy"] = sum(n.get("immediate_entropy",0) for n in nodes)/ncount
    f["bitwise_op_density"] = sum(n.get("bitwise_op_density",0) for n in nodes)/ncount
    f["crypto_constant_hits"] = sum(n.get("crypto_constant_hits",0) for n in nodes)
    f["branch_condition_complexity"] = sum(
        n.get("branch_condition_complexity",0) for n in nodes
    )

    # opcode ratios
    def avg_ratio(key):
        return sum(n.get("opcode_ratios",{}).get(key,0) for n in nodes)/ncount

    for r in ["add_ratio","logical_ratio","load_store_ratio",
              "xor_ratio","multiply_ratio","rotate_ratio"]:
        f[r] = avg_ratio(r)

    # crypto flags
    f["has_aes_sbox"]       = bool(cs.get("has_aes_sbox"))
    f["rsa_bigint_detected"]= bool(cs.get("rsa_bigint_detected"))
    f["has_aes_rcon"]       = bool(cs.get("has_aes_rcon"))
    f["has_sha_constants"]  = bool(cs.get("has_sha_constants"))

    # data references
    f["rodata_refs_count"] = data.get("rodata_refs_count",0)
    f["string_refs_count"] = data.get("string_refs_count",0)
    f["stack_frame_size"] = data.get("stack_frame_size",0)

    # op categories
    f["bitwise_ops"]     = op.get("bitwise_ops",0)
    f["crypto_like_ops"] = op.get("crypto_like_ops",0)
    f["arithmetic_ops"]  = op.get("arithmetic_ops",0)
    f["mem_ops_ratio"]   = float(op.get("mem_ops_ratio",0))

    # entropy
    f["function_byte_entropy"] = ent.get("function_byte_entropy",0)
    f["opcode_entropy"] = ent.get("opcode_entropy",0)
    f["cyclomatic_complexity_density"] = ent.get("cyclomatic_complexity_density",0)

    # ngrams
    f["unique_ngram_count"] = seq.get("unique_ngram_count",0)

    f["_text"] = stringify(func)
    return f


# ============================================================
# CLASSIFY SHA VARIANT
# ============================================================

def classify_sha(func_name):
    lname = func_name.lower()

    if lname in SHA1_FUNCS:
        return "SHA-1"

    if lname in SHA224_FUNCS:
        return "SHA-224"

    return "Non-Crypto"


# ============================================================
# EXTRACT METADATA FROM BINARY NAME
# ============================================================

def extract_metadata(filename):
    base = os.path.basename(filename).replace(".json","")
    parts = base.split("_")

    arch = "unknown"
    compiler = "unknown"
    opt = "unknown"

    if len(parts) >= 4:
        arch     = parts[-3]
        compiler = parts[-2]
        opt      = parts[-1]

    return arch, compiler, opt


# ============================================================
# MAIN PIPELINE
# ============================================================

def process():

    files = sorted(glob.glob(os.path.join(TARGET_DIR, "*.json")))
    files = files[START_INDEX:END_INDEX]

    all_rows = []

    for jf in files:
        with open(jf,"r",encoding="utf-8") as fh:
            data = json.load(fh)

        binary = data.get("binary", os.path.basename(jf))

        arch, comp, opt = extract_metadata(binary)

        for func in data.get("functions", []):
            fname = func.get("name","")

            feats = extract_features(func)
            label = classify_sha(fname)

            row = {
                "architecture": arch,
                "algorithm": label,
                "compiler": comp,
                "optimization": opt,
                "filename": binary,
                "function_name": fname,
                "function_address": func.get("address",""),
                "label": label,
            }

            row.update(feats)
            all_rows.append(row)

    # JSON output
    with open(OUTPUT_JSON,"w",encoding="utf-8") as jf:
        json.dump(all_rows, jf, indent=2)

    # CSV output
    with open(OUTPUT_CSV,"w",newline="",encoding="utf-8") as cf:
        writer = csv.DictWriter(cf, fieldnames=all_rows[0].keys())
        writer.writeheader()
        writer.writerows(all_rows)

    print("[+] SHA dataset created:", OUTPUT_JSON, OUTPUT_CSV)


if __name__ == "__main__":
    process()
