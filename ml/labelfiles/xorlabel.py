# xor_label.py
# Labeling script for XOR-based cipher functions

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


OUTPUT_JSON = "xor_training_dataset.json"
OUTPUT_CSV  = "xor_crypto_dataset.csv"

START_INDEX = 360
END_INDEX   = 400

# ============================================================
# XOR FUNCTION NAME MAP
# ============================================================
XOR_FUNCS = [
    "xor_init",
    "xor_key_schedule",
    "xor_encrypt_block",
    "xor_decrypt_block",
    "xor_stream_encrypt",
    "substitute_bytes",
    "permute_bytes",
    "diffuse_bytes",
    "init_inv_sbox",
    "rotl8",
    "rotr8",
]

# lowercase
XOR_FUNCS = [f.lower() for f in XOR_FUNCS]


# ============================================================
# FEATURE EXTRACTION (same as RSA/MD5)
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

    keys = [
        "num_basic_blocks","num_edges","cyclomatic_complexity",
        "loop_count","loop_depth","branch_density","average_block_size",
        "num_entry_exit_paths","strongly_connected_components",
        "num_conditional_edges","num_unconditional_edges","num_loop_edges",
        "avg_edge_branch_condition_complexplexity"
    ]

    for k in keys:
        f[k] = graph.get(k, 0)

    f["instruction_count"] = sum(n.get("instruction_count",0) for n in nodes)
    f["immediate_entropy"] = sum(n.get("immediate_entropy",0) for n in nodes) / ncount
    f["bitwise_op_density"] = sum(n.get("bitwise_op_density",0) for n in nodes) / ncount
    f["crypto_constant_hits"] = sum(n.get("crypto_constant_hits",0) for n in nodes)
    f["branch_condition_complexity"] = sum(n.get("branch_condition_complexity",0) for n in nodes)

    def avg_ratio(r):
        return sum(n.get("opcode_ratios",{}).get(r,0) for n in nodes) / ncount

    for r in ["add_ratio","logical_ratio","load_store_ratio","xor_ratio","multiply_ratio","rotate_ratio"]:
        f[r] = avg_ratio(r)

    f["rodata_refs_count"] = data.get("rodata_refs_count",0)
    f["string_refs_count"] = data.get("string_refs_count",0)
    f["stack_frame_size"] = data.get("stack_frame_size",0)

    f["bitwise_ops"]     = op.get("bitwise_ops",0)
    f["crypto_like_ops"] = op.get("crypto_like_ops",0)
    f["arithmetic_ops"]  = op.get("arithmetic_ops",0)
    f["mem_ops_ratio"]   = float(op.get("mem_ops_ratio",0))

    f["function_byte_entropy"] = ent.get("function_byte_entropy",0)
    f["opcode_entropy"]        = ent.get("opcode_entropy",0)
    f["cyclomatic_complexity_density"] = ent.get("cyclomatic_complexity_density",0)

    f["unique_ngram_count"] = seq.get("unique_ngram_count",0)

    return f


# ============================================================
# LABELING LOGIC
# ============================================================
def is_xor_cipher(func):
    name = func.get("name","").lower()
    return any(x in name for x in XOR_FUNCS)


# ============================================================
# MAIN
# ============================================================
def process():

    files = sorted(glob.glob(os.path.join(TARGET_DIR,"*.json")))
    files = files[START_INDEX:END_INDEX]

    all_samples = []

    for jf in files:
        with open(jf,"r",encoding="utf-8") as fh:
            data = json.load(fh)

        binary = data.get("binary", os.path.basename(jf))

        parts = binary.split("_")
        meta = {
            "filename": binary,
            "architecture":  parts[-3] if len(parts)>=4 else "unknown",
            "compiler":      parts[-2] if len(parts)>=4 else "unknown",
            "optimization":  parts[-1].split(".")[0] if len(parts)>=4 else "unknown",
        }

        for func in data.get("functions",[]):

            fname = func.get("name","")
            feats = extract_features(func)

            if is_xor_cipher(func):
                label = "XOR-CIPHER"
            else:
                label = "Non-Crypto"

            all_samples.append({
                "architecture": meta["architecture"],
                "algorithm": label,
                "compiler": meta["compiler"],
                "optimization": meta["optimization"],
                "filename": meta["filename"],
                "function_name": fname,
                "function_address": func.get("address",""),
                "label": label,
                **feats
            })

    with open(OUTPUT_CSV,"w",newline="",encoding="utf-8") as cf:
        writer = csv.DictWriter(cf, fieldnames=all_samples[0].keys())
        writer.writeheader()
        writer.writerows(all_samples)

    with open(OUTPUT_JSON,"w",encoding="utf-8") as jf:
        json.dump(all_samples, jf, indent=2)

    print("[+] Generated XOR dataset:", OUTPUT_JSON, OUTPUT_CSV)


if __name__ == "__main__":
    process()
