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
    os.path.join(os.path.dirname(__file__), "..", "..", "test_dataset_json")
)

OUTPUT_JSON = "xor_training_dataset.json"
OUTPUT_CSV  = "xor_crypto_dataset.csv"

START_INDEX = 310
END_INDEX   = 355


# ============================================================
# TRUE XOR FUNCTION NAME SET (based on your dataset)
# ============================================================
XOR_FUNCS = {
    "xor_init",
    "xor_encrypt_block",
    "xor_decrypt_block",
    "xor_stream",

    # helper mixing/permutation functions used in your XOR cipher
    "rol",
    "sub",
    "perm",
    "diff"
}


# ============================================================
# FEATURE EXTRACTION
# ============================================================
def extract_features(func):
    f = {}

    graph = func.get("graph_level", {}) or {}
    nodes = func.get("node_level", []) or []
    op    = func.get("op_category_counts", {}) or {}
    data  = func.get("data_references", {}) or {}
    ent   = func.get("entropy_metrics", {}) or {}
    seq   = func.get("instruction_sequence", {}) or {}

    ncount = max(1, len(nodes))

    # graph-level
    graph_keys = [
        "num_basic_blocks","num_edges","cyclomatic_complexity",
        "loop_count","loop_depth","branch_density","average_block_size",
        "num_entry_exit_paths","strongly_connected_components",
        "num_conditional_edges","num_unconditional_edges","num_loop_edges",
        "avg_edge_branch_condition_complexplexity"
    ]
    for k in graph_keys:
        f[k] = graph.get(k, 0)

    # aggregated instruction-level features
    f["instruction_count"] = sum(n.get("instruction_count",0) for n in nodes)
    f["immediate_entropy"] = sum(n.get("immediate_entropy",0) for n in nodes)/ncount
    f["bitwise_op_density"] = sum(n.get("bitwise_op_density",0) for n in nodes)/ncount
    f["crypto_constant_hits"] = sum(n.get("crypto_constant_hits",0) for n in nodes)
    f["branch_condition_complexity"] = sum(
        n.get("branch_condition_complexity",0) for n in nodes
    )

    # opcode ratios
    def avg_ratio(k):
        return sum(n.get("opcode_ratios",{}).get(k,0) for n in nodes) / ncount

    for r in ["add_ratio","logical_ratio","load_store_ratio",
              "xor_ratio","multiply_ratio","rotate_ratio"]:
        f[r] = avg_ratio(r)

    # data references
    f["rodata_refs_count"] = data.get("rodata_refs_count",0)
    f["string_refs_count"] = data.get("string_refs_count",0)
    f["stack_frame_size"]  = data.get("stack_frame_size",0)

    # operation categories
    f["bitwise_ops"]     = op.get("bitwise_ops",0)
    f["crypto_like_ops"] = op.get("crypto_like_ops",0)
    f["arithmetic_ops"]  = op.get("arithmetic_ops",0)
    f["mem_ops_ratio"]   = float(op.get("mem_ops_ratio",0))

    # entropy
    f["function_byte_entropy"] = ent.get("function_byte_entropy",0)
    f["opcode_entropy"]        = ent.get("opcode_entropy",0)
    f["cyclomatic_complexity_density"] = ent.get("cyclomatic_complexity_density",0)

    # ngram features
    f["unique_ngram_count"] = seq.get("unique_ngram_count",0)

    return f


# ============================================================
# XOR CLASSIFIER
# ============================================================
def is_xor_cipher(func):
    lname = func.get("name","").lower()
    return lname in XOR_FUNCS


# ============================================================
# MAIN
# ============================================================
def process():

    files = sorted(glob.glob(os.path.join(TARGET_DIR,"*.json")))
    files = files[START_INDEX:END_INDEX]

    all_rows = []

    for jf in files:
        with open(jf,"r",encoding="utf-8") as fh:
            data = json.load(fh)

        binary = data.get("binary", os.path.basename(jf))
        parts = binary.split("_")

        meta = {
            "filename": binary,
            "architecture": parts[-3] if len(parts)>=4 else "unknown",
            "compiler":     parts[-2] if len(parts)>=4 else "unknown",
            "optimization": parts[-1].split(".")[0] if len(parts)>=4 else "unknown",
        }

        for func in data.get("functions", []):
            fname = func.get("name","")
            feats = extract_features(func)

            label = "XOR-CIPHER" if is_xor_cipher(func) else "Non-Crypto"

            row = {
                "architecture": meta["architecture"],
                "algorithm": label,
                "compiler": meta["compiler"],
                "optimization": meta["optimization"],
                "filename": meta["filename"],
                "function_name": fname,
                "function_address": func.get("address",""),
                "label": label,
                **feats
            }

            all_rows.append(row)

    # write CSV
    with open(OUTPUT_CSV,"w",newline="",encoding="utf-8") as cf:
        writer = csv.DictWriter(cf, fieldnames=all_rows[0].keys())
        writer.writeheader()
        writer.writerows(all_rows)

    # write JSON
    with open(OUTPUT_JSON,"w",encoding="utf-8") as jf:
        json.dump(all_rows, jf, indent=2)

    print("[+] Generated XOR dataset:", OUTPUT_JSON, OUTPUT_CSV)


if __name__ == "__main__":
    process()
