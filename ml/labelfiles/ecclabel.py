import os
import glob
import json
import csv
import math
import re

# ============================================================
# CONFIG
# ============================================================
TARGET_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "ghidra_output")
)


OUTPUT_JSON = "ecc_training_dataset.json"
OUTPUT_CSV  = "ecc_crypto_dataset.csv"

START_INDEX = 120   # ECC dataset range
END_INDEX   = 160


# ============================================================
# STRICT ECC FUNCTION NAMES (ONLY THESE ARE ECC)
# ============================================================

ECC_NAMES = {
    "ec_init_curve",
    "ec_point_double",
    "ec_point_add",
    "ec_scalar_mult",
    "ecdh_generate_keypair",
    "ecdh_compute_shared_secret",
    "ecdsa_sign",
    "ecdsa_verify"
}

ECC_NAMES = {n.lower() for n in ECC_NAMES}


# ============================================================
# STRINGIFY
# ============================================================

def stringify(func):
    try:
        return json.dumps(func, sort_keys=True).lower()
    except:
        return str(func).lower()


# ============================================================
# FEATURE EXTRACTION (same format as RSA/SHA)
# ============================================================

def extract_features(func):
    f = {}
    graph = func.get("graph_level", {}) or {}
    nodes = func.get("node_level", []) or func.get("nodes", []) or []
    op = func.get("op_category_counts", {}) or {}
    cs = func.get("crypto_signatures", {}) or {}
    data_ref = func.get("data_references", {}) or {}
    entropy = func.get("entropy_metrics", {}) or {}
    seq = func.get("instruction_sequence", {}) or {}

    n = max(1, len(nodes))

    # graph metrics
    for k in [
        "num_basic_blocks","num_edges","cyclomatic_complexity","loop_count",
        "loop_depth","branch_density","average_block_size","num_entry_exit_paths",
        "strongly_connected_components","num_conditional_edges",
        "num_unconditional_edges","num_loop_edges",
        "avg_edge_branch_condition_complexplexity"
    ]:
        f[k] = graph.get(k, 0)

    # instruction-level features
    f["instruction_count"] = sum(n_.get("instruction_count",0) for n_ in nodes)
    f["immediate_entropy"] = sum(n_.get("immediate_entropy",0) for n_ in nodes)/n
    f["bitwise_op_density"] = sum(n_.get("bitwise_op_density",0) for n_ in nodes)/n
    f["crypto_constant_hits"] = sum(n_.get("crypto_constant_hits",0) for n_ in nodes)
    f["branch_condition_complexity"] = sum(n_.get("branch_condition_complexity",0) for n_ in nodes)

    # ratios
    def avg_ratio(key):
        return sum(n_.get("opcode_ratios",{}).get(key,0) for n_ in nodes)/n

    for r in ["add_ratio","logical_ratio","load_store_ratio","xor_ratio",
              "multiply_ratio","rotate_ratio"]:
        f[r] = avg_ratio(r)

    # crypto signature flags
    f["has_aes_sbox"] = bool(cs.get("has_aes_sbox"))
    f["rsa_bigint_detected"] = bool(cs.get("rsa_bigint_detected"))
    f["has_aes_rcon"] = bool(cs.get("has_aes_rcon"))
    f["has_sha_constants"] = bool(cs.get("has_sha_constants"))

    # data refs
    f["rodata_refs_count"] = data_ref.get("rodata_refs_count", 0)
    f["string_refs_count"] = data_ref.get("string_refs_count", 0)
    f["stack_frame_size"] = data_ref.get("stack_frame_size", 0)

    # categories
    f["bitwise_ops"] = op.get("bitwise_ops", 0)
    f["crypto_like_ops"] = op.get("crypto_like_ops", 0)
    f["arithmetic_ops"] = op.get("arithmetic_ops", 0)
    f["mem_ops_ratio"] = float(op.get("mem_ops_ratio", 0.0))

    # entropy
    f["function_byte_entropy"] = entropy.get("function_byte_entropy", 0)
    f["opcode_entropy"] = entropy.get("opcode_entropy", 0)
    f["cyclomatic_complexicity_density"] = entropy.get("cyclomatic_complexity_density", 0)
    f["unique_ngram_count"] = seq.get("unique_ngram_count", 0)

    f["_text"] = stringify(func)

    return f


# ============================================================
# STRICT LABELING (NO RULES — ONLY NAMES)
# ============================================================

def classify_ecc(function_name):
    """Return ECC or Non-Crypto strictly based on name."""
    fn = function_name.lower()

    if fn in ECC_NAMES:
        return "ECC"

    return "Non-Crypto"


# ============================================================
# MAIN PIPELINE
# ============================================================

def process():

    files = sorted(glob.glob(os.path.join(TARGET_DIR, "*.json")))
    files = files[START_INDEX:END_INDEX]

    all_rows = []
    all_json = []

    for jf in files:
        with open(jf, "r", encoding="utf-8") as f:
            data = json.load(f)

        binary = data.get("binary", os.path.basename(jf))
        parts = binary.split("_")

        arch = parts[-3] if len(parts)>=4 else "unknown"
        compiler = parts[-2] if len(parts)>=4 else "unknown"
        opt = parts[-1].split(".")[0] if len(parts)>=4 else "unknown"

        for func in data.get("functions", []):

            fname = func.get("name","")
            addr = func.get("address", "")

            feats = extract_features(func)
            label = classify_ecc(fname)

            row = {
                "architecture": arch,
                "algorithm": label,
                "compiler": compiler,
                "optimization": opt,
                "filename": binary,
                "function_name": fname,
                "function_address": addr,
                "label": label,
                **feats
            }

            all_rows.append(row)

            all_json.append({
                "filename": binary,
                "function_name": fname,
                "function_address": addr,
                "label": label,
                "features": feats
            })

    # save JSON
    with open(OUTPUT_JSON, "w", encoding="utf-8") as jj:
        json.dump(all_json, jj, indent=2)

    # save CSV
    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as cf:
        writer = csv.DictWriter(cf, fieldnames=all_rows[0].keys())
        writer.writeheader()
        for r in all_rows:
            writer.writerow(r)

    print("[+] ECC dataset generated:")
    print("    JSON:", OUTPUT_JSON)
    print("    CSV :", OUTPUT_CSV)


if __name__ == "__main__":
    process()
