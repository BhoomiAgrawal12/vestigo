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
    os.path.join(os.path.dirname(__file__), "..", "..", "test_dataset_json")
)

OUTPUT_JSON = "ecc_training_dataset.json"
OUTPUT_CSV  = "ecc_crypto_dataset.csv"

START_INDEX = 135   # ECC dataset start
END_INDEX   = 155   # ECC dataset end index


# ============================================================
# STRICT ECC FUNCTION NAMES (BASED ON YOUR DUMP)
# ============================================================

ECC_NAMES = {
    # curve setup
    "init_demo_curve",

    # point operations
    "point_double",
    "point_infinity",
    "point_add",
    "point_is_equal",

    # scalar multiplication
    "scalar_mul",

    # ecdh key exchange
    "gen_keypair",
    "compute_shared",

    # ecdsa
    "ecdsa_sign_toy",
    "ecdsa_verify_toy",

    # printing
    "print_point",

    # field arithmetic mod p
    "mod_add",
    "mod_sub",
    "mod_mul",
    "mod_inv",
    "mod_pow",
    "modnorm",

    # number theory helpers
    "egcd",
    "__umodti3",
    "__clzdi2",
}

ECC_NAMES = {name.lower() for name in ECC_NAMES}


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
    nodes = func.get("node_level", []) or func.get("nodes", []) or []
    op = func.get("op_category_counts", {}) or {}
    cs = func.get("crypto_signatures", {}) or {}
    data_ref = func.get("data_references", {}) or {}
    entropy = func.get("entropy_metrics", {}) or {}
    seq = func.get("instruction_sequence", {}) or {}

    n = max(1, len(nodes))

    # graph metrics
    graph_keys = [
        "num_basic_blocks","num_edges","cyclomatic_complexity","loop_count",
        "loop_depth","branch_density","average_block_size",
        "num_entry_exit_paths","strongly_connected_components",
        "num_conditional_edges","num_unconditional_edges","num_loop_edges",
        "avg_edge_branch_condition_complexplexity"
    ]
    for k in graph_keys:
        f[k] = graph.get(k, 0)

    # instruction-level aggregation
    f["instruction_count"] = sum(n_.get("instruction_count",0) for n_ in nodes)
    f["immediate_entropy"] = sum(n_.get("immediate_entropy",0) for n_ in nodes)/n
    f["bitwise_op_density"] = sum(n_.get("bitwise_op_density",0) for n_ in nodes)/n
    f["crypto_constant_hits"] = sum(n_.get("crypto_constant_hits",0) for n_ in nodes)
    f["branch_condition_complexity"] = sum(n_.get("branch_condition_complexity",0) for n_ in nodes)

    # opcode ratio averages
    def avg_ratio(field):
        return sum(n_.get("opcode_ratios",{}).get(field,0) for n_ in nodes)/n

    for r in ["add_ratio","logical_ratio","load_store_ratio","xor_ratio",
              "multiply_ratio","rotate_ratio"]:
        f[r] = avg_ratio(r)

    # crypto signature flags
    f["has_aes_sbox"] = bool(cs.get("has_aes_sbox"))
    f["rsa_bigint_detected"] = bool(cs.get("rsa_bigint_detected"))
    f["has_aes_rcon"] = bool(cs.get("has_aes_rcon"))
    f["has_sha_constants"] = bool(cs.get("has_sha_constants"))

    # data references
    f["rodata_refs_count"] = data_ref.get("rodata_refs_count", 0)
    f["string_refs_count"] = data_ref.get("string_refs_count", 0)
    f["stack_frame_size"] = data_ref.get("stack_frame_size", 0)

    # operation categories
    f["bitwise_ops"] = op.get("bitwise_ops", 0)
    f["crypto_like_ops"] = op.get("crypto_like_ops", 0)
    f["arithmetic_ops"] = op.get("arithmetic_ops", 0)
    f["mem_ops_ratio"] = float(op.get("mem_ops_ratio", 0.0))

    # entropy metrics
    f["function_byte_entropy"] = entropy.get("function_byte_entropy", 0)
    f["opcode_entropy"] = entropy.get("opcode_entropy", 0)
    f["cyclomatic_complexicity_density"] = entropy.get("cyclomatic_complexity_density", 0)

    f["unique_ngram_count"] = seq.get("unique_ngram_count", 0)

    # raw text
    f["_text"] = stringify(func)

    return f


# ============================================================
# STRICT NAME-BASED ECC CLASSIFICATION
# ============================================================

def classify_ecc(name):
    return "ECC" if name.lower() in ECC_NAMES else "Non-Crypto"


# ============================================================
# MAIN PIPELINE
# ============================================================

def process():

    files = sorted(glob.glob(os.path.join(TARGET_DIR, "*.json")))
    files = files[START_INDEX:END_INDEX]

    rows = []
    jdata = []

    for jf in files:
        with open(jf, "r", encoding="utf-8") as f:
            data = json.load(f)

        binary = data.get("binary", os.path.basename(jf))
        parts = binary.split("_")

        arch = parts[-3] if len(parts)>=4 else "unknown"
        compiler = parts[-2] if len(parts)>=4 else "unknown"
        opt = parts[-1].split(".")[0] if len(parts)>=4 else "unknown"

        for func in data.get("functions", []):
            fname = func.get("name", "")
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

            rows.append(row)

            jdata.append({
                "filename": binary,
                "function_name": fname,
                "function_address": addr,
                "label": label,
                "features": feats
            })

    # JSON output
    with open(OUTPUT_JSON, "w", encoding="utf-8") as jf:
        json.dump(jdata, jf, indent=2)

    # CSV output
    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as cf:
        writer = csv.DictWriter(cf, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    print("[+] ECC dataset generated:")
    print("    JSON:", OUTPUT_JSON)
    print("    CSV :", OUTPUT_CSV)


if __name__ == "__main__":
    process()
