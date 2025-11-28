import os
import glob
import json
import csv
import math

# ============================================================
# CONFIG
# ============================================================
TARGET_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "ghidra_output")
)

OUTPUT_JSON = "sha_training_dataset.json"
OUTPUT_CSV  = "sha_crypto_dataset.csv"

START_INDEX = 280     # Your SHA dataset range
END_INDEX   = 360


# ============================================================
# SHA NAME MATCH (HIGHEST PRIORITY)
# ============================================================

SHA1_FUNCS = {
    "sha1_transform", "sha1_init", "sha1_update", "sha1_final"
}

SHA224_FUNCS = {
    "sha224_transform", "sha224_init", "sha224_update", "sha224_final"
}


# ============================================================
# VARIANT FROM FILENAME
# ============================================================

def infer_variant(filename):
    lf = filename.lower()
    if "sha224" in lf or "sha-224" in lf:
        return "SHA-224"
    if "sha1" in lf:
        return "SHA-1"
    return "SHA"


# ============================================================
# STRINGIFY + FEATURE EXTRACTION
# ============================================================

def stringify(func):
    try:
        return json.dumps(func, sort_keys=True).lower()
    except:
        return str(func).lower()


def extract_features(func):
    f = {}
    graph = func.get("graph_level", {})
    nodes = func.get("node_level", [])
    op    = func.get("op_category_counts", {})
    cs    = func.get("crypto_signatures", {})
    data  = func.get("data_references", {})
    ent   = func.get("entropy_metrics", {})
    seq   = func.get("instruction_sequence", {})

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

    # counts
    f["instruction_count"] = sum(n.get("instruction_count", 0) for n in nodes)
    f["immediate_entropy"] = sum(n.get("immediate_entropy", 0) for n in nodes)/ncount
    f["bitwise_op_density"] = sum(n.get("bitwise_op_density", 0) for n in nodes)/ncount
    f["crypto_constant_hits"] = sum(n.get("crypto_constant_hits", 0) for n in nodes)
    f["branch_condition_complexity"] = sum(
        n.get("branch_condition_complexity", 0) for n in nodes
    )

    # opcode ratios
    def avg_ratio(key):
        return sum(n.get("opcode_ratios", {}).get(key, 0) for n in nodes) / ncount

    for r in ["add_ratio","logical_ratio","load_store_ratio",
              "xor_ratio","multiply_ratio","rotate_ratio"]:
        f[r] = avg_ratio(r)

    # crypto flags
    f["has_aes_sbox"]       = bool(cs.get("has_aes_sbox"))
    f["rsa_bigint_detected"]= bool(cs.get("rsa_bigint_detected"))
    f["has_aes_rcon"]       = bool(cs.get("has_aes_rcon"))
    f["has_sha_constants"]  = bool(cs.get("has_sha_constants"))

    # data refs
    f["rodata_refs_count"] = data.get("rodata_refs_count",0)
    f["string_refs_count"] = data.get("string_refs_count",0)
    f["stack_frame_size"] = data.get("stack_frame_size",0)

    # op categories
    f["bitwise_ops"]       = op.get("bitwise_ops",0)
    f["crypto_like_ops"]   = op.get("crypto_like_ops",0)
    f["arithmetic_ops"]    = op.get("arithmetic_ops",0)
    f["mem_ops_ratio"]     = float(op.get("mem_ops_ratio",0))

    # entropy
    f["function_byte_entropy"] = ent.get("function_byte_entropy",0)
    f["opcode_entropy"] = ent.get("opcode_entropy",0)
    f["cyclomatic_complexity_density"] = ent.get("cyclomatic_complexity_density",0)

    # ngrams
    f["unique_ngram_count"] = seq.get("unique_ngram_count", 0)

    f["_text"] = stringify(func)
    return f


# ============================================================
# LABEL ONLY SHA FUNCTIONS
# ============================================================

def classify_sha(func_name, filename):
    lname = func_name.lower()

    if lname in SHA1_FUNCS:
        return "SHA-1"

    if lname in SHA224_FUNCS:
        return "SHA-224"

    return "Non-Crypto"


# ============================================================
# FILE METADATA EXTRACTION
# ============================================================

def extract_metadata(filename):
    """
    Expected filename format:
    sha1_x86_gcc_O2.json
    sha224_arm_clang_O3.json
    sha1_avr_gcc_O0.json
    """
    base = os.path.basename(filename).replace(".json","")
    parts = base.split("_")

    architecture = "unknown"
    compiler = "unknown"
    optimization = "unknown"

    if len(parts) >= 4:
        architecture = parts[-3]
        compiler     = parts[-2]
        optimization = parts[-1]

    return architecture, compiler, optimization


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

            label = classify_sha(fname, binary)

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

    # Save JSON
    with open(OUTPUT_JSON,"w",encoding="utf-8") as j:
        json.dump(all_rows, j, indent=2)

    # Save CSV
    with open(OUTPUT_CSV,"w",newline="",encoding="utf-8") as cf:
        writer = csv.DictWriter(cf, fieldnames=all_rows[0].keys())
        writer.writeheader()
        writer.writerows(all_rows)

    print("[+] SHA dataset written:", OUTPUT_JSON, OUTPUT_CSV)


if __name__ == "__main__":
    process()
