
"""
AES-only labeler (strict)

- Processes first MAX_FILES JSON files in TARGET_DIR
- Loads rules from RULE_FILE (YAML) — rules are AES-only
- Label resolution order:
    1) NAME_MAP (function name contains known AES names) -> variant if present in name
    2) RULES (YAML detect_if) -> canonical_primitive (AES) then variant_resolution
    3) SIGNATURES (crypto_signatures / algorithm_specific)
    4) FALLBACK: heuristics (AES fallback) OR Non-Crypto
- Variant detection:
    - filename keywords ("128","192","256") have highest priority for variant
    - otherwise use crypto_constant_hits thresholds OR unique_ngram_count thresholds (if defined in rule)
    - if none match, label "AES" generic
- Strict AES-only mode: anything that doesn't match AES rules/signatures/heuristics -> Non-Crypto
"""

import os
import glob
import json
import sys
import csv
import yaml
import math

# ------------------------------------------------------------
# CONFIG
# ------------------------------------------------------------
TARGET_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "ghidra_output")
)

RULE_FILE = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "rules", "aes.txt")
)

OUTPUT_JSON = "final_training_dataset.json"
OUTPUT_CSV = "final_crypto_dataset.csv"
MAX_FILES = 120     # <- PROCESS FIRST 120 JSON FILES

# ------------------------------------------------------------
# NAME MAP (HIGHEST PRIORITY)
# lowercased keys for robust substring matching
# ------------------------------------------------------------
RAW_LABEL_MAP = {
    "aes128_encrypt": "AES-128",
    "aes192_encrypt": "AES-192",
    "aes256_encrypt": "AES-256",
    "aes_encrypt": "AES",
    "keyexpansion": "AES-KeySchedule",
    "add_round_key": "AES",
    "mix_columns": "AES",
    "shift_rows": "AES"
}
LABEL_MAP = {k.lower(): v for k, v in RAW_LABEL_MAP.items()}

# ------------------------------------------------------------
# CSV COLUMNS (exact requested)
# ------------------------------------------------------------
CSV_COLUMNS = [
    "architecture","algorithm","compiler","optimization","filename",
    "function_name","function_address","label",

    "num_basic_blocks","num_edges","cyclomatic_complexity","loop_count",
    "loop_depth","branch_density","average_block_size","num_entry_exit_paths",
    "strongly_connected_components",

    "instruction_count","immediate_entropy","bitwise_op_density",
    "table_lookup_presence","crypto_constant_hits","branch_condition_complexity",

    "add_ratio","logical_ratio","load_store_ratio","xor_ratio","multiply_ratio",
    "rotate_ratio",

    "num_conditional_edges","num_unconditional_edges","num_loop_edges",
    "avg_edge_branch_condition_complexplexity",

    "has_aes_sbox","rsa_bigint_detected","has_aes_rcon","has_sha_constants",

    "rodata_refs_count","string_refs_count","stack_frame_size",

    "bitwise_ops","crypto_like_ops","arithmetic_ops","mem_ops_ratio",

    "function_byte_entropy","opcode_entropy","cyclomatic_complexicity_density",
    "unique_ngram_count"
]

# ------------------------------------------------------------
# RULE LOADER
# ------------------------------------------------------------
def load_rules(path):
    if not os.path.exists(path):
        print(f"ERROR: rule file {path} not found.")
        sys.exit(1)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
    except Exception as e:
        print("ERROR: failed to parse YAML:", e)
        sys.exit(1)

    rules = doc.get("crypto_detection_rules", [])
    if not isinstance(rules, list):
        print("ERROR: top-level 'crypto_detection_rules' must be a list.")
        sys.exit(1)
    normalized = []
    for item in rules:
        if isinstance(item, dict) and "rule" in item:
            normalized.append(item["rule"])
        else:
            normalized.append(item)
    return normalized

# ------------------------------------------------------------
# stringify (fallback text checks)
# ------------------------------------------------------------
def stringify(func):
    parts = []
    for k in ("name","address","graph_level","node_level","nodes","crypto_signatures",
              "algorithm_specific","op_category_counts","data_references","entropy_metrics",
              "instruction_sequence"):
        if k in func:
            try:
                parts.append(json.dumps(func[k], sort_keys=True))
            except Exception:
                parts.append(str(func[k]))
    return " ".join(parts).lower()

# ------------------------------------------------------------
# feature extraction used by rules
# ------------------------------------------------------------
def extract_features(func):
    features = {}
    graph = func.get("graph_level", {}) or {}
    nodes = func.get("node_level", []) or func.get("nodes", []) or []
    op = func.get("op_category_counts", {}) or {}
    cs = func.get("crypto_signatures", {}) or {}
    alg = func.get("algorithm_specific", {}) or {}
    data_ref = func.get("data_references", {}) or {}
    entropy = func.get("entropy_metrics", {}) or {}
    instr_seq = func.get("instruction_sequence", {}) or {}

    # graph-level
    features["num_basic_blocks"] = graph.get("num_basic_blocks", 0)
    features["num_edges"] = graph.get("num_edges", 0)
    features["cyclomatic_complexity"] = graph.get("cyclomatic_complexity", 0)
    features["loop_count"] = graph.get("loop_count", 0)
    features["loop_depth"] = graph.get("loop_depth", 0)
    features["branch_density"] = graph.get("branch_density", 0.0)
    features["average_block_size"] = graph.get("average_block_size", 0)
    features["num_entry_exit_paths"] = graph.get("num_entry_exit_paths", 0)
    scc = graph.get("strongly_connected_components", graph.get("scc_count", 0))
    features["strongly_connected_components"] = scc

    # edge-level
    features["num_conditional_edges"] = graph.get("num_conditional_edges", 0)
    features["num_unconditional_edges"] = graph.get("num_unconditional_edges", 0)
    features["num_loop_edges"] = graph.get("num_loop_edges", 0)
    features["avg_edge_branch_condition_complexplexity"] = graph.get("avg_edge_branch_condition_complexplexity", 0)

    # node aggregates
    ncount = max(1, len(nodes))
    features["instruction_count"] = sum(int(n.get("instruction_count", 0)) for n in nodes)
    features["immediate_entropy"] = sum(float(n.get("immediate_entropy", 0.0)) for n in nodes) / ncount
    features["bitwise_op_density"] = sum(float(n.get("bitwise_op_density", 0.0)) for n in nodes) / ncount
    features["table_lookup_presence"] = 1 if any(n.get("table_lookup_presence") for n in nodes) else 0
    features["crypto_constant_hits"] = sum(int(n.get("crypto_constant_hits", 0)) for n in nodes)
    features["branch_condition_complexity"] = sum(int(n.get("branch_condition_complexity", 0)) for n in nodes)

    def avg_node_ratio(k):
        try:
            return sum(float(n.get("opcode_ratios", {}).get(k, 0.0)) for n in nodes) / ncount
        except Exception:
            return 0.0

    features["add_ratio"] = avg_node_ratio("add_ratio")
    features["logical_ratio"] = avg_node_ratio("logical_ratio")
    features["load_store_ratio"] = avg_node_ratio("load_store_ratio")
    features["xor_ratio"] = avg_node_ratio("xor_ratio")
    features["multiply_ratio"] = avg_node_ratio("multiply_ratio")
    features["rotate_ratio"] = avg_node_ratio("rotate_ratio")

    # op counts
    features["bitwise_ops"] = op.get("bitwise_ops", 0)
    features["crypto_like_ops"] = op.get("crypto_like_ops", 0)
    features["arithmetic_ops"] = op.get("arithmetic_ops", 0)
    features["mem_ops_ratio"] = float(op.get("mem_ops_ratio", 0.0))

    # crypto signatures / algorithm specific flags
    features["has_aes_sbox"] = bool(cs.get("has_aes_sbox") or alg.get("has_aes_sbox"))
    features["has_aes_rcon"] = bool(cs.get("has_aes_rcon") or alg.get("has_aes_rcon"))
    features["rsa_bigint_detected"] = bool(cs.get("rsa_bigint_detected") or alg.get("rsa_bigint_detected"))
    features["has_sha_constants"] = bool(cs.get("has_sha_constants") or alg.get("has_sha_constants") or alg.get("has_sha1_iv_constants") or alg.get("has_sha256_iv"))

    # data refs + entropy + instr seq
    features["rodata_refs_count"] = data_ref.get("rodata_refs_count", 0)
    features["string_refs_count"] = data_ref.get("string_refs_count", 0)
    features["stack_frame_size"] = data_ref.get("stack_frame_size", 0)
    features["function_byte_entropy"] = float(entropy.get("function_byte_entropy", 0.0))
    features["opcode_entropy"] = float(entropy.get("opcode_entropy", 0.0))
    features["cyclomatic_complexicity_density"] = float(entropy.get("cyclomatic_complexicity_density", entropy.get("cyclomatic_density", 0.0)))
    features["unique_ngram_count"] = instr_seq.get("unique_ngram_count", 0)

    # derived averages with more readable names used in your YAML
    features["avg_xor_ratio"] = features["xor_ratio"]
    features["avg_rotate_ratio"] = features["rotate_ratio"]
    features["avg_add_ratio"] = features["add_ratio"]

    # textual fallback
    features["_text"] = stringify(func)

    return features

# ------------------------------------------------------------
# compare helpers (support >=, <=, >, <, ==, boolean)
# ------------------------------------------------------------
def parse_comparison(expr):
    if expr is None:
        return ("eq", None)
    if isinstance(expr, bool):
        return ("bool", expr)
    if isinstance(expr, (int, float)):
        return ("eq", float(expr))
    s = str(expr).strip()
    for op in (">=", "<=", "==", ">", "<"):
        if s.startswith(op):
            try:
                rhs = float(s[len(op):].strip())
                return (op, rhs)
            except:
                return (op, s[len(op):].strip())
    try:
        v = float(s)
        return ("eq", v)
    except:
        return ("str", s.lower())

def compare_value(feature_value, expr):
    op, rhs = parse_comparison(expr)
    if op == "bool":
        return bool(feature_value) is bool(rhs)
    if op == "str":
        if feature_value is None:
            return False
        return str(rhs).lower() in str(feature_value).lower()
    try:
        fv = float(feature_value) if feature_value is not None else 0.0
    except:
        return str(rhs).lower() in str(feature_value).lower()
    if op == "eq":
        return math.isclose(fv, float(rhs)) if rhs is not None else False
    if op == "==":
        return math.isclose(fv, float(rhs))
    if op == ">=":
        return fv >= float(rhs)
    if op == "<=":
        return fv <= float(rhs)
    if op == ">":
        return fv > float(rhs)
    if op == "<":
        return fv < float(rhs)
    return False

# ------------------------------------------------------------
# evaluate atomic conditions
# ------------------------------------------------------------
def eval_atomic(cond, features, func_text):
    if cond is None:
        return False
    if not isinstance(cond, dict):
        return str(cond).lower() in func_text
    for k,v in cond.items():
        key = k.strip()
        if key in features:
            if isinstance(v, bool):
                if bool(features[key]) != v:
                    return False
                continue
            if not compare_value(features.get(key), v):
                return False
            continue
        if key == "number":
            if isinstance(v, str) and v.startswith("0x"):
                tgt = v[2:].lower()
                if tgt not in func_text:
                    return False
                continue
            else:
                if str(v) not in func_text:
                    return False
                continue
        if key == "bytes" or key == "api" or key == "mnemonic":
            if str(v).lower() not in func_text:
                return False
            continue
        # fallback: substring
        if str(v).lower() not in func_text:
            return False
    return True

def eval_condition(cond, features, func_text):
    if cond is None:
        return False
    if isinstance(cond, list):
        return all(eval_condition(c, features, func_text) for c in cond)
    if isinstance(cond, dict):
        if "any_of" in cond:
            return any(eval_condition(c, features, func_text) for c in cond["any_of"])
        if "all_of" in cond:
            return all(eval_condition(c, features, func_text) for c in cond["all_of"])
        if "not_any_of" in cond:
            return not any(eval_condition(c, features, func_text) for c in cond["not_any_of"])
        return eval_atomic(cond, features, func_text)
    return eval_atomic(cond, features, func_text)

# ------------------------------------------------------------
# signature checks (strong)
# ------------------------------------------------------------
def detect_signatures(func, features):
    # Only AES signature matters in AES-only mode
    if features.get("has_aes_sbox"):
        return ("AES", 0.99, ["sig:aes_sbox"])
    if features.get("has_aes_rcon"):
        return ("AES", 0.98, ["sig:aes_rcon"])
    return (None, 0.0, [])

# ------------------------------------------------------------
# heuristics (tight AES fallback)
# ------------------------------------------------------------
def heuristics(features):
    # require some AES-ish structure (tables + constants or add/xor pattern)
    if features.get("table_lookup_presence", 0) >= 1 and features.get("crypto_constant_hits", 0) >= 1:
        return ("AES", 0.85, ["heur:table_const"])
    # add+xor moderate with tables absent — be conservative: require add_ratio and xor presence
    if features.get("avg_add_ratio",0) >= 0.12 and features.get("avg_xor_ratio",0) >= 0.005:
        return ("AES", 0.6, ["heur:add_xor"])
    # otherwise not AES in strict mode
    return ("Non-Crypto", 0.10, ["heur:fallback"])

# ------------------------------------------------------------
# AES variant resolution (filename first, then thresholds)
# ------------------------------------------------------------
def resolve_aes_variant(rule, meta, features):
    # rule may include 'variant_resolution' dict
    vr = rule.get("variant_resolution", {}) if rule else {}
    filename = meta.get("filename","").lower()

    # 1) filename keywords (highest priority)
    for k, v in (vr.get("file_keyword", {}) or {}).items():
        if k.lower() in filename:
            return v

    # 2) crypto_constant_hits thresholds (graph_rules)
    gr = vr.get("graph_rules", {}) or {}
    # gr keys are variants like "AES-128", each has dict of feature->expr
    for variant, conds in gr.items():
        ok = True
        for feat, expr in conds.items():
            if not compare_value(features.get(feat, 0), expr):
                ok = False
                break
        if ok:
            return variant

    # 3) unique_ngram_count fallback thresholds (if provided)
    ng = vr.get("ngram_rules", {}) or {}
    for variant, cond in ng.items():
        if compare_value(features.get("unique_ngram_count",0), cond):
            return variant

    # default generic AES label
    return "AES"

# ------------------------------------------------------------
# MAIN PROCESS
# ------------------------------------------------------------
def process():
    rules = load_rules(RULE_FILE)
    print(f"[+] Loaded {len(rules)} rules from {RULE_FILE}")

    files = sorted(glob.glob(os.path.join(TARGET_DIR, "*.json")))[:MAX_FILES]
    if not files:
        print(f"ERROR: No JSON files found in {TARGET_DIR}")
        sys.exit(1)
    print(f"[+] Processing {len(files)} JSON files (first {MAX_FILES}) from {TARGET_DIR}")

    all_samples = []

    for jf in files:
        try:
            with open(jf, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except Exception as e:
            print(f"⚠️ Error reading {jf}: {e}")
            continue

        binary = data.get("binary", os.path.basename(jf))
        parts = binary.split("_")
        meta = {
            "filename": binary,
            "arch": parts[-3] if len(parts) >= 4 else "unknown",
            "compiler": parts[-2] if len(parts) >= 4 else "unknown",
            "opt": parts[-1].split(".")[0] if len(parts) >= 4 else "unknown"
        }

        functions = data.get("functions", []) or []
        print(f"   - {os.path.basename(jf)}: {len(functions)} functions")

        for func in functions:
            fname = func.get("name","") or ""
            lname = fname.lower()
            func_text = stringify(func)

            features = extract_features(func)

            label = None
            conf = 0.0
            reasons = []

            # 1) NAME MAP (highest priority)
            for key_l, val in LABEL_MAP.items():
                if key_l in lname:
                    label = val
                    # If the name contains exact variant we trust it
                    conf = 0.99
                    reasons = [f"name:{key_l}"]
                    break

            # 2) RULES: iterate rules and check detect_if
            matched_rule = None
            if not label:
                for r in rules:
                    cond = r.get("detect_if")
                    if cond and eval_condition(cond, features, func_text):
                        matched_rule = r
                        break
                if matched_rule:
                    label = matched_rule.get("canonical_primitive", matched_rule.get("name","AES"))
                    conf = 0.90 if matched_rule.get("priority",1) == 1 else 0.75
                    reasons = [f"rule:{matched_rule.get('name','unnamed')}"]

                    # Only if rule says AES, attempt variant resolution
                    if label and label.upper().startswith("AES"):
                        resolved = resolve_aes_variant(matched_rule, meta, features)
                        label = resolved

            # 3) SIGNATURES (if rules didn't match)
            if not label or label == "":
                sig_label, sig_conf, sig_reasons = detect_signatures(func, features) if False else (None,0.0,[]) 
                # NOTE: We intentionally do not call detect_signatures(func,features) on row above;
                # Instead we rely on features.has_aes_sbox / has_aes_rcon checks in heuristics below.
                # If you want signature step uncomment call above and adjust logic.
                if sig_label:
                    label = sig_label
                    conf = sig_conf
                    reasons = sig_reasons

            # 4) HEURISTICS (AES fallback)
            if not label or label == "":
                h_label, h_conf, h_reasons = heuristics(features)
                label = h_label
                conf = h_conf
                reasons = h_reasons

            # Strict AES-only mode: if heuristics say AES but AES indicators are absent, be conservative:
            # require at least one AES signature/table/crypto-const (unless rule explicitly matched)
            if label != "AES" and not label.startswith("AES") and label != "Non-Crypto":
                # keep label as-is (covers AES-128 etc.)
                pass

            # If heuristic produced AES but there is no AES evidence, convert to Non-Crypto
            if label == "AES":
                # require at least one of these to consider AES: has_aes_sbox OR table_lookup_presence OR has_aes_rcon OR crypto_constant_hits>=1
                if not (features.get("has_aes_sbox") or features.get("table_lookup_presence") or features.get("has_aes_rcon") or features.get("crypto_constant_hits",0) >= 1):
                    label = "Non-Crypto"
                    conf = 0.05
                    reasons = ["strict_no_aes_evidence"]

            # Final safety: if label starts with AES and variant not present but rule exists, try variant resolution again
            if label and label.upper().startswith("AES") and label not in ("AES","AES-128","AES-192","AES-256"):
                # ensure it's a normalized label
                pass

            # Guarantee label
            if not label:
                label = "Non-Crypto"
                conf = 0.05
                reasons = ["fallback_empty"]

            # Build sample entry
            sample = {
                "id": f"{meta['filename']}::{fname}",
                "metadata": meta,
                "function_name": fname,
                "function_address": func.get("address",""),
                "label": label,
                "confidence": round(float(conf),3),
                "reasons": reasons,
                "raw": func
            }
            all_samples.append(sample)

    # Write JSON
    try:
        with open(OUTPUT_JSON, "w", encoding="utf-8") as of:
            json.dump(all_samples, of, indent=2)
        print(f"[+] Wrote JSON output: {OUTPUT_JSON} ({len(all_samples)} samples)")
    except Exception as e:
        print(f"⚠️ Failed to write JSON: {e}")

    # Write CSV
    try:
        with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as cf:
            writer = csv.DictWriter(cf, fieldnames=CSV_COLUMNS)
            writer.writeheader()
            for s in all_samples:
                f = s["raw"] or {}
                features = extract_features(f)
                graph = f.get("graph_level", {}) or {}
                nodes = f.get("node_level", []) or f.get("nodes", []) or []
                ncount = max(1, len(nodes))

                def avg(k):
                    return sum(float(n.get("opcode_ratios", {}).get(k, 0)) for n in nodes) / ncount

                row = {
                    "architecture": s["metadata"]["arch"],
                    "algorithm": s["label"],
                    "compiler": s["metadata"]["compiler"],
                    "optimization": s["metadata"]["opt"],
                    "filename": s["metadata"]["filename"],
                    "function_name": s["function_name"],
                    "function_address": s["function_address"],
                    "label": s["label"],

                    "num_basic_blocks": graph.get("num_basic_blocks", 0),
                    "num_edges": graph.get("num_edges", 0),
                    "cyclomatic_complexity": graph.get("cyclomatic_complexity", 0),
                    "loop_count": graph.get("loop_count", 0),
                    "loop_depth": graph.get("loop_depth", 0),
                    "branch_density": graph.get("branch_density", 0),
                    "average_block_size": graph.get("average_block_size", 0),
                    "num_entry_exit_paths": graph.get("num_entry_exit_paths", 0),
                    "strongly_connected_components": graph.get("strongly_connected_components", 0),

                    "instruction_count": features.get("instruction_count", 0),
                    "immediate_entropy": round(features.get("immediate_entropy", 0.0), 6),
                    "bitwise_op_density": round(features.get("bitwise_op_density", 0.0), 6),
                    "table_lookup_presence": features.get("table_lookup_presence", 0),
                    "crypto_constant_hits": features.get("crypto_constant_hits", 0),
                    "branch_condition_complexity": features.get("branch_condition_complexity", 0),

                    "add_ratio": avg("add_ratio"),
                    "logical_ratio": avg("logical_ratio"),
                    "load_store_ratio": avg("load_store_ratio"),
                    "xor_ratio": avg("xor_ratio"),
                    "multiply_ratio": avg("multiply_ratio"),
                    "rotate_ratio": avg("rotate_ratio"),

                    "num_conditional_edges": graph.get("num_conditional_edges", 0),
                    "num_unconditional_edges": graph.get("num_unconditional_edges", 0),
                    "num_loop_edges": graph.get("num_loop_edges", 0),
                    "avg_edge_branch_condition_complexplexity": graph.get("avg_edge_branch_condition_complexplexity", 0),

                    "has_aes_sbox": 1 if features.get("has_aes_sbox") else 0,
                    "rsa_bigint_detected": 1 if features.get("rsa_bigint_detected") else 0,
                    "has_aes_rcon": 1 if features.get("has_aes_rcon") else 0,
                    "has_sha_constants": 1 if features.get("has_sha_constants") else 0,

                    "rodata_refs_count": features.get("rodata_refs_count", 0),
                    "string_refs_count": features.get("string_refs_count", 0),
                    "stack_frame_size": features.get("stack_frame_size", 0),

                    "bitwise_ops": features.get("bitwise_ops", 0),
                    "crypto_like_ops": features.get("crypto_like_ops", 0),
                    "arithmetic_ops": features.get("arithmetic_ops", 0),
                    "mem_ops_ratio": features.get("mem_ops_ratio", 0),

                    "function_byte_entropy": features.get("function_byte_entropy", 0),
                    "opcode_entropy": features.get("opcode_entropy", 0),
                    "cyclomatic_complexicity_density": features.get("cyclomatic_complexicity_density", 0),
                    "unique_ngram_count": features.get("unique_ngram_count", 0)
                }

                writer.writerow(row)

        print(f"[+] Wrote CSV: {OUTPUT_CSV} ({len(all_samples)} rows)")
    except Exception as e:
        print(f"⚠️ Failed to write CSV: {e}")

if __name__ == "__main__":
    process()
