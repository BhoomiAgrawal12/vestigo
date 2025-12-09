
import json
import argparse
from pathlib import Path
import datetime
import os
from typing import Any, Dict

from dotenv import load_dotenv
load_dotenv()

from openai import OpenAI


# -----------------------------------------
# Load text file with safe fallback
# -----------------------------------------
def load_text(path: str) -> str:
    file_path = Path(path)

    if not file_path.exists():
        parent_path = Path("..") / path
        if parent_path.exists():
            file_path = parent_path
        else:
            raise FileNotFoundError(f"File not found: {path}")

    return file_path.read_text(encoding="utf-8", errors="ignore")


# -----------------------------------------
# Build LLM prompt for STRACE ONLY
# -----------------------------------------
def build_strace_prompt(strace_log: str) -> str:
    return f"""
You are a world-class firmware cryptography analyst.

You are given ONLY a Linux STRACE syscall log for a single execution of a binary.

Your job is to THINK CAREFULLY and decide, based ONLY on what STRACE can reveal:

1. Does this execution involve any cryptographic behavior at all?
   - Look for:
     - getrandom()/urandom usage
     - read/write of suspicious binary buffers
     - "Original" vs "Encrypted" style prints
     - repeated patterns suggesting encryption, hashing, or key generation
   - If there is clearly no crypto-like activity, classify as NON_CRYPTO.

2. If there IS crypto-like behavior, decide whether it is:
   - STANDARD_CRYPTO:
     One of the following algorithms:
     [
       "AES", "ARIA", "CMAC", "Camellia", "ChaCha20",
       "DES", "DH", "DSA", "ECC", "HMAC", "MD5",
       "RSA", "SEED", "SHA-1", "SHA-224", "SHA-256",
       "SHA-3", "SHA-512"
     ]
   - PROPRIETARY_CRYPTO:
     A custom / home-grown / non-standard cipher, stream, hash, or MAC.

   You MUST NOT blindly default to AES or any other algorithm.
   - Only choose "AES" if the behavior strongly matches AES usage patterns.
   - Only choose another STANDARD algorithm if there is a solid, defensible reason.
   - If the behavior is clearly crypto but does NOT convincingly match any standard algorithm,
     THEN (and only then) classify as PROPRIETARY_CRYPTO.

3. For PROPRIETARY_CRYPTO:
   - Provide a detailed technical analysis grounded in FACTS visible in STRACE:
     - getrandom() usage and size
     - printed "Original:" / "Encrypted:" buffers and their lengths
     - number and sequence of syscalls
     - lack of large mmap() regions typical of big crypto libraries
     - small memory footprint or very short execution
   - Explain WHY it does not fit known standard algorithms:
     - e.g., simple 1-byte-to-1-byte mapping,
       XOR+rotate style behavior,
       no indication of block structure,
       no heavy memory usage,
       no repeated read/write of big buffers, etc.
   - For the field "crypto_algorithm" in this case, you SHOULD provide a short descriptive label like:
     - "proprietary_stream_cipher"
     - "proprietary_xor_rotate_cipher"
     - "proprietary_block_cipher"
     - "proprietary_hash_like_function"
     rather than just the generic word "proprietary".

4. For STANDARD_CRYPTO:
   - Set "crypto_algorithm" to the exact name from the allowed list
     (e.g., "AES", "ChaCha20", "SHA-256", "RSA").
   - Give short reasoning based on STRACE evidence (e.g., key-gen patterns, repeated reads/writes, etc.).

5. For NON_CRYPTO:
   - Set "crypto_classification" to "NON_CRYPTO".
   - Set "crypto_algorithm" to "none".
   - Explain why the behavior appears non-cryptographic.

Your mandatory JSON output format (no extra keys, no extra text):

{{
  "crypto_classification": "STANDARD_CRYPTO" | "PROPRIETARY_CRYPTO" | "NON_CRYPTO",
  "crypto_algorithm": "",           // STANDARD: one of the list; PROPRIETARY: descriptive label like 'proprietary_xor_rotate_cipher'; NON_CRYPTO: 'none'
  "is_proprietary": false,          // true only when crypto_classification == "PROPRIETARY_CRYPTO"
  "reasoning": "",                  // High-level explanation (2–8 sentences), grounded in STRACE facts
  "confidence": 0.0,                // 0.0 – 1.0, reflect your uncertainty realistically

  "proprietary_analysis": {{
    "summary": "",                  // Short description of the suspected proprietary scheme, or empty string if not proprietary
    "evidence": [                   // Concrete facts grounded in STRACE
      {{
        "fact": "",                 // e.g., "getrandom() is called once to obtain 8 bytes"
        "support": ""               // e.g., "Observed syscall: getrandom(..., 8, GRND_NONBLOCK) = 8 before write() of encrypted buffer"
      }}
    ]
  }}
}}

Rules:
- If crypto_classification != "PROPRIETARY_CRYPTO":
  - "is_proprietary": false
  - "proprietary_analysis.summary": ""
  - "proprietary_analysis.evidence": []
- You MUST return ONLY valid JSON with this exact structure.
- Do NOT include any explanation outside the JSON object.

────────────────────────────────────────
STRACE LOG:
────────────────────────────────────────
{strace_log}
"""


# -----------------------------------------
# LLM call for STRACE ONLY
# -----------------------------------------
def call_llm(prompt: str) -> Dict[str, Any]:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("Missing OPENAI_API_KEY")

    client = OpenAI(api_key=api_key)

    response = client.chat.completions.create(
        model="gpt-4o",

        messages=[
            {
                "role": "system",
                "content": "You must return ONLY valid JSON that strictly follows the requested schema."
            },
            {"role": "user", "content": prompt}
        ],
        response_format={"type": "json_object"},
        temperature=0,
        max_tokens=4096
    )

    return json.loads(response.choices[0].message.content)


# -----------------------------------------
# MAIN ENGINE
# -----------------------------------------
def run_engine(analysis_file: str, strace_file: str, out_file: str):

    # Load RAW analysis file (NO LLM PROCESSING)
    print(f"[*] Loading analysis file: {analysis_file}")
    analysis_raw = load_text(analysis_file)

    # Load STRACE file and send only STRACE to LLM
    print(f"[*] Loading strace file: {strace_file}")
    strace_raw = load_text(strace_file)

    print("[*] Running LLM analysis on STRACE...")
    strace_result = call_llm(build_strace_prompt(strace_raw))

    # Build final JSON output with two sections
    final = {
        "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
        "analysis_file": analysis_file,
        "strace_file": strace_file,

        # RAW analysis section
        "analysis_section": analysis_raw,

        # LLM-evaluated STRACE section
        "strace_section": strace_result
    }

    Path(out_file).write_text(json.dumps(final, indent=2), encoding="utf-8")
    print(f"[✓] Final combined report saved → {out_file}")

    return final


# -----------------------------------------
# CLI
# -----------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Two-Stage Crypto Analyzer (Analysis RAW + STRACE LLM)"
    )

    # Allow both --analysis and legacy --input
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--analysis", help="Analysis log file (preferred)")
    group.add_argument("--input", help="Alias for analysis log file (legacy flag)")

    parser.add_argument("--strace", required=True, help="Strace log file")
    parser.add_argument("--out", default="final_report.json", help="Output JSON file")

    args = parser.parse_args()

    analysis_file = args.analysis or args.input
    strace_file = args.strace
    out_file = args.out

    run_engine(analysis_file, strace_file, out_file)


if __name__ == "__main__":
    main()
