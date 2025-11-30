#!/usr/bin/env python3
"""
Run feature extraction on test dataset binaries using ghidra_scripts/extract_features.py
and store results in test_outputs.
"""
import os
import subprocess
import json
import glob
import time
import shutil
from datetime import datetime

# Configuration
GHIDRA_HOME = "/opt/ghidra"
BINARY_DIR = "test_dataset_binaries"
OUTPUT_DIR = "test_outputs"
TEMP_OUTPUT_DIR = "test_dataset_json" # Default output of the script
PROJECT_DIR = "/tmp/ghidra_test_project"
PROJECT_NAME = "test_extraction"
SCRIPT_PATH = "ghidra_scripts/extract_features.py"
BATCH_SIZE = 20
TIMEOUT_PER_BINARY = 300

def run_ghidra_extraction(binary_path):
    """Run Ghidra headless analysis on a binary"""
    analyzer_bin = os.path.join(GHIDRA_HOME, "support", "analyzeHeadless")
    binary_name = os.path.basename(binary_path)
    
    # Ensure temp project dir exists
    os.makedirs(PROJECT_DIR, exist_ok=True)
    
    # The script writes to test_dataset_json in the project root (current dir)
    # We pass the current directory as the project root argument to the script
    # to ensure it writes where we expect.
    cwd = os.getcwd()
    
    cmd = [
        analyzer_bin,
        PROJECT_DIR,
        PROJECT_NAME,
        "-import", binary_path,
        "-postScript", os.path.abspath(SCRIPT_PATH),
        cwd, # Argument to script: Project Root
        "-deleteProject"
    ]
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=cwd,
            timeout=TIMEOUT_PER_BINARY
        )
        
        # Check for output in the default location
        # The script sanitizes the name: safe_name = "".join(c if c.isalnum() or c in "-_." else "_" for c in program_name)
        # Usually binary_name is safe enough, but let's replicate logic if needed.
        # For now assume binary_name + "_features.json"
        
        safe_name = "".join(c if c.isalnum() or c in "-_." else "_" for c in binary_name)
        json_filename = f"{safe_name}_features.json"
        source_json = os.path.join(TEMP_OUTPUT_DIR, json_filename)
        
        if os.path.exists(source_json):
            # Move to final destination
            dest_json = os.path.join(OUTPUT_DIR, json_filename)
            shutil.move(source_json, dest_json)
            
            # Validate
            with open(dest_json, 'r') as f:
                data = json.load(f)
            return True, len(data.get('functions', []))
        else:
            # Debug: print stderr if failed
            # print(f"Stderr: {result.stderr[-200:]}")
            return False, 0
            
    except subprocess.TimeoutExpired:
        return False, 0
    except Exception as e:
        print(f"Exception: {e}")
        return False, 0

def main():
    start_time = time.time()
    
    print("=" * 80)
    print("TEST DATASET FEATURE EXTRACTION")
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 80)
    
    # Setup directories
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    # Ensure temp dir exists so script doesn't fail if it tries to check it
    os.makedirs(TEMP_OUTPUT_DIR, exist_ok=True)
    
    # Find binaries
    binaries = sorted(glob.glob(os.path.join(BINARY_DIR, "*.elf")))
    # Add other types if needed, e.g. .ihx
    binaries.extend(sorted(glob.glob(os.path.join(BINARY_DIR, "*.ihx"))))
    
    if not binaries:
        print(f"✗ No binaries found in {BINARY_DIR}")
        return
        
    print(f"Found {len(binaries)} binaries")
    print(f"Output directory: {OUTPUT_DIR}")
    print()
    
    results = {
        'success': 0,
        'failed': 0,
        'total_functions': 0,
        'failed_binaries': []
    }
    
    # Process
    for i, binary_path in enumerate(binaries):
        binary_name = os.path.basename(binary_path)
        
        # Check if output already exists
        safe_name = "".join(c if c.isalnum() or c in "-_." else "_" for c in binary_name)
        json_filename = f"{safe_name}_features.json"
        dest_json = os.path.join(OUTPUT_DIR, json_filename)
        
        if os.path.exists(dest_json):
            print(f"[{i+1}/{len(binaries)}] {binary_name[:40]:40s} ⏭️  SKIP")
            results['success'] += 1
            continue
            
        print(f"[{i+1}/{len(binaries)}] {binary_name[:40]:40s} ", end='', flush=True)
        
        success, num_funcs = run_ghidra_extraction(binary_path)
        
        if success:
            results['success'] += 1
            results['total_functions'] += num_funcs
            print(f"✓ ({num_funcs} funcs)")
        else:
            results['failed'] += 1
            results['failed_binaries'].append(binary_name)
            print(f"✗ FAILED")
            
    # Summary
    elapsed = time.time() - start_time
    print("\n" + "=" * 80)
    print("EXTRACTION COMPLETE")
    print(f"Total binaries: {len(binaries)}")
    print(f"Success: {results['success']}")
    print(f"Failed: {results['failed']}")
    print(f"Total functions: {results['total_functions']}")
    print(f"Time: {elapsed/60:.1f} min")
    
    if results['failed_binaries']:
        print("\nFailed binaries:")
        for b in results['failed_binaries'][:10]:
            print(f"  - {b}")

if __name__ == "__main__":
    main()
