#!/usr/bin/env python3
"""
Demo script to test the Active Tracing Harness with a simple test binary.

This script:
1. Compiles a test firmware binary
2. Runs the harness on it
3. Analyzes the output
4. Generates a report

Usage:
    python3 demo_harness.py
"""

import os
import sys
import json
import subprocess
from pathlib import Path
from collections import Counter

def print_banner(text):
    """Print a nice banner"""
    print("\n" + "=" * 80)
    print(f"  {text}")
    print("=" * 80 + "\n")

def run_command(cmd, description):
    """Run a shell command and handle errors"""
    print(f"[→] {description}")
    print(f"    Command: {cmd}")
    
    result = subprocess.run(
        cmd,
        shell=True,
        capture_output=True,
        text=True
    )
    
    if result.returncode == 0:
        print(f"[✓] Success")
        if result.stdout:
            print(f"    Output: {result.stdout.strip()[:200]}")
    else:
        print(f"[✗] Failed (exit code: {result.returncode})")
        if result.stderr:
            print(f"    Error: {result.stderr.strip()[:500]}")
        return False
    
    return True

def compile_test_binary():
    """Compile the test firmware"""
    print_banner("STEP 1: Compile Test Binary")
    
    if not os.path.exists('test_firmware.c'):
        print("[✗] test_firmware.c not found!")
        return None
    
    # Try to compile
    binary_name = "test_firmware"
    
    # First, try with -no-pie for easier analysis
    if run_command(
        f"gcc test_firmware.c -o {binary_name} -static -no-pie -O0 -g",
        "Compiling test firmware (static, no-pie, debug symbols)"
    ):
        pass
    elif run_command(
        f"gcc test_firmware.c -o {binary_name} -O0 -g",
        "Compiling test firmware (fallback: dynamic)"
    ):
        pass
    else:
        print("[✗] Compilation failed!")
        return None
    
    # Verify binary
    if os.path.exists(binary_name):
        # Get file info
        result = subprocess.run(
            f"file {binary_name}",
            shell=True,
            capture_output=True,
            text=True
        )
        print(f"\n[i] Binary info: {result.stdout.strip()}")
        return binary_name
    
    return None

def create_golden_input():
    """Create a valid golden input manually for demo purposes"""
    print_banner("STEP 2: Create Golden Input (Manual)")
    
    # Create a valid input that matches test_firmware.c expectations:
    # - 4 bytes: magic header (0xDEADBEEF)
    # - 1 byte: version (1)
    # - 32 bytes: key material
    # - Rest: padding
    
    golden_input = bytearray()
    
    # Magic header (little-endian on x86)
    golden_input.extend(b'\xEF\xBE\xAD\xDE')
    
    # Version
    golden_input.append(1)
    
    # Key material (32 bytes)
    golden_input.extend(b'0123456789ABCDEF' * 2)
    
    # Padding
    golden_input.extend(b'\x00' * (256 - len(golden_input)))
    
    # Save to file
    with open('golden_input.bin', 'wb') as f:
        f.write(golden_input)
    
    print(f"[✓] Created golden_input.bin ({len(golden_input)} bytes)")
    print(f"    Magic: 0xDEADBEEF")
    print(f"    Version: 1")
    print(f"    Key material: 32 bytes")
    
    return True

def run_harness(binary_name):
    """Run the active tracing harness"""
    print_banner("STEP 3: Run Active Tracing Harness")
    
    cmd = (
        f"python3 harness.py {binary_name} "
        f"--skip-solver "
        f"--golden-input golden_input.bin "
        f"--output demo_trace.jsonl "
        f"--max-instructions 50000 "
        f"--qiling-timeout 30 "
        f"--log-level INFO "
        f"--verbose"
    )
    
    print(f"[→] Running harness...")
    print(f"    {cmd}\n")
    
    # Run with real-time output
    result = subprocess.run(
        cmd,
        shell=True,
        text=True
    )
    
    if result.returncode == 0:
        print(f"\n[✓] Harness completed successfully")
        return True
    else:
        print(f"\n[✗] Harness failed (exit code: {result.returncode})")
        return False

def analyze_trace():
    """Analyze the generated trace"""
    print_banner("STEP 4: Analyze Execution Trace")
    
    trace_file = "demo_trace.jsonl"
    
    if not os.path.exists(trace_file):
        print(f"[✗] Trace file not found: {trace_file}")
        return False
    
    # Load trace
    traces = []
    with open(trace_file, 'r') as f:
        for line in f:
            try:
                traces.append(json.loads(line))
            except:
                pass
    
    print(f"[✓] Loaded {len(traces)} trace events")
    
    # Analyze phases
    phase_counts = Counter(t['phase'] for t in traces)
    
    print("\n📊 Trace Statistics:")
    print("-" * 60)
    print(f"Total instructions: {len(traces)}")
    print(f"\nPhase breakdown:")
    for phase, count in phase_counts.most_common():
        percentage = (count / len(traces)) * 100
        print(f"  {phase:15s}: {count:6d} instructions ({percentage:5.2f}%)")
    
    # Analyze mnemonics
    mnemonic_counts = Counter(t['mnemonic'] for t in traces)
    
    print(f"\nTop 10 instructions:")
    for mnemonic, count in mnemonic_counts.most_common(10):
        print(f"  {mnemonic:10s}: {count:6d}")
    
    # Find interesting events
    print("\n🔍 Interesting Events:")
    print("-" * 60)
    
    # Find phase transitions
    last_phase = None
    transitions = []
    for i, trace in enumerate(traces):
        if trace['phase'] != last_phase:
            transitions.append((i, last_phase, trace['phase']))
            last_phase = trace['phase']
    
    print(f"Phase transitions:")
    for idx, from_phase, to_phase in transitions:
        from_str = from_phase or "START"
        print(f"  Instruction {idx:6d}: {from_str:12s} → {to_phase}")
    
    # Find syscalls/calls
    calls = [t for t in traces if t['mnemonic'] in ['call', 'bl', 'jal', 'syscall']]
    print(f"\nFunction calls found: {len(calls)}")
    if len(calls) > 0:
        print(f"  First call at: {calls[0]['address']}")
        print(f"  Last call at:  {calls[-1]['address']}")
    
    # Sample handshake instructions
    handshake_traces = [t for t in traces if t['phase'] == 'handshake']
    if handshake_traces:
        print(f"\n📝 Sample Handshake Instructions (first 5):")
        for trace in handshake_traces[:5]:
            print(f"  {trace['address']:12s} {trace['mnemonic']:8s} {trace['operands']}")
    
    print("\n" + "=" * 60)
    
    return True

def generate_report():
    """Generate final report"""
    print_banner("STEP 5: Generate Report")
    
    files_to_check = [
        ('golden_input.bin', 'Golden input data'),
        ('demo_trace.jsonl', 'Execution trace'),
        ('harness.log', 'Detailed log file'),
    ]
    
    print("📁 Generated Files:")
    print("-" * 60)
    
    for filename, description in files_to_check:
        if os.path.exists(filename):
            size = os.path.getsize(filename)
            size_str = f"{size:,} bytes"
            if size > 1024:
                size_str = f"{size/1024:.1f} KB"
            if size > 1024*1024:
                size_str = f"{size/(1024*1024):.1f} MB"
            
            print(f"✓ {filename:25s} - {description:30s} ({size_str})")
        else:
            print(f"✗ {filename:25s} - {description:30s} (NOT FOUND)")
    
    print("\n" + "=" * 60)
    print("Demo complete! 🎉")
    print("\nNext steps:")
    print("  1. Examine demo_trace.jsonl for instruction traces")
    print("  2. Review harness.log for execution details")
    print("  3. Try modifying golden_input.bin to see different execution paths")
    print("  4. Use jq to filter trace: jq '.phase' demo_trace.jsonl | sort | uniq -c")
    print("=" * 60 + "\n")

def main():
    print_banner("Active Tracing Harness - Demo")
    print("This demo will:")
    print("  1. Compile a test firmware binary")
    print("  2. Create a valid golden input")
    print("  3. Run the harness to trace execution")
    print("  4. Analyze the results")
    print("\nNote: This demo skips Engine A (angr) for speed and uses")
    print("      a pre-crafted golden input. Full harness demo requires")
    print("      angr to be installed.")
    
    input("\nPress Enter to continue...")
    
    # Step 1: Compile
    binary = compile_test_binary()
    if not binary:
        print("\n[✗] Demo failed: Could not compile test binary")
        return 1
    
    # Step 2: Create golden input
    if not create_golden_input():
        print("\n[✗] Demo failed: Could not create golden input")
        return 1
    
    # Step 3: Run harness
    if not run_harness(binary):
        print("\n[✗] Demo failed: Harness execution failed")
        print("\n[i] This may be due to missing dependencies (Qiling)")
        print("[i] Check harness.log for details")
        return 1
    
    # Step 4: Analyze
    if not analyze_trace():
        print("\n[✗] Demo failed: Could not analyze trace")
        return 1
    
    # Step 5: Report
    generate_report()
    
    return 0

if __name__ == '__main__':
    sys.exit(main())
