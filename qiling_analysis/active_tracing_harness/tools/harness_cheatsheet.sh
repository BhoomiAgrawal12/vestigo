#!/bin/bash
# Active Tracing Harness - Quick Reference Cheat Sheet
# Save this file and run: source harness_cheatsheet.sh

# ============================================================================
# INSTALLATION
# ============================================================================

alias harness-install='pip install angr qiling capstone unicorn && \
                       git clone https://github.com/qilingframework/rootfs.git /tmp/qiling_rootfs'

# ============================================================================
# BASIC USAGE
# ============================================================================

# Auto-detect everything (simplest)
alias harness-auto='python3 harness.py'

# With architecture specified
alias harness-arm='python3 harness.py --arch arm'
alias harness-mips='python3 harness.py --arch mips'
alias harness-x86='python3 harness.py --arch x86_64'

# ============================================================================
# QUICK TRACE (no symbolic execution)
# ============================================================================

# Using hex input
alias qtrace-hex='python3 quick_trace.py --input-hex'

# Using binary file
alias qtrace-file='python3 quick_trace.py --input'

# Using ASCII string
alias qtrace-string='python3 quick_trace.py --input-string'

# ============================================================================
# ANALYSIS HELPERS
# ============================================================================

# Count instructions by phase
alias trace-phases='jq -r ".phase" trace.jsonl | sort | uniq -c'

# Extract only handshake phase
alias trace-handshake='jq "select(.phase == \"handshake\")" trace.jsonl'

# Get top 10 instructions
alias trace-top10='jq -r ".mnemonic" trace.jsonl | sort | uniq -c | sort -rn | head -10'

# Show first N instructions
alias trace-head='jq -s ".[0:100]" trace.jsonl'

# Count total instructions
alias trace-count='wc -l trace.jsonl'

# View golden input as hex
alias golden-hex='xxd golden_input.bin | head -20'

# ============================================================================
# COMMON WORKFLOWS
# ============================================================================

# Workflow 1: Unknown firmware
harness-unknown() {
    echo "Running harness on unknown firmware..."
    python3 harness.py "$1" --arch auto --verbose --output "trace_$1.jsonl"
}

# Workflow 2: Known recv address
harness-known-recv() {
    local binary="$1"
    local recv_addr="$2"
    python3 harness.py "$binary" --recv-address "$recv_addr" --verbose
}

# Workflow 3: Quick test with custom input
harness-quick-test() {
    local binary="$1"
    local hex_input="$2"
    python3 quick_trace.py "$binary" --input-hex "$hex_input" -o quick_test.jsonl
    jq -r '.phase' quick_test.jsonl | sort | uniq -c
}

# Workflow 4: Batch process multiple binaries
harness-batch() {
    local dir="$1"
    mkdir -p traces
    for bin in "$dir"/*.bin "$dir"/*.elf; do
        [ -f "$bin" ] || continue
        echo "Processing: $bin"
        python3 harness.py "$bin" --output "traces/$(basename $bin).jsonl" 2>&1 | tee "traces/$(basename $bin).log"
    done
}

# ============================================================================
# DEBUGGING
# ============================================================================

# Run with full debug output
alias harness-debug='python3 harness.py --log-level DEBUG --verbose'

# Check if recv was found
harness-check-recv() {
    python3 -c "
import angr
p = angr.Project('$1', auto_load_libs=False)
try:
    sym = p.loader.find_symbol('recv')
    print(f'recv found at: {hex(sym.rebased_addr)}')
except:
    print('recv not found in symbols')
"
}

# View last 100 trace events
alias trace-tail='tail -100 trace.jsonl | jq .'

# Check harness log for errors
alias harness-errors='grep -i "error\|fail\|warning" harness.log'

# ============================================================================
# ANALYSIS SCRIPTS
# ============================================================================

# Generate phase transition report
trace-transitions() {
    python3 << 'EOF'
import json
import sys

last_phase = None
transitions = []

with open('trace.jsonl', 'r') as f:
    for i, line in enumerate(f):
        try:
            trace = json.loads(line)
            if trace['phase'] != last_phase:
                transitions.append((i, last_phase, trace['phase']))
                last_phase = trace['phase']
        except:
            pass

print("Phase Transitions:")
print("-" * 60)
for idx, from_p, to_p in transitions:
    from_str = from_p or "START"
    print(f"  Instruction {idx:6d}: {from_str:12s} → {to_p}")
EOF
}

# Extract crypto-related instructions
trace-crypto() {
    jq 'select(.mnemonic | test("xor|aes|mul|sha|rol|ror"))' trace.jsonl
}

# Find function calls
trace-calls() {
    jq 'select(.mnemonic | test("call|bl|jal|jalr"))' trace.jsonl | \
    jq -r '"\(.address) \(.mnemonic) \(.operands)"'
}

# Generate execution statistics
trace-stats() {
    python3 << 'EOF'
import json
from collections import Counter

traces = []
with open('trace.jsonl', 'r') as f:
    for line in f:
        try:
            traces.append(json.loads(line))
        except:
            pass

print(f"Total Instructions: {len(traces)}")
print(f"\nPhase Breakdown:")
phase_counts = Counter(t['phase'] for t in traces)
for phase, count in phase_counts.most_common():
    pct = (count/len(traces))*100
    print(f"  {phase:15s}: {count:6d} ({pct:5.2f}%)")

print(f"\nTop 15 Instructions:")
insn_counts = Counter(t['mnemonic'] for t in traces)
for insn, count in insn_counts.most_common(15):
    print(f"  {insn:10s}: {count:6d}")

if traces:
    print(f"\nExecution Timeline:")
    print(f"  Start:    {traces[0]['address']}")
    print(f"  End:      {traces[-1]['address']}")
    print(f"  Duration: {traces[-1]['timestamp']:.3f}s")
EOF
}

# ============================================================================
# EXAMPLES
# ============================================================================

# Example 1: Analyze unknown IoT firmware
example-iot() {
    echo "Example: IoT Firmware Analysis"
    echo "python3 harness.py iot_device.bin --arch arm --verbose"
}

# Example 2: Router firmware with known recv
example-router() {
    echo "Example: Router Firmware"
    echo "python3 harness.py router_fw.bin --arch mips --recv-address 0x80484000"
}

# Example 3: Quick trace with custom input
example-quick() {
    echo "Example: Quick Trace"
    echo "python3 quick_trace.py firmware.bin --input-hex 'deadbeef01020304'"
}

# ============================================================================
# HELP
# ============================================================================

harness-help() {
    cat << 'EOF'
╔════════════════════════════════════════════════════════════════════╗
║         Active Tracing Harness - Quick Reference                   ║
╚════════════════════════════════════════════════════════════════════╝

INSTALLATION:
  harness-install              Install dependencies

BASIC USAGE:
  python3 harness.py <binary>                    Auto-detect everything
  python3 harness.py <binary> --arch arm         Specify architecture
  python3 harness.py <binary> --recv-address 0x  Known recv address

QUICK TRACE (no angr):
  python3 quick_trace.py <binary> --input-hex "deadbeef..."
  python3 quick_trace.py <binary> --input data.bin

ANALYSIS:
  trace-phases                 Count instructions by phase
  trace-handshake              Extract handshake phase only
  trace-top10                  Top 10 most common instructions
  trace-transitions            Show phase transitions
  trace-stats                  Full statistics report

WORKFLOWS:
  harness-unknown <binary>                  Full auto analysis
  harness-known-recv <binary> <addr>        With known recv
  harness-quick-test <binary> <hex>         Quick test with input
  harness-batch <directory>                 Process multiple files

DEBUGGING:
  harness-debug <binary>       Full debug output
  harness-errors               Show errors from log
  trace-tail                   Last 100 trace events

FILES:
  golden_input.bin             Solved input data
  trace.jsonl                  Execution trace
  harness.log                  Detailed log

DOCUMENTATION:
  less HARNESS_README.md              Full documentation
  less HARNESS_IMPLEMENTATION.md      Technical details

DEMO:
  python3 demo_harness.py      Run complete demo

MORE:
  python3 harness.py --help    Full CLI options
  python3 quick_trace.py --help

EOF
}

# Show help on load
echo "Active Tracing Harness - Quick Reference loaded!"
echo "Type 'harness-help' for commands"
