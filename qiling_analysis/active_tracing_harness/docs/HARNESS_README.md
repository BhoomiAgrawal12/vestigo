# Active Tracing Harness for Firmware Analysis

## Overview

This harness provides an **end-to-end solution** for analyzing closed-source firmware binaries that communicate over proprietary network protocols **without requiring a live server or network connection**.

### The Problem

Traditional firmware analysis fails when:
- The binary expects network data but hangs at `recv()` or `read()`
- No server/peer is available to communicate with
- Traffic capture (tcpdump) is useless because there's no traffic
- You need execution traces for ML/LSTM analysis but can't run the binary

### The Solution

A two-engine approach:

1. **Engine A (Symbolic Solver)** - Uses `angr` to:
   - Symbolically execute the binary
   - Find valid network inputs that make the binary proceed successfully
   - Avoid error paths and infinite loops
   - Save the "golden input" for injection

2. **Engine B (Dynamic Tracer)** - Uses `Qiling` to:
   - Execute the binary with full system emulation
   - Hook network syscalls (`recv`, `read`, etc.)
   - Inject the golden input when the binary requests data
   - Capture complete instruction traces tagged by execution phase
   - Output JSONL traces for ML analysis

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    HARNESS ORCHESTRATOR                      │
└─────────────────────────────────────────────────────────────┘
                              │
                              ├───────────────────────┐
                              │                       │
                              ▼                       ▼
                    ┌──────────────────┐   ┌──────────────────┐
                    │   ENGINE A       │   │   ENGINE B       │
                    │   Symbolic       │   │   Dynamic        │
                    │   Solver (angr)  │   │   Tracer (Qiling)│
                    └──────────────────┘   └──────────────────┘
                              │                       │
                              ▼                       ▼
                    ┌──────────────────┐   ┌──────────────────┐
                    │ golden_input.bin │   │  trace.jsonl     │
                    │ (Valid network   │   │  (Instruction    │
                    │  input data)     │   │   traces w/tags) │
                    └──────────────────┘   └──────────────────┘
```

## Installation

### Prerequisites

```bash
# Python 3.8+
python3 --version

# Install core dependencies
pip install angr qiling capstone

# Optional: For ARM/MIPS firmware
pip install unicorn keystone-engine
```

### Qiling Rootfs Setup

Qiling requires architecture-specific root filesystems:

```bash
# Download rootfs packs
git clone https://github.com/qilingframework/rootfs.git /tmp/qiling_rootfs

# Or use the built-in downloader
python3 -c "from qiling import *; Qiling.install_rootfs()"
```

## Usage

### Basic Usage

```bash
# Auto-detect everything
python3 harness.py firmware.elf

# Specify architecture
python3 harness.py firmware.bin --arch arm

# Use custom recv function name
python3 harness.py firmware.bin --recv-func uart_read
```

### Advanced Usage

#### 1. Manual recv Address

If you've reverse-engineered the binary and know the recv address:

```bash
python3 harness.py firmware.bin --recv-address 0x8048abc
```

#### 2. Guide Symbolic Execution

Avoid known error handlers:

```bash
python3 harness.py firmware.bin \
    --avoid 0x8048100 \  # error_handler
    --avoid 0x8048200 \  # exit_on_invalid
    --find 0x8048500     # success_path
```

#### 3. Skip Solver (Use Existing Input)

If you already have valid input data:

```bash
python3 harness.py firmware.bin \
    --skip-solver \
    --golden-input captured_packet.bin
```

#### 4. Extended Tracing

```bash
python3 harness.py firmware.bin \
    --max-instructions 500000 \
    --qiling-timeout 300 \
    --output extended_trace.jsonl
```

#### 5. Debugging Mode

```bash
python3 harness.py firmware.bin \
    --log-level DEBUG \
    --verbose
```

### Full Example Workflow

```bash
# Step 1: Run harness on unknown firmware
python3 harness.py ./samples/iot_device.elf \
    --arch arm \
    --angr-timeout 600 \
    --qiling-timeout 120 \
    --output traces/iot_trace.jsonl \
    --verbose

# Step 2: Check outputs
ls -lh golden_input.bin traces/iot_trace.jsonl

# Step 3: Analyze trace phases
jq -r '.phase' traces/iot_trace.jsonl | sort | uniq -c
#   1234 init
#   5678 handshake
#   3456 processing

# Step 4: Extract handshake instructions
jq 'select(.phase == "handshake")' traces/iot_trace.jsonl > handshake_only.jsonl

# Step 5: Feed to LSTM model
python3 ml/train_lstm.py --input traces/iot_trace.jsonl
```

## Output Format

### Golden Input (`golden_input.bin`)

Raw binary data that causes successful execution:
```
00000000: 1603 0100 0101 0000 0000 0000 0000 0000  ................
00000010: 0000 0000 0000 0000 0000 0000 0000 0000  ................
```

### Execution Trace (`trace.jsonl`)

JSONL (newline-delimited JSON) with instruction-level detail:

```json
{
  "address": "0x8048420",
  "mnemonic": "mov",
  "operands": "r0, r1",
  "phase": "init",
  "timestamp": 0.0023,
  "registers": {
    "r0": "0x0",
    "r1": "0x7fff1234",
    "sp": "0x7fff0000",
    "pc": "0x8048420"
  },
  "memory_access": null
}
```

#### Trace Phases

- `init` - Pre-network-read initialization
- `handshake` - Processing injected golden input
- `key_exchange` - Cryptographic key derivation
- `processing` - Post-handshake logic
- `error` - Error handling paths

### Log File (`harness.log`)

Detailed execution log with timestamps, useful for debugging.

## Architecture Support

| Architecture | Angr Support | Qiling Support | Status |
|--------------|--------------|----------------|--------|
| x86_64       | ✅           | ✅             | Tested |
| x86 (32-bit) | ✅           | ✅             | Tested |
| ARM          | ✅           | ✅             | Tested |
| ARM64        | ✅           | ✅             | Tested |
| MIPS         | ✅           | ✅             | Tested |
| AVR          | ⚠️           | ❌             | Limited |

## Realistic Constraints & Error Handling

### Engine A Failures

**Timeout:**
```
[WARNING] Symbolic execution timeout reached
[INFO] Attempting to continue with Engine B using fallback input
```

**No Solution Found:**
```
[ERROR] No viable states found
[WARNING] Engine A failed to find golden input
```

**Workaround:** Provide `--avoid` addresses to prune search space, or manually create golden input.

### Engine B Failures

**Invalid Binary:**
```
[ERROR] Failed to initialize Qiling: Unknown format
```

**Workaround:** Verify binary format with `file` command, check architecture.

**Rootfs Missing:**
```
[ERROR] Qiling rootfs not found for arm_linux
```

**Workaround:** Download rootfs or specify with `--rootfs`.

**Execution Crashes:**
```
[ERROR] Execution error: Access violation at 0xdeadbeef
[INFO] Partial trace captured: 45023 instructions
```

**Workaround:** Trace is saved even on crash - use partial trace.

## Performance Tuning

### For Large Binaries (>5MB)

```bash
python3 harness.py firmware.bin \
    --angr-timeout 1800 \          # 30 minutes
    --max-instructions 1000000 \   # 1M instructions
    --no-registers                 # Skip register capture (faster)
```

### For Quick Testing

```bash
python3 harness.py firmware.bin \
    --angr-timeout 60 \
    --qiling-timeout 30 \
    --max-instructions 10000
```

## Integration with ML Pipeline

### LSTM Training Data

The trace output is designed for LSTM sequence modeling:

```python
import json

# Load traces
traces = []
with open('trace.jsonl', 'r') as f:
    for line in f:
        traces.append(json.loads(line))

# Convert to feature vectors
# Example: [address, mnemonic_id, phase_id]
X = []
for trace in traces:
    # Your feature extraction
    features = extract_features(trace)
    X.append(features)

# Train LSTM
model.fit(X, y, epochs=50)
```

### Phase Extraction

```bash
# Get only handshake phase
jq 'select(.phase == "handshake")' trace.jsonl > handshake.jsonl

# Get init + handshake
jq 'select(.phase == "init" or .phase == "handshake")' trace.jsonl > early_phase.jsonl
```

## Troubleshooting

### Problem: "angr not available"

```bash
pip install angr
# If fails on ARM Mac:
pip install angr --no-binary :all:
```

### Problem: "recv address not found"

Solution 1: Use Ghidra/IDA to find recv:
```bash
# In Ghidra, search for:
# - "recv" in symbol tree
# - Syscall instructions (ARM: svc 0)
# - Cross-references from network code

python3 harness.py firmware.bin --recv-address 0xADDRESS
```

Solution 2: Trace manually and find:
```bash
strace ./firmware.bin 2>&1 | grep recv
# recvfrom(3, ...
```

### Problem: "Execution hangs in Qiling"

Check timeout:
```bash
python3 harness.py firmware.bin --qiling-timeout 300
```

Check infinite loop:
```bash
tail -100 harness.log | grep "address"
# If same address repeats > 1000 times, it's a loop
```

### Problem: "Trace is too large"

Limit instructions:
```bash
python3 harness.py firmware.bin --max-instructions 50000
```

Or filter post-processing:
```bash
# Take first 10K instructions
head -10000 trace.jsonl > trace_limited.jsonl
```

## Real-World Example: IoT Door Lock

```bash
# Scenario: Smart lock firmware with proprietary protocol
# Goal: Understand unlock handshake

# Step 1: Initial analysis
file smartlock.bin
# smartlock.bin: ELF 32-bit LSB executable, ARM

# Step 2: Run harness
python3 harness.py smartlock.bin \
    --arch arm \
    --recv-func ble_read \
    --angr-timeout 900 \
    --output traces/smartlock.jsonl \
    --verbose

# Step 3: Check results
jq '.phase' traces/smartlock.jsonl | sort | uniq -c
#   3456 init
#  12345 handshake
#   6789 processing

# Step 4: Analyze handshake
jq 'select(.phase == "handshake" and .mnemonic == "bl")' traces/smartlock.jsonl
# Find crypto function calls

# Step 5: Extract golden input
xxd golden_input.bin
# 00000000: 4142 4344 1234 5678 ...
# Reverse engineer protocol from this!
```

## Contributing

Areas for improvement:
- [ ] AVR architecture support
- [ ] Better heuristics for recv detection
- [ ] Memory access tracking (loads/stores)
- [ ] Support for custom syscalls
- [ ] Multi-phase golden input (multiple recv calls)
- [ ] Graph-based trace visualization

## License

MIT License - Free to use for research and commercial purposes.

## Citation

If you use this harness in research, please cite:

```bibtex
@software{active_tracing_harness,
  title={Active Tracing Harness for Firmware Analysis},
  author={Security Research Team},
  year={2025},
  url={https://github.com/kamini08/vestigo-data}
}
```

## Support

For issues, questions, or contributions:
- GitHub Issues: https://github.com/kamini08/vestigo-data/issues
- Email: security-research@example.com

---

**Remember:** This tool performs dynamic code execution. Only analyze binaries you trust or in isolated environments (VMs, containers).
