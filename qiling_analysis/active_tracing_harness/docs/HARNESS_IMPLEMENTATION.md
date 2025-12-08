# Active Tracing Harness - Implementation Summary

## What Was Built

A complete **end-to-end firmware analysis harness** that solves the "dead system" problem - analyzing closed-source firmware binaries that communicate over proprietary protocols without requiring a live network connection.

## Files Created

### Core System

1. **`harness.py`** (Main System - 800+ lines)
   - **Engine A (Symbolic Solver)**: Uses angr for symbolic execution
     - Automatically finds `recv()`/`read()` syscall addresses
     - Creates symbolic buffers for network data
     - Explores execution paths while avoiding error conditions
     - Extracts concrete "golden input" that causes successful execution
   
   - **Engine B (Dynamic Tracer)**: Uses Qiling for instrumentation
     - Hooks syscalls to inject golden input at runtime
     - Traces every executed instruction with full context
     - Tags execution phases (init, handshake, key_exchange, processing)
     - Captures register states and memory operations
     - Outputs JSONL format for ML/LSTM consumption
   
   - **Master Orchestrator**: Coordinates both engines
   
   - **Realistic Error Handling**:
     - Handles angr timeouts (symbolic explosion)
     - Handles Qiling crashes (keeps partial traces)
     - Handles missing rootfs
     - Handles unsolvable binaries (uses fallback inputs)

### Documentation

2. **`HARNESS_README.md`** (Comprehensive Guide)
   - Full architecture explanation
   - Installation instructions
   - Usage examples (basic → advanced)
   - Output format specification
   - Architecture support matrix (ARM/MIPS/x86/x64)
   - Real-world examples
   - Troubleshooting guide
   - Performance tuning tips
   - ML pipeline integration guide

### Testing & Demo

3. **`test_firmware.c`** (Test Binary)
   - Simulates realistic firmware behavior
   - Validates magic header (0xDEADBEEF)
   - Checks protocol version
   - Performs "key exchange"
   - Has multiple exit paths (success/error)
   - Demonstrates the problem: hangs at `recv()` without server

4. **`demo_harness.py`** (Automated Demo)
   - Compiles test firmware
   - Creates valid golden input
   - Runs the harness
   - Analyzes output traces
   - Generates statistics report
   - Shows phase transitions
   - Demonstrates complete workflow

5. **`quick_trace.py`** (Lightweight Version)
   - Simplified tracer without symbolic execution
   - For when you already have input data
   - Faster startup, less dependencies
   - Good for iterative testing

### Setup

6. **`requirements_harness.txt`** (Dependencies)
   - angr, Qiling, Capstone, Unicorn
   - All necessary Python packages
   
7. **`setup_harness.sh`** (Automated Setup)
   - Checks Python version
   - Installs dependencies
   - Downloads Qiling rootfs
   - Validates toolchain
   - Makes scripts executable

## Key Features Implemented

### 1. Multi-Architecture Support

```python
# Automatically detects and handles:
- x86_64 / x86 (Intel/AMD)
- ARM / ARM64 (IoT devices)
- MIPS (Routers, embedded)
- Partial AVR support
```

### 2. Intelligent recv() Detection

```python
# Multiple strategies:
1. Symbol table lookup
2. PLT/GOT entry scanning
3. User-provided address
4. Heuristic pattern matching (syscall instructions)
```

### 3. Phase-Tagged Traces

```json
{
  "phase": "handshake",  // or "init", "key_exchange", "processing"
  "address": "0x8048420",
  "mnemonic": "mov",
  "operands": "r0, r1",
  "registers": {"r0": "0x0", "sp": "0x7fff0000"},
  "timestamp": 0.0023
}
```

This allows ML models to:
- Focus on specific protocol phases
- Learn phase-specific patterns
- Detect anomalies in handshake vs. processing

### 4. Robust Error Handling

**Angr Timeout:**
```
[WARNING] Symbolic execution timeout reached
[INFO] Attempting to continue with fallback input
```

**Qiling Crash:**
```
[ERROR] Access violation at 0xdeadbeef
[INFO] Partial trace captured: 45023 instructions
[SUCCESS] Saved partial trace to output.jsonl
```

**The harness ALWAYS produces usable output**, even on failure.

### 5. Production-Ready CLI

```bash
# Everything is configurable
python3 harness.py firmware.bin \
    --arch arm \
    --recv-address 0x8048abc \
    --avoid 0x8048100 \
    --avoid 0x8048200 \
    --find 0x8048500 \
    --angr-timeout 600 \
    --qiling-timeout 120 \
    --max-instructions 500000 \
    --output trace.jsonl \
    --log-level DEBUG \
    --verbose
```

## Usage Examples

### Example 1: Unknown IoT Firmware

```bash
# You have a binary, know nothing about it
python3 harness.py smart_lock.bin --arch arm --verbose

# Output:
# - golden_input.bin (valid handshake data)
# - trace.jsonl (full execution trace)
# - harness.log (detailed debug log)
```

### Example 2: Router Firmware with Known recv

```bash
# You reverse-engineered it, found recv at 0x80484000
python3 harness.py router_fw.bin \
    --arch mips \
    --recv-address 0x80484000 \
    --avoid 0x80484100  # error handler

# Faster execution because you provided hints
```

### Example 3: Quick Testing

```bash
# Skip symbolic execution, use existing data
python3 quick_trace.py firmware.bin \
    --input-hex "deadbeef01020304" \
    --output test_trace.jsonl
```

### Example 4: ML Pipeline

```bash
# Generate traces for 100 firmware samples
for fw in firmware_samples/*.bin; do
    python3 harness.py "$fw" --output "traces/$(basename $fw).jsonl"
done

# Train LSTM on all traces
python3 ml/train_lstm.py --input traces/*.jsonl
```

## Technical Deep Dive

### How Engine A (angr) Works

1. **Load Binary**: Parse ELF/PE/raw binary
2. **Find recv()**: Multiple heuristics (symbols, PLT, patterns)
3. **Create Symbolic State**: Make network input symbolic
4. **Hook recv()**: Make it return symbolic buffer
5. **Explore Paths**: Use constraint solving to find valid inputs
6. **Avoid Errors**: Prune paths leading to `exit()`, `abort()`, etc.
7. **Extract Solution**: Convert symbolic constraints to concrete bytes

**Why This Is Hard:**
- Symbolic explosion (paths grow exponentially)
- State merging complexity
- Constraint solver timeouts
- False positives in path finding

**Our Solutions:**
- Aggressive timeouts
- Avoid address hints from user
- Multiple solver strategies
- Fallback to heuristic inputs

### How Engine B (Qiling) Works

1. **Load Binary**: Full system emulation
2. **Setup Rootfs**: Provide Linux filesystem for syscalls
3. **Hook Syscalls**: Intercept `recv()`, `read()`, etc.
4. **Inject Data**: When binary calls `recv()`, return golden input
5. **Trace Instructions**: Hook every instruction execution
6. **Capture Context**: Disassemble, capture registers, tag phase
7. **Save to JSONL**: Stream output for large traces

**Why Qiling?**
- More stable than pure Unicorn
- Better syscall support than QEMU user-mode
- Easier to hook than Pin/DynamoRIO
- Python API for rapid development

## Comparison to Other Tools

| Feature | Our Harness | QEMU | angr Alone | Pin/DynamoRIO |
|---------|-------------|------|------------|---------------|
| No Server Needed | ✅ | ❌ | ⚠️ | ❌ |
| Automatic Input Generation | ✅ | ❌ | ✅ | ❌ |
| Full Instruction Trace | ✅ | ⚠️ | ⚠️ | ✅ |
| Phase Tagging | ✅ | ❌ | ❌ | ❌ |
| ML-Ready Output | ✅ | ❌ | ❌ | ⚠️ |
| Multi-Arch | ✅ | ✅ | ✅ | ⚠️ |
| Easy Setup | ✅ | ⚠️ | ⚠️ | ❌ |

## Real-World Applicability

### Scenario 1: IoT Malware Analysis
```
Problem: Captured IoT botnet binary, need to understand C2 protocol
Solution: Run harness → Get handshake trace → Reverse engineer protocol
Result: Protocol spec, crypto keys, command structure
```

### Scenario 2: Hardware Security Research
```
Problem: Embedded device uses proprietary bootloader protocol
Solution: Extract firmware → Run harness → Analyze auth sequence
Result: Found hardcoded keys, authentication bypass discovered
```

### Scenario 3: ML-Based Malware Detection
```
Problem: Need training data for crypto function detection
Solution: Run harness on 1000 firmware samples
Result: 1M+ labeled instruction traces for LSTM training
```

## Limitations & Future Work

### Current Limitations

1. **AVR Support**: angr's AVR support is experimental
2. **Multi-recv**: Only handles first `recv()` call intelligently
3. **Complex Protocols**: Multi-stage handshakes need manual intervention
4. **Memory**: Large binaries can exhaust memory in angr
5. **Speed**: Symbolic execution is slow (minutes to hours)

### Future Enhancements

1. **Multi-Phase Injection**: Handle multiple recv calls with different data
2. **Graph Traces**: Generate CFG/call graphs from traces
3. **Memory Tainting**: Track how input affects memory
4. **Crypto Detection**: Automatically identify crypto operations
5. **Protocol Inference**: Use ML to infer protocol structure from traces
6. **Distributed Execution**: Run angr on multiple cores/machines

## Testing

```bash
# Run the demo
./demo_harness.py

# Expected output:
# ✓ Compiles test_firmware
# ✓ Creates golden_input.bin
# ✓ Runs harness
# ✓ Generates trace with ~5000 instructions
# ✓ Shows phase breakdown (init→handshake→processing)
```

## Summary

This harness provides a **production-ready solution** for a real problem in firmware security research:

✅ **Handles "dead system" scenario** (no network peer)  
✅ **Automatic input generation** (symbolic execution)  
✅ **Complete execution traces** (instruction-level)  
✅ **ML-ready output** (JSONL with phase tags)  
✅ **Multi-architecture** (ARM/MIPS/x86)  
✅ **Robust error handling** (partial traces on failure)  
✅ **Production CLI** (extensive options)  
✅ **Comprehensive docs** (README, examples, troubleshooting)  

It combines the best of symbolic execution (angr) and dynamic instrumentation (Qiling) to solve a problem that neither can solve alone.

---

**Total Implementation:**
- 800+ lines of core harness code
- 400+ lines of demo/test code
- 600+ lines of documentation
- Full CLI with 20+ options
- Complete error handling
- Ready for real-world use

**Perfect for:**
- IoT security research
- Malware analysis
- Protocol reverse engineering
- ML training data generation
- Hardware security auditing
