# Active Tracing Harness for Firmware Analysis

A comprehensive dual-engine system for generating execution traces of firmware binaries, specifically designed to capture cryptographic operations (handshake and key exchange phases) for machine learning training data.

## 🎯 Purpose

This harness combines **symbolic execution** (angr) and **dynamic binary instrumentation** (Qiling) to:
- Automatically discover valid inputs for firmware binaries
- Generate instruction-level execution traces in JSONL format
- Detect and tag cryptographic operations (handshake, key exchange)
- Provide ML-ready datasets for LSTM model training

## 📁 Project Structure

```
active_tracing_harness/
├── harness.py                    # Main dual-engine orchestrator
├── quick_trace.py                # Lightweight tracer (no symbolic execution)
├── analyze_trace.py              # Crypto pattern detection (Engine C)
├── trace_crypto_binary.py        # Specialized crypto binary tracer
│
├── docs/                         # Comprehensive documentation
│   ├── START_HERE.md             # Quick start guide (read this first!)
│   ├── HARNESS_README.md         # Complete user manual
│   ├── HARNESS_IMPLEMENTATION.md # Technical deep-dive
│   ├── HARNESS_ARCHITECTURE.txt  # Visual architecture diagrams
│   ├── HARNESS_COMPLETE.md       # Overview and navigation
│   └── DELIVERY_SUMMARY.md       # Executive summary
│
├── tests/                        # Testing infrastructure
│   ├── demo_harness.py           # Automated demo system
│   ├── complete_test.py          # End-to-end test suite
│   ├── test_firmware.c           # Test binary source code
│   ├── simple_test               # Compiled test binary
│   └── golden_input.bin          # Test input data
│
├── tools/                        # Setup and utility scripts
│   ├── setup_harness.sh          # Automated installation
│   ├── harness_cheatsheet.sh     # Quick reference commands
│   └── requirements_harness.txt  # Python dependencies
│
├── output/                       # Generated outputs
│   ├── traces/                   # JSONL trace files
│   └── inputs/                   # Generated input buffers
│
└── examples/                     # Example usage scripts
```

## 🚀 Quick Start

### 1. Installation
```bash
cd tools/
./setup_harness.sh
```

### 2. Basic Usage
```bash
# Full dual-engine mode (symbolic + dynamic)
python3 harness.py /path/to/firmware_binary --verbose

# Quick trace mode (pre-existing input)
python3 quick_trace.py /path/to/binary --input-file input.bin

# Analyze crypto patterns in traces
python3 analyze_trace.py output/traces/trace.jsonl
```

### 3. Run Demo
```bash
cd tests/
python3 demo_harness.py
```

## 📚 Documentation Guide

**Start Here:**
1. `docs/START_HERE.md` - Quick start guide for new users
2. `docs/HARNESS_README.md` - Complete usage manual with examples
3. `docs/HARNESS_ARCHITECTURE.txt` - System architecture and data flow

**Deep Dives:**
- `docs/HARNESS_IMPLEMENTATION.md` - Technical implementation details
- `docs/HARNESS_COMPLETE.md` - Project overview and file navigation
- `docs/DELIVERY_SUMMARY.md` - Executive summary of capabilities

## 🔧 Core Components

### Engine A: Symbolic Solver (angr)
- Automatic input generation through constraint solving
- Identifies `recv()` syscalls and generates valid buffers
- Explores execution paths to find interesting inputs

### Engine B: Dynamic Tracer (Qiling)
- Instruction-level execution tracing
- Full CPU emulation with syscall hooking
- Captures register states, memory access, and control flow

### Engine C: Crypto Analyzer
- Sliding window pattern detection
- Identifies cryptographic operations through heuristics:
  - High bitwise mixing density
  - Arithmetic operation patterns
  - Data entropy analysis
- Phase tagging: init → handshake → key_exchange → processing

## 📊 Output Format

Traces are generated in **JSONL** (JSON Lines) format for ML pipeline compatibility:

```json
{
  "address": "0x401234",
  "instruction": "xor eax, eax",
  "registers": {"rax": "0x0", "rbx": "0x7fff1234"},
  "phase": "handshake",
  "metadata": {"function": "crypto_init", "loop_depth": 2}
}
```

## 🎓 Example Workflows

### Trace a Crypto Binary
```bash
# With automatic input generation
python3 harness.py crypto_binary \
    --max-instructions 100000 \
    --qiling-timeout 120 \
    --verbose

# Analyze the generated trace
python3 analyze_trace.py output/traces/crypto_binary_trace.jsonl
```

### Quick Iteration with Known Input
```bash
# Fast tracing without symbolic execution
python3 quick_trace.py firmware.bin \
    --input-file golden_input.bin \
    --max-instructions 50000
```

### Run Full Test Suite
```bash
cd tests/
python3 complete_test.py
```

## 🛠️ Dependencies

- **Python 3.12+**
- **angr 9.2.186** - Symbolic execution engine
- **Qiling 1.4.8** - Dynamic instrumentation framework
- **Capstone 4.0.2** - Disassembly library
- **Unicorn** - CPU emulation backend
- **Z3 Solver 4.13.0** - Constraint solving

All dependencies managed via virtual environment in `../qiling_env/`

## 📈 Key Features

✅ **Dual-Engine Architecture** - Combines symbolic and dynamic analysis strengths  
✅ **Automatic Input Generation** - No manual reverse engineering needed  
✅ **Crypto Pattern Detection** - ML-powered heuristic analysis  
✅ **Phase Tagging** - Labels execution phases (init, handshake, key exchange)  
✅ **ML-Ready Output** - JSONL format for direct model training ingestion  
✅ **Graceful Error Handling** - Partial traces on timeout/failure  
✅ **Extensive Logging** - Debug-level visibility into execution  

## 🔍 Troubleshooting

**Issue: Timeout on large binaries**
```bash
# Increase timeout and instruction limit
python3 harness.py binary --qiling-timeout 300 --max-instructions 200000
```

**Issue: No crypto patterns detected**
```bash
# Verify trace contains crypto operations
python3 analyze_trace.py trace.jsonl --verbose
# Check if binary actually performs crypto
objdump -d binary | grep -i "xor\|rol\|ror"
```

**Issue: Rootfs path errors**
```bash
# Specify explicit rootfs path
python3 harness.py binary --rootfs /path/to/qiling/rootfs/x8664_linux
```

## 📝 Usage Tips

1. **Start with the demo**: `cd tests/ && python3 demo_harness.py`
2. **Read START_HERE.md**: Essential setup and concepts
3. **Use verbose mode**: `--verbose` flag for debugging
4. **Check tool cheatsheet**: `tools/harness_cheatsheet.sh` for quick commands
5. **Analyze incrementally**: Start with short traces, increase limits gradually

## 🤝 Integration

This harness integrates with the broader **vestigo-data** pipeline:
- Outputs compatible with ML training scripts in `ml/`
- Traces can be labeled with `ghidra_scripts/` analysis
- Results feed into GNN models in `gnn_output/`

## 📞 Support

For questions or issues:
1. Check `docs/HARNESS_README.md` for detailed usage
2. Review `docs/HARNESS_IMPLEMENTATION.md` for technical details
3. Run demo: `python3 tests/demo_harness.py` to verify setup

## 🎯 Next Steps

1. **Run the demo**: Validate your installation
2. **Trace a real binary**: Test on firmware from `../firmware_samples/`
3. **Analyze traces**: Use `analyze_trace.py` to detect crypto patterns
4. **Feed to ML**: Pass JSONL traces to LSTM training pipeline

---

**Version**: 1.0  
**Last Updated**: 2025  
**License**: Internal Research Project
