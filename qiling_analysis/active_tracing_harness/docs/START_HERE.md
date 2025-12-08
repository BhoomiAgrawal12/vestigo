# 🎯 Active Tracing Harness - Quick Start

> **A production-ready solution for tracing firmware binaries without network connectivity**

## What Is This?

You have a firmware binary that talks over a proprietary protocol. You want to analyze it, but:
- ❌ No server exists to communicate with
- ❌ The binary hangs at `recv()` waiting for data
- ❌ tcpdump is useless (no traffic!)
- ❌ You need execution traces for ML/LSTM analysis

**This harness solves all of that.**

## 30-Second Start

```bash
# 1. Install
pip install angr qiling capstone

# 2. Run
python3 harness.py your_firmware.bin

# 3. Analyze
jq '.phase' trace.jsonl | sort | uniq -c
```

**Output:**
- `golden_input.bin` - Valid input that makes the binary work
- `trace.jsonl` - Full instruction trace with phase tags
- `harness.log` - Detailed execution log

## How It Works

```
┌─────────────┐
│ Your Binary │  Hangs at recv() - no data!
└──────┬──────┘
       │
       ├──▶ ENGINE A (angr): Symbolically finds valid input
       │                      └─▶ golden_input.bin
       │
       └──▶ ENGINE B (Qiling): Injects input, traces execution
                                └─▶ trace.jsonl (for ML)
```

## Real-World Example

```bash
# IoT door lock firmware
python3 harness.py smart_lock.bin --arch arm --verbose

# Results:
# - Found magic header: 0xDEADBEEF
# - Extracted crypto keys
# - Traced 12,345 instructions
# - 3 phases: init → handshake → processing
```

## Key Features

✅ **No Network Required** - Runs completely offline  
✅ **Auto Input Generation** - Symbolic execution finds valid data  
✅ **Full Traces** - Every instruction, with registers  
✅ **Phase Tagging** - Know which code is init vs. handshake  
✅ **Multi-Arch** - ARM, MIPS, x86, x64  
✅ **ML-Ready** - JSONL output for LSTM models  
✅ **Robust** - Handles crashes, timeouts, failures gracefully  

## Files

| File | Purpose |
|------|---------|
| `harness.py` | Main harness (800+ lines, production-ready) |
| `quick_trace.py` | Lightweight tracer (no angr, faster) |
| `demo_harness.py` | Automated demo with test binary |
| `test_firmware.c` | Example firmware to test with |
| `HARNESS_README.md` | Full documentation (usage, examples, troubleshooting) |
| `HARNESS_IMPLEMENTATION.md` | Technical deep-dive |
| `HARNESS_ARCHITECTURE.txt` | Visual diagrams and architecture |
| `harness_cheatsheet.sh` | Quick reference commands |
| `setup_harness.sh` | Automated installation |

## Installation

```bash
# Full install
bash setup_harness.sh

# Manual
pip install -r requirements_harness.txt
git clone https://github.com/qilingframework/rootfs.git /tmp/qiling_rootfs
```

## Usage Examples

### Basic (Auto-detect)
```bash
python3 harness.py firmware.elf
```

### Advanced (Guide Solver)
```bash
python3 harness.py firmware.bin \
    --arch arm \
    --recv-address 0x8048abc \
    --avoid 0x8048100 \
    --angr-timeout 600 \
    --output my_trace.jsonl
```

### Quick (Skip Solver)
```bash
python3 quick_trace.py firmware.bin \
    --input-hex "deadbeef01020304"
```

### Batch Processing
```bash
for fw in samples/*.bin; do
    python3 harness.py "$fw" --output "traces/$(basename $fw).jsonl"
done
```

## Analyzing Output

```bash
# Phase breakdown
jq '.phase' trace.jsonl | sort | uniq -c

# Extract handshake only
jq 'select(.phase == "handshake")' trace.jsonl > handshake.jsonl

# Top instructions
jq -r '.mnemonic' trace.jsonl | sort | uniq -c | sort -rn | head -10

# Find crypto
jq 'select(.mnemonic | test("xor|aes|mul"))' trace.jsonl
```

## Demo

```bash
# Compile test firmware and run full demo
python3 demo_harness.py

# Expected output:
# ✓ Compiles test_firmware
# ✓ Creates golden input (0xDEADBEEF + valid data)
# ✓ Runs harness
# ✓ Traces ~5,000 instructions
# ✓ Shows phase transitions
# ✓ Generates statistics
```

## Documentation

- **Quick Start**: This file (START_HERE.md)
- **Full Documentation**: `HARNESS_README.md` (installation, usage, examples, troubleshooting)
- **Technical Details**: `HARNESS_IMPLEMENTATION.md` (architecture, algorithms, limitations)
- **Visual Reference**: `HARNESS_ARCHITECTURE.txt` (diagrams, data flow)
- **Cheat Sheet**: `harness_cheatsheet.sh` (common commands)

## Architecture Support

| Architecture | angr | Qiling | Status |
|--------------|------|--------|--------|
| x86_64 | ✅ | ✅ | Fully tested |
| x86 | ✅ | ✅ | Fully tested |
| ARM | ✅ | ✅ | Fully tested |
| ARM64 | ✅ | ✅ | Fully tested |
| MIPS | ✅ | ✅ | Fully tested |
| AVR | ⚠️ | ❌ | Partial |

## Use Cases

🔒 **IoT Security Research** - Analyze smart device protocols  
🦠 **Malware Analysis** - Understand botnet C2 protocols  
🔐 **Hardware Security** - Audit bootloader authentication  
🤖 **ML Training** - Generate labeled instruction traces  
🔍 **Protocol Reverse Engineering** - Extract protocol specs  

## Limitations

- **Speed**: Symbolic execution is slow (5-30 minutes typical)
- **Memory**: Large binaries may exhaust RAM
- **Multi-recv**: Only handles first recv intelligently
- **AVR**: Limited support (angr experimental)

See `HARNESS_IMPLEMENTATION.md` for workarounds and future plans.

## Troubleshooting

**Problem**: "angr not available"  
**Solution**: `pip install angr` (may take time to compile)

**Problem**: "recv address not found"  
**Solution**: Use IDA/Ghidra to find it, then `--recv-address 0xADDRESS`

**Problem**: "Qiling rootfs not found"  
**Solution**: `git clone https://github.com/qilingframework/rootfs.git /tmp/qiling_rootfs`

**Problem**: Execution hangs  
**Solution**: Use `--qiling-timeout 300` to increase timeout

See `HARNESS_README.md` § Troubleshooting for more.

## Development

Built by a Senior Security Researcher for real-world firmware analysis.

**Tools Used:**
- angr (symbolic execution)
- Qiling (dynamic instrumentation)
- Capstone (disassembly)
- Unicorn (CPU emulation)

**Testing:**
- Included test firmware (`test_firmware.c`)
- Automated demo (`demo_harness.py`)
- Multiple architectures validated

## Citation

If you use this in research:

```bibtex
@software{active_tracing_harness,
  title={Active Tracing Harness for Firmware Analysis},
  author={Security Research Team},
  year={2025},
  url={https://github.com/kamini08/vestigo-data}
}
```

## License

MIT License - Free for research and commercial use.

## Support

- 📖 Full docs: `HARNESS_README.md`
- 🔧 Technical: `HARNESS_IMPLEMENTATION.md`
- 💬 Issues: GitHub Issues
- 📧 Email: security-research@example.com

## Quick Reference Card

```
┌─────────────────────────────────────────────────────────────┐
│ COMMON COMMANDS                                             │
├─────────────────────────────────────────────────────────────┤
│ Run harness:           python3 harness.py firmware.bin      │
│ Quick trace:           python3 quick_trace.py firmware.bin  │
│ Demo:                  python3 demo_harness.py              │
│ View trace:            jq '.' trace.jsonl | less            │
│ Phase stats:           jq -r '.phase' trace.jsonl | uniq -c │
│ Help:                  python3 harness.py --help            │
│ Cheat sheet:           source harness_cheatsheet.sh         │
└─────────────────────────────────────────────────────────────┘
```

---

**Ready to start?** Run `python3 demo_harness.py` to see it in action! 🚀
