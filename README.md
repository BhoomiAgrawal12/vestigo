# Permutation Factory

Permutation Factory is a comprehensive pipeline for cross-compiling C source code into multiple architectures, performing headless analysis using Ghidra, and extracting cryptographic features for Machine Learning applications.

## Features

- **Cross-Compilation Matrix**: Automatically builds C code for multiple architectures (x86_64, ARM, MIPS, RISC-V, AVR, Z80) and optimization levels using Docker.
- **Headless Ghidra Analysis**: Automates Ghidra to analyze binaries and export P-Code/instruction data to JSON.
- **Feature Extraction**: Extracts cryptographic indicators (S-Boxes, constants) and structural features (entropy, instruction histograms) from binaries and analysis results.

## Prerequisites

- **Docker**: Required for the cross-compilation environment.
- **Python 3.x**: For running the orchestration scripts.
- **Ghidra**: Required for `analyzer.py` to perform binary analysis.

## Installation

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd cross-compiler
   ```

2. Build the Docker image (required for `builder.py`):
   ```bash
   python3 builder.py --source aes_128.c --build-image
   ```
   *Note: You only need to run with `--build-image` once.*

## Usage

### 1. Cross-Compilation (`builder.py`)

Compiles a source C file across all defined architectures and optimization levels.

```bash
python3 builder.py --source <source_file.c> [--output <output_dir>]
```

**Example:**
```bash
python3 builder.py --source aes_128.c --output bin
```
This will generate ELF/IHX binaries in the `bin/` directory for x86_64, ARM, MIPS, RISC-V, AVR, and Z80.

### 2. Binary Analysis (`analyzer.py`)

Uses Ghidra's `analyzeHeadless` to process all binaries in the `bin/` directory and export intermediate data.

**Configuration:**
Update the `GHIDRA_HOME` variable in `analyzer.py` to point to your Ghidra installation.

```bash
python3 analyzer.py
```
This produces `ghidra_output.json` (or individual JSONs depending on script configuration) containing function and instruction data.

### 3. Feature Extraction (`extract_features.py`)

Extracts ML-ready features from a binary and its corresponding Ghidra analysis JSON.



### **`4.features.json`**
Final feature vector for **Machine Learning** or **rule-based crypto detection**.



```bash
python3 extract_features.py
```
*Note: Currently configured to run on a specific example in `__main__`. Modify the script to iterate over your dataset as needed.*


## Supported Architectures

The `builder.py` script supports the following architectures via the provided Dockerfile:

- **x86_64** (GCC, Clang)
- **ARM** (arm-linux-gnueabihf)
- **MIPS** (mips-linux-gnu)
- **RISC-V** (riscv64-linux-gnu)
- **AVR** (avr-gcc)
- **Z80** (sdcc)

## Project Structure

- `builder.py`: Orchestrates the Docker-based cross-compilation.
- `Dockerfile`: Defines the build environment with all cross-compilers.
- `analyzer.py`: Wrapper for Ghidra headless analysis.
- `ghidra_script.py`: The Ghidra Python script executed by `analyzeHeadless`.
- `extract_features.py`: Extracts static and structural features from binaries.
- `aes_*.c`: Example cryptographic source files.
