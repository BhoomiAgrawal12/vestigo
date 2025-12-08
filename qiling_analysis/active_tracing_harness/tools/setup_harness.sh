#!/bin/bash
# Setup script for Active Tracing Harness
# Run with: bash setup_harness.sh

set -e

echo "========================================"
echo "  Active Tracing Harness Setup"
echo "========================================"
echo ""

# Check Python version
echo "[1/6] Checking Python version..."
python_version=$(python3 --version 2>&1 | awk '{print $2}')
echo "      Found Python $python_version"

# Check for pip
echo "[2/6] Checking pip..."
if ! command -v pip3 &> /dev/null; then
    echo "      ERROR: pip3 not found. Please install pip."
    exit 1
fi
echo "      pip3 found"

# Install Python dependencies
echo "[3/6] Installing Python dependencies..."
echo "      This may take several minutes..."
if pip3 install -r requirements_harness.txt; then
    echo "      ✓ Dependencies installed"
else
    echo "      ⚠ Some dependencies failed to install"
    echo "      This is often normal - angr can be tricky"
    echo "      Continuing anyway..."
fi

# Setup Qiling rootfs
echo "[4/6] Setting up Qiling rootfs..."
if [ ! -d "/tmp/qiling_rootfs" ]; then
    echo "      Downloading Qiling rootfs..."
    cd /tmp
    if git clone https://github.com/qilingframework/rootfs.git qiling_rootfs 2>/dev/null; then
        echo "      ✓ Rootfs downloaded"
    else
        echo "      ⚠ Could not download rootfs"
        echo "      You may need to set it up manually"
    fi
    cd - > /dev/null
else
    echo "      ✓ Rootfs already exists"
fi

# Check for GCC (for test binaries)
echo "[5/6] Checking for GCC..."
if command -v gcc &> /dev/null; then
    gcc_version=$(gcc --version | head -n1)
    echo "      ✓ $gcc_version"
else
    echo "      ⚠ GCC not found - you won't be able to compile test binaries"
fi

# Make scripts executable
echo "[6/6] Making scripts executable..."
chmod +x harness.py 2>/dev/null || true
chmod +x demo_harness.py 2>/dev/null || true
echo "      ✓ Scripts ready"

echo ""
echo "========================================"
echo "  Setup Complete!"
echo "========================================"
echo ""
echo "Quick start:"
echo "  1. Test the demo:"
echo "     python3 demo_harness.py"
echo ""
echo "  2. Run on your own binary:"
echo "     python3 harness.py your_firmware.elf"
echo ""
echo "  3. Read the documentation:"
echo "     less HARNESS_README.md"
echo ""
echo "Troubleshooting:"
echo "  - If angr fails, try: pip install --no-binary angr angr"
echo "  - If Qiling fails, check /tmp/qiling_rootfs exists"
echo "  - For ARM/MIPS, install cross-compilers:"
echo "    sudo apt install gcc-arm-linux-gnueabi gcc-mips-linux-gnu"
echo ""
echo "========================================"
