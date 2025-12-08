#!/usr/bin/env python3
"""
Trace a crypto binary and analyze it
"""
import sys
from qiling import Qiling
from qiling.const import QL_VERBOSE
import json
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_ARCH_X86, CS_MODE_64

def trace_crypto_binary(binary_path, output_file):
    """Trace execution of a crypto binary"""
    
    # Detect architecture
    with open(binary_path, 'rb') as f:
        header = f.read(20)
        is_64bit = header[4] == 2  # ELF class 64-bit
    
    # Setup rootfs based on architecture
    if 'x86' in binary_path:
        if is_64bit:
            rootfs = "qiling_analysis/rootfs/x8664_linux"
            cs_arch = CS_ARCH_X86
            cs_mode = CS_MODE_64
        else:
            rootfs = "qiling_analysis/rootfs/x86_linux"
            cs_arch = CS_ARCH_X86
            cs_mode = CS_MODE_32
    elif 'arm' in binary_path:
        rootfs = "qiling_analysis/rootfs/arm_linux"
        cs_arch = CS_ARCH_ARM
        cs_mode = CS_MODE_ARM
    else:
        print(f"[!] Unsupported architecture in: {binary_path}")
        return False
    
    print(f"[*] Binary: {binary_path}")
    print(f"[*] Rootfs: {rootfs}")
    print(f"[*] Architecture: {'x86_64' if is_64bit else 'x86_32'}")
    
    # Initialize disassembler
    md = Cs(cs_arch, cs_mode)
    
    # Output file
    trace_file = open(output_file, 'w')
    instruction_count = 0
    
    def hook_code(ql, address, size):
        nonlocal instruction_count
        try:
            buf = ql.mem.read(address, size)
            for i in md.disasm(buf, address):
                instruction_count += 1
                
                # Capture event
                event = {
                    'address': f'0x{i.address:x}',
                    'mnemonic': i.mnemonic,
                    'op_str': i.op_str,
                    'phase': 'execution'
                }
                
                trace_file.write(json.dumps(event) + '\n')
                
                # Progress indicator
                if instruction_count % 1000 == 0:
                    print(f"[*] Traced {instruction_count:,} instructions...", end='\r')
                
                # Stop after reasonable amount
                if instruction_count >= 50000:
                    print(f"\n[*] Reached instruction limit (50k)")
                    ql.emu_stop()
                    
        except Exception as e:
            pass
    
    try:
        # Create Qiling instance
        ql = Qiling([binary_path], rootfs, verbose=QL_VERBOSE.OFF)
        
        # Hook all instructions
        ql.hook_code(hook_code)
        
        print(f"[*] Starting emulation...")
        ql.run()
        
        print(f"\n[✓] Traced {instruction_count:,} instructions")
        print(f"[✓] Output: {output_file}")
        
        trace_file.close()
        return True
        
    except Exception as e:
        print(f"[!] Error during emulation: {e}")
        trace_file.close()
        return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 trace_crypto_binary.py <binary> [output.jsonl]")
        sys.exit(1)
    
    binary = sys.argv[1]
    output = sys.argv[2] if len(sys.argv) > 2 else "crypto_trace.jsonl"
    
    success = trace_crypto_binary(binary, output)
    sys.exit(0 if success else 1)
