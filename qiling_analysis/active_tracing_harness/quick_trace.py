#!/usr/bin/env python3
"""
Quick Trace - Simplified tracing without symbolic execution

This is a lightweight version of the harness that skips Engine A (angr)
and just does dynamic tracing with a provided input buffer.

Use this when:
- You already know what input data to inject
- You want fast results without symbolic solving
- Testing/debugging the tracing infrastructure

Usage:
    python3 quick_trace.py firmware.elf --input data.bin
    python3 quick_trace.py firmware.elf --input-hex "deadbeef01020304"
"""

import os
import sys
import json
import time
import logging
import argparse
from pathlib import Path

try:
    from qiling import Qiling
    from qiling.const import QL_VERBOSE
    QILING_AVAILABLE = True
except ImportError:
    QILING_AVAILABLE = False
    print("[ERROR] Qiling not available. Install with: pip install qiling")
    sys.exit(1)


class QuickTracer:
    """Lightweight tracer without symbolic execution"""
    
    def __init__(self, binary_path, input_data, output_file, 
                 rootfs=None, max_instr=50000, timeout=30, verbose=False):
        self.binary_path = binary_path
        self.input_data = input_data
        self.output_file = output_file
        self.rootfs = rootfs or "/tmp/qiling_rootfs"
        self.max_instr = max_instr
        self.timeout = timeout
        self.verbose = verbose
        
        self.ql = None
        self.traces = []
        self.instr_count = 0
        self.start_time = 0
        self.injected = False
        
        # Setup logging
        level = logging.DEBUG if verbose else logging.INFO
        logging.basicConfig(
            level=level,
            format='[%(levelname)s] %(message)s'
        )
        self.logger = logging.getLogger('QuickTrace')
    
    def hook_syscalls(self):
        """Hook network syscalls to inject data"""
        
        def recv_hook(ql, sockfd, buf, length, flags):
            if not self.injected:
                bytes_to_inject = min(length, len(self.input_data))
                ql.mem.write(buf, self.input_data[:bytes_to_inject])
                self.logger.info(f"Injected {bytes_to_inject} bytes at recv()")
                self.injected = True
                return bytes_to_inject
            return 0
        
        def read_hook(ql, fd, buf, length):
            if fd > 2 and not self.injected:  # Not stdin/stdout/stderr
                bytes_to_inject = min(length, len(self.input_data))
                ql.mem.write(buf, self.input_data[:bytes_to_inject])
                self.logger.info(f"Injected {bytes_to_inject} bytes at read()")
                self.injected = True
                return bytes_to_inject
            return 0
        
        try:
            self.ql.os.set_syscall("recv", recv_hook)
            self.ql.os.set_syscall("recvfrom", recv_hook)
            self.ql.os.set_syscall("read", read_hook)
        except Exception as e:
            self.logger.warning(f"Syscall hook setup warning: {e}")
    
    def hook_instructions(self):
        """Trace every instruction"""
        
        def trace_insn(ql, address, size):
            self.instr_count += 1
            
            # Check limits
            if self.instr_count > self.max_instr:
                self.logger.warning("Max instructions reached")
                ql.emu_stop()
                return
            
            if time.time() - self.start_time > self.timeout:
                self.logger.warning("Timeout reached")
                ql.emu_stop()
                return
            
            # Disassemble
            try:
                md = ql.arch.disassembler
                insn_bytes = ql.mem.read(address, size)
                
                mnemonic = "???"
                operands = ""
                
                for insn in md.disasm(insn_bytes, address):
                    mnemonic = insn.mnemonic
                    operands = insn.op_str
                    break
                
                # Store trace
                trace = {
                    'address': hex(address),
                    'mnemonic': mnemonic,
                    'operands': operands,
                    'phase': 'post_injection' if self.injected else 'pre_injection',
                    'instruction_num': self.instr_count,
                    'timestamp': time.time() - self.start_time
                }
                
                self.traces.append(trace)
                
                if self.verbose and self.instr_count % 100 == 0:
                    self.logger.debug(f"Traced {self.instr_count} instructions")
                
            except Exception as e:
                if self.verbose:
                    self.logger.debug(f"Trace error at {hex(address)}: {e}")
        
        self.ql.hook_code(trace_insn)
    
    def run(self):
        """Execute the trace"""
        self.logger.info("=" * 60)
        self.logger.info("Quick Trace - Lightweight Firmware Tracer")
        self.logger.info("=" * 60)
        self.logger.info(f"Binary: {self.binary_path}")
        self.logger.info(f"Input: {len(self.input_data)} bytes")
        self.logger.info(f"Output: {self.output_file}")
        
        # Setup Qiling
        try:
            self.logger.info("Initializing Qiling...")
            self.ql = Qiling(
                [self.binary_path],
                self.rootfs,
                verbose=QL_VERBOSE.DEBUG if self.verbose else QL_VERBOSE.OFF
            )
            self.logger.info(f"Loaded: {self.ql.arch.type.name} / {self.ql.os.type.name}")
        except Exception as e:
            self.logger.error(f"Failed to initialize Qiling: {e}")
            return False
        
        # Install hooks
        self.hook_syscalls()
        self.hook_instructions()
        
        # Run
        try:
            self.logger.info("Starting execution...")
            self.start_time = time.time()
            self.ql.run()
            elapsed = time.time() - self.start_time
            
            self.logger.info(f"Execution finished in {elapsed:.2f}s")
            self.logger.info(f"Traced {self.instr_count} instructions")
            
        except Exception as e:
            self.logger.warning(f"Execution stopped: {e}")
            self.logger.info(f"Partial trace: {self.instr_count} instructions")
        
        # Save trace
        try:
            with open(self.output_file, 'w') as f:
                for trace in self.traces:
                    f.write(json.dumps(trace) + '\n')
            
            self.logger.info(f"Saved {len(self.traces)} events to {self.output_file}")
            
            # Stats
            pre = sum(1 for t in self.traces if t['phase'] == 'pre_injection')
            post = sum(1 for t in self.traces if t['phase'] == 'post_injection')
            
            self.logger.info(f"Phase breakdown:")
            self.logger.info(f"  Pre-injection:  {pre:6d} instructions")
            self.logger.info(f"  Post-injection: {post:6d} instructions")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to save trace: {e}")
            return False


def main():
    parser = argparse.ArgumentParser(
        description='Quick Trace - Fast firmware tracing without symbolic execution',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('binary', help='Target binary to trace')
    
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('--input', help='Input data file (binary)')
    input_group.add_argument('--input-hex', help='Input data as hex string')
    input_group.add_argument('--input-string', help='Input data as ASCII string')
    
    parser.add_argument('--rootfs', help='Qiling rootfs path')
    parser.add_argument('-o', '--output', default='quick_trace.jsonl',
                       help='Output trace file (default: quick_trace.jsonl)')
    parser.add_argument('--max-instructions', type=int, default=50000,
                       help='Max instructions to trace (default: 50000)')
    parser.add_argument('--timeout', type=int, default=30,
                       help='Execution timeout in seconds (default: 30)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')
    
    args = parser.parse_args()
    
    # Validate binary
    if not os.path.exists(args.binary):
        print(f"[ERROR] Binary not found: {args.binary}")
        return 1
    
    # Load input data
    if args.input:
        try:
            with open(args.input, 'rb') as f:
                input_data = f.read()
        except Exception as e:
            print(f"[ERROR] Could not read input file: {e}")
            return 1
    elif args.input_hex:
        try:
            # Remove spaces, 0x prefix, etc.
            hex_str = args.input_hex.replace(' ', '').replace('0x', '')
            input_data = bytes.fromhex(hex_str)
        except Exception as e:
            print(f"[ERROR] Invalid hex string: {e}")
            return 1
    elif args.input_string:
        input_data = args.input_string.encode('utf-8')
    
    # Run tracer
    tracer = QuickTracer(
        binary_path=args.binary,
        input_data=input_data,
        output_file=args.output,
        rootfs=args.rootfs,
        max_instr=args.max_instructions,
        timeout=args.timeout,
        verbose=args.verbose
    )
    
    success = tracer.run()
    
    if success:
        print("\n[SUCCESS] Trace complete!")
        print(f"View trace: less {args.output}")
        print(f"Analyze: jq '.' {args.output}")
        return 0
    else:
        print("\n[FAILED] Trace did not complete successfully")
        return 1


if __name__ == '__main__':
    sys.exit(main())
