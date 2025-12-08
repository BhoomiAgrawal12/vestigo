#!/usr/bin/env python3
"""
Active Tracing Harness for Closed-Source Firmware Analysis
===========================================================

This harness combines symbolic execution (angr) with dynamic tracing (Qiling)
to analyze firmware binaries that communicate over proprietary protocols without
requiring a live network connection.

Architecture:
    Engine A (Solver): Uses angr to symbolically execute and find valid inputs
    Engine B (Tracer): Uses Qiling to inject inputs and trace execution

Author: Security Research Team
Date: December 2025
"""

import os
import sys
import json
import time
import logging
import argparse
from pathlib import Path
from typing import Optional, Dict, List, Tuple, Any
from dataclasses import dataclass, asdict
from enum import Enum

# Symbolic execution
try:
    import angr
    import claripy
    ANGR_AVAILABLE = True
except ImportError:
    ANGR_AVAILABLE = False
    print("[WARNING] angr not available. Install with: pip install angr")

# Dynamic instrumentation
try:
    from qiling import Qiling
    from qiling.const import QL_VERBOSE
    QILING_AVAILABLE = True
except ImportError:
    QILING_AVAILABLE = False
    print("[WARNING] Qiling not available. Install with: pip install qiling")


# ============================================================================
# Configuration and Data Classes
# ============================================================================

class TracePhase(Enum):
    """Execution phases for trace tagging"""
    INIT = "init"
    HANDSHAKE = "handshake"
    KEY_EXCHANGE = "key_exchange"
    PROCESSING = "processing"
    ERROR = "error"


@dataclass
class TraceEvent:
    """Single instruction trace event"""
    address: int
    mnemonic: str
    operands: str
    phase: str
    timestamp: float
    registers: Optional[Dict[str, int]] = None
    memory_access: Optional[str] = None
    
    def to_json(self) -> str:
        """Convert to JSON line for JSONL output"""
        return json.dumps({
            'address': hex(self.address),
            'mnemonic': self.mnemonic,
            'operands': self.operands,
            'phase': self.phase,
            'timestamp': self.timestamp,
            'registers': {k: hex(v) if isinstance(v, int) else v 
                         for k, v in (self.registers or {}).items()},
            'memory_access': self.memory_access
        })


@dataclass
class HarnessConfig:
    """Configuration for the harness"""
    binary_path: str
    architecture: str = "auto"  # auto, arm, mips, x86_64, x86, avr
    rootfs_path: Optional[str] = None
    
    # Engine A (angr) settings
    angr_timeout: int = 300  # seconds
    angr_max_steps: int = 1000
    symbolic_buffer_size: int = 256
    recv_func_name: str = "recv"  # or read, uart_read, etc.
    recv_address: Optional[int] = None
    
    # Engine B (Qiling) settings
    qiling_timeout: int = 60
    trace_output: str = "trace.jsonl"
    golden_input_file: str = "golden_input.bin"
    log_level: str = "INFO"
    
    # Advanced options
    explore_avoid_addresses: List[int] = None
    explore_find_addresses: List[int] = None
    max_trace_instructions: int = 100000
    capture_registers: bool = True
    verbose: bool = False


# ============================================================================
# Engine A: Symbolic Solver (angr)
# ============================================================================

class SymbolicSolver:
    """
    Uses angr to find valid inputs that allow the binary to proceed
    past network read operations without hanging or erroring.
    """
    
    def __init__(self, config: HarnessConfig):
        self.config = config
        self.project = None
        self.logger = logging.getLogger("EngineA.Solver")
        
    def load_binary(self) -> bool:
        """Load the binary into angr"""
        if not ANGR_AVAILABLE:
            self.logger.error("angr is not available")
            return False
            
        try:
            self.logger.info(f"Loading binary: {self.config.binary_path}")
            self.project = angr.Project(
                self.config.binary_path,
                auto_load_libs=False,
                load_options={'auto_load_libs': False}
            )
            self.logger.info(f"Detected architecture: {self.project.arch.name}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to load binary: {e}")
            return False
    
    def find_recv_address(self) -> Optional[int]:
        """
        Attempt to locate the recv/read function address.
        Tries multiple strategies:
        1. Symbol table lookup
        2. PLT/GOT entries
        3. User-provided address
        4. Heuristic scanning for common patterns
        """
        if self.config.recv_address:
            self.logger.info(f"Using user-provided recv address: {hex(self.config.recv_address)}")
            return self.config.recv_address
        
        # Strategy 1: Symbol lookup
        try:
            symbol = self.project.loader.find_symbol(self.config.recv_func_name)
            if symbol:
                self.logger.info(f"Found {self.config.recv_func_name} at {hex(symbol.rebased_addr)}")
                return symbol.rebased_addr
        except Exception as e:
            self.logger.debug(f"Symbol lookup failed: {e}")
        
        # Strategy 2: PLT entries
        for addr, name in self.project.loader.main_object.plt.items():
            if self.config.recv_func_name in name:
                self.logger.info(f"Found {name} in PLT at {hex(addr)}")
                return addr
        
        # Strategy 3: Scan for syscall patterns (Linux ARM example)
        if 'arm' in self.project.arch.name.lower():
            self.logger.info("Scanning for syscall patterns (ARM recv/read)")
            # Look for: mov r7, #3 (read syscall); svc 0
            # This is a simplified heuristic
            pass
        
        self.logger.warning("Could not automatically find recv function")
        return None
    
    def solve_for_valid_input(self, recv_addr: int) -> Optional[bytes]:
        """
        Use symbolic execution to find an input that causes the binary
        to execute successfully past the recv call.
        
        Strategy:
        1. Create symbolic buffer for recv data
        2. Hook recv to return symbolic data
        3. Explore paths avoiding error/exit
        4. Extract concrete input from successful state
        """
        try:
            self.logger.info("Starting symbolic execution...")
            
            # Create entry state
            state = self.project.factory.entry_state(
                add_options={
                    angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
                }
            )
            
            # Create symbolic buffer for network input
            symbolic_buffer = claripy.BVS(
                'network_input',
                self.config.symbolic_buffer_size * 8
            )
            
            # Store symbolic buffer at a known address
            buffer_addr = 0x50000000  # Arbitrary high address
            state.memory.store(buffer_addr, symbolic_buffer)
            
            # Hook the recv function
            recv_hook_addr = recv_addr
            
            @self.project.hook(recv_hook_addr, length=0)
            def recv_hook(state):
                """Simulate recv returning our symbolic data"""
                # recv(int sockfd, void *buf, size_t len, int flags)
                # Returns number of bytes received
                
                buf_ptr = state.regs.r1 if 'arm' in self.project.arch.name.lower() else state.regs.rsi
                length = state.regs.r2 if 'arm' in self.project.arch.name.lower() else state.regs.rdx
                
                # Copy symbolic buffer to the destination
                state.memory.store(buf_ptr, symbolic_buffer)
                
                # Return the length
                if 'arm' in self.project.arch.name.lower():
                    state.regs.r0 = self.config.symbolic_buffer_size
                else:
                    state.regs.rax = self.config.symbolic_buffer_size
                
                self.logger.debug("recv hook triggered, returning symbolic data")
            
            # Setup simulation manager
            simgr = self.project.factory.simulation_manager(state)
            
            # Define exploration strategy
            avoid_addresses = self.config.explore_avoid_addresses or []
            find_addresses = self.config.explore_find_addresses
            
            # Add common error/exit patterns to avoid list
            exit_symbols = ['exit', '_exit', 'abort', 'error', 'panic']
            for sym_name in exit_symbols:
                try:
                    sym = self.project.loader.find_symbol(sym_name)
                    if sym:
                        avoid_addresses.append(sym.rebased_addr)
                except:
                    pass
            
            self.logger.info(f"Exploring with {len(avoid_addresses)} avoid addresses")
            
            # Explore with timeout
            start_time = time.time()
            step_count = 0
            
            while len(simgr.active) > 0 and step_count < self.config.angr_max_steps:
                if time.time() - start_time > self.config.angr_timeout:
                    self.logger.warning("Symbolic execution timeout reached")
                    break
                
                simgr.step()
                step_count += 1
                
                if step_count % 100 == 0:
                    self.logger.debug(f"Step {step_count}: {len(simgr.active)} active, "
                                    f"{len(simgr.deadended)} deadended")
                
                # Check if we found a good state
                if find_addresses:
                    for state in simgr.active:
                        if state.addr in find_addresses:
                            self.logger.info(f"Found target address: {hex(state.addr)}")
                            return self._extract_input(state, symbolic_buffer)
                
                # Remove states that hit avoid addresses
                for state in list(simgr.active):
                    if state.addr in avoid_addresses:
                        self.logger.debug(f"Avoiding address: {hex(state.addr)}")
                        simgr.active.remove(state)
            
            # If no specific find address, use the first successful state
            if len(simgr.deadended) > 0:
                self.logger.info("Using deadended state (completed execution)")
                return self._extract_input(simgr.deadended[0], symbolic_buffer)
            
            if len(simgr.active) > 0:
                self.logger.info("Using active state (in-progress execution)")
                return self._extract_input(simgr.active[0], symbolic_buffer)
            
            self.logger.error("No viable states found")
            return None
            
        except Exception as e:
            self.logger.error(f"Symbolic execution failed: {e}", exc_info=True)
            return None
    
    def _extract_input(self, state, symbolic_buffer) -> bytes:
        """Extract concrete input from a state"""
        try:
            # Evaluate the symbolic buffer to get concrete bytes
            concrete_input = state.solver.eval(symbolic_buffer, cast_to=bytes)
            self.logger.info(f"Extracted {len(concrete_input)} bytes of input")
            return concrete_input
        except Exception as e:
            self.logger.error(f"Failed to extract input: {e}")
            # Return a basic valid-looking buffer
            return b'\x00' * self.config.symbolic_buffer_size
    
    def save_golden_input(self, input_data: bytes) -> bool:
        """Save the solved input to a file"""
        try:
            with open(self.config.golden_input_file, 'wb') as f:
                f.write(input_data)
            self.logger.info(f"Golden input saved to {self.config.golden_input_file}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to save golden input: {e}")
            return False
    
    def run(self) -> Optional[bytes]:
        """Main execution flow for Engine A"""
        self.logger.info("=" * 60)
        self.logger.info("ENGINE A: SYMBOLIC SOLVER")
        self.logger.info("=" * 60)
        
        if not self.load_binary():
            return None
        
        recv_addr = self.find_recv_address()
        if not recv_addr:
            self.logger.error("Cannot proceed without recv address. "
                            "Use --recv-address to specify manually")
            return None
        
        golden_input = self.solve_for_valid_input(recv_addr)
        if golden_input:
            self.save_golden_input(golden_input)
        
        return golden_input


# ============================================================================
# Engine B: Dynamic Tracer (Qiling)
# ============================================================================

class DynamicTracer:
    """
    Uses Qiling to dynamically execute the binary, inject the golden input,
    and capture detailed execution traces for ML analysis.
    """
    
    def __init__(self, config: HarnessConfig):
        self.config = config
        self.ql: Optional[Qiling] = None
        self.logger = logging.getLogger("EngineB.Tracer")
        self.trace_events: List[TraceEvent] = []
        self.current_phase = TracePhase.INIT
        self.golden_input: Optional[bytes] = None
        self.instruction_count = 0
        self.start_time = time.time()
        self.recv_called = False
        
    def load_golden_input(self) -> bool:
        """Load the golden input found by Engine A"""
        try:
            with open(self.config.golden_input_file, 'rb') as f:
                self.golden_input = f.read()
            self.logger.info(f"Loaded {len(self.golden_input)} bytes of golden input")
            return True
        except Exception as e:
            self.logger.error(f"Failed to load golden input: {e}")
            return False
    
    def setup_qiling(self) -> bool:
        """Initialize Qiling with the target binary"""
        if not QILING_AVAILABLE:
            self.logger.error("Qiling is not available")
            return False
        
        try:
            # Determine rootfs
            rootfs = self.config.rootfs_path
            if not rootfs:
                # Try to use Qiling's default rootfs
                arch_map = {
                    'arm': 'arm_linux',
                    'aarch64': 'arm64_linux',
                    'mips': 'mips_linux',
                    'x86_64': 'x8664_linux',
                    'x86': 'x86_linux',
                }
                # This is a simplified guess - in production, handle this better
                rootfs = f"/tmp/qiling_rootfs"
            
            self.logger.info(f"Initializing Qiling with binary: {self.config.binary_path}")
            
            # Create Qiling instance
            self.ql = Qiling(
                [self.config.binary_path],
                rootfs,
                verbose=QL_VERBOSE.DEBUG if self.config.verbose else QL_VERBOSE.OFF
            )
            
            self.logger.info(f"Qiling initialized - Arch: {self.ql.arch.type}, "
                           f"OS: {self.ql.os.type}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to initialize Qiling: {e}", exc_info=True)
            return False
    
    def hook_syscalls(self):
        """Hook network-related syscalls to inject golden input"""
        
        def recv_hook(ql: Qiling, sockfd: int, buf: int, length: int, flags: int):
            """Hook for recv() syscall"""
            self.logger.info(f"recv() called: sockfd={sockfd}, buf={hex(buf)}, len={length}")
            
            if not self.recv_called and self.golden_input:
                # First recv - inject golden input
                bytes_to_inject = min(length, len(self.golden_input))
                ql.mem.write(buf, self.golden_input[:bytes_to_inject])
                
                self.logger.info(f"Injected {bytes_to_inject} bytes of golden input")
                self.recv_called = True
                
                # Transition to HANDSHAKE phase
                self.current_phase = TracePhase.HANDSHAKE
                self.logger.info("Phase transition: INIT -> HANDSHAKE")
                
                # Return number of bytes "received"
                return bytes_to_inject
            else:
                # Subsequent recv calls - return 0 (connection closed)
                self.logger.debug("Subsequent recv() - returning 0")
                return 0
        
        def read_hook(ql: Qiling, fd: int, buf: int, length: int):
            """Hook for read() syscall (for UART/serial)"""
            self.logger.info(f"read() called: fd={fd}, buf={hex(buf)}, len={length}")
            
            # Treat fd 0-2 as stdin/stdout/stderr normally
            if fd < 3:
                return ql.os.syscall(ql.os.read, fd, buf, length)
            
            # For other FDs, inject golden input
            if not self.recv_called and self.golden_input:
                bytes_to_inject = min(length, len(self.golden_input))
                ql.mem.write(buf, self.golden_input[:bytes_to_inject])
                
                self.logger.info(f"Injected {bytes_to_inject} bytes via read()")
                self.recv_called = True
                self.current_phase = TracePhase.HANDSHAKE
                
                return bytes_to_inject
            else:
                return 0
        
        # Hook the syscalls
        try:
            # Linux syscall numbers (arch-dependent, this is x86_64 example)
            # You'd need to adjust these for ARM/MIPS
            self.ql.os.set_syscall("recv", recv_hook)
            self.ql.os.set_syscall("recvfrom", recv_hook)
            self.ql.os.set_syscall("read", read_hook)
            self.logger.info("Syscall hooks installed")
        except Exception as e:
            self.logger.warning(f"Some syscall hooks failed: {e}")
    
    def hook_instructions(self):
        """Hook every instruction to build execution trace"""
        
        def trace_instruction(ql: Qiling, address: int, size: int):
            """Called for each executed instruction"""
            self.instruction_count += 1
            
            # Check limits
            if self.instruction_count > self.config.max_trace_instructions:
                self.logger.warning("Max trace instructions reached, stopping")
                ql.emu_stop()
                return
            
            if time.time() - self.start_time > self.config.qiling_timeout:
                self.logger.warning("Qiling timeout reached, stopping")
                ql.emu_stop()
                return
            
            try:
                # Disassemble instruction
                md = ql.arch.disassembler
                insn_bytes = ql.mem.read(address, size)
                
                mnemonic = "unknown"
                operands = ""
                
                try:
                    for insn in md.disasm(insn_bytes, address):
                        mnemonic = insn.mnemonic
                        operands = insn.op_str
                        break
                except:
                    pass
                
                # Capture registers if enabled
                registers = None
                if self.config.capture_registers:
                    registers = self._capture_registers(ql)
                
                # Create trace event
                event = TraceEvent(
                    address=address,
                    mnemonic=mnemonic,
                    operands=operands,
                    phase=self.current_phase.value,
                    timestamp=time.time() - self.start_time,
                    registers=registers
                )
                
                self.trace_events.append(event)
                
                # Log progress periodically
                if self.instruction_count % 1000 == 0:
                    self.logger.debug(f"Traced {self.instruction_count} instructions "
                                    f"(Phase: {self.current_phase.value})")
                
            except Exception as e:
                self.logger.debug(f"Error tracing instruction at {hex(address)}: {e}")
        
        self.ql.hook_code(trace_instruction)
        self.logger.info("Instruction trace hook installed")
    
    def _capture_registers(self, ql: Qiling) -> Dict[str, int]:
        """Capture current register state"""
        try:
            arch_type = ql.arch.type.name.lower()
            
            if 'arm' in arch_type:
                return {
                    'r0': ql.arch.regs.r0, 'r1': ql.arch.regs.r1,
                    'r2': ql.arch.regs.r2, 'r3': ql.arch.regs.r3,
                    'sp': ql.arch.regs.sp, 'lr': ql.arch.regs.lr,
                    'pc': ql.arch.regs.pc
                }
            elif 'mips' in arch_type:
                return {
                    'v0': ql.arch.regs.v0, 'v1': ql.arch.regs.v1,
                    'a0': ql.arch.regs.a0, 'a1': ql.arch.regs.a1,
                    'sp': ql.arch.regs.sp, 'ra': ql.arch.regs.ra,
                    'pc': ql.arch.regs.pc
                }
            elif 'x86' in arch_type:
                if '64' in arch_type:
                    return {
                        'rax': ql.arch.regs.rax, 'rbx': ql.arch.regs.rbx,
                        'rcx': ql.arch.regs.rcx, 'rdx': ql.arch.regs.rdx,
                        'rsp': ql.arch.regs.rsp, 'rip': ql.arch.regs.rip
                    }
                else:
                    return {
                        'eax': ql.arch.regs.eax, 'ebx': ql.arch.regs.ebx,
                        'ecx': ql.arch.regs.ecx, 'edx': ql.arch.regs.edx,
                        'esp': ql.arch.regs.esp, 'eip': ql.arch.regs.eip
                    }
        except Exception as e:
            self.logger.debug(f"Error capturing registers: {e}")
        
        return {}
    
    def save_trace(self) -> bool:
        """Save execution trace to JSONL file"""
        try:
            with open(self.config.trace_output, 'w') as f:
                for event in self.trace_events:
                    f.write(event.to_json() + '\n')
            
            self.logger.info(f"Saved {len(self.trace_events)} trace events to "
                           f"{self.config.trace_output}")
            
            # Print statistics
            phase_counts = {}
            for event in self.trace_events:
                phase_counts[event.phase] = phase_counts.get(event.phase, 0) + 1
            
            self.logger.info("Trace statistics by phase:")
            for phase, count in phase_counts.items():
                self.logger.info(f"  {phase}: {count} instructions")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to save trace: {e}")
            return False
    
    def run(self) -> bool:
        """Main execution flow for Engine B"""
        self.logger.info("=" * 60)
        self.logger.info("ENGINE B: DYNAMIC TRACER")
        self.logger.info("=" * 60)
        
        if not self.load_golden_input():
            self.logger.warning("No golden input available, using empty buffer")
            self.golden_input = b'\x00' * 256
        
        if not self.setup_qiling():
            return False
        
        self.hook_syscalls()
        self.hook_instructions()
        
        try:
            self.logger.info("Starting execution trace...")
            self.start_time = time.time()
            
            self.ql.run()
            
            elapsed = time.time() - self.start_time
            self.logger.info(f"Execution completed in {elapsed:.2f}s")
            self.logger.info(f"Traced {self.instruction_count} instructions")
            
        except Exception as e:
            self.logger.error(f"Execution error: {e}", exc_info=True)
            self.logger.info(f"Partial trace captured: {self.instruction_count} instructions")
        
        return self.save_trace()


# ============================================================================
# Master Orchestrator
# ============================================================================

class ActiveTracingHarness:
    """
    Master orchestrator that runs both engines in sequence to produce
    a complete execution trace of the firmware binary.
    """
    
    def __init__(self, config: HarnessConfig):
        self.config = config
        self.logger = logging.getLogger("Harness")
        
    def run(self) -> bool:
        """Execute the full harness pipeline"""
        self.logger.info("=" * 80)
        self.logger.info("ACTIVE TRACING HARNESS - START")
        self.logger.info("=" * 80)
        self.logger.info(f"Target binary: {self.config.binary_path}")
        self.logger.info(f"Architecture: {self.config.architecture}")
        
        overall_start = time.time()
        
        # Phase 1: Symbolic Solver
        if ANGR_AVAILABLE:
            solver = SymbolicSolver(self.config)
            golden_input = solver.run()
            
            if not golden_input:
                self.logger.warning("Engine A failed to find golden input")
                self.logger.info("Attempting to continue with Engine B using fallback input")
        else:
            self.logger.warning("angr not available, skipping Engine A")
            # Create a dummy golden input
            dummy_input = b'\x16\x03\x01\x00\x01\x01' + b'\x00' * 250  # Fake TLS ClientHello
            with open(self.config.golden_input_file, 'wb') as f:
                f.write(dummy_input)
        
        # Phase 2: Dynamic Tracer
        if QILING_AVAILABLE:
            tracer = DynamicTracer(self.config)
            success = tracer.run()
            
            if not success:
                self.logger.error("Engine B failed to complete tracing")
                return False
        else:
            self.logger.error("Qiling not available, cannot run Engine B")
            return False
        
        overall_elapsed = time.time() - overall_start
        
        self.logger.info("=" * 80)
        self.logger.info("ACTIVE TRACING HARNESS - COMPLETE")
        self.logger.info("=" * 80)
        self.logger.info(f"Total execution time: {overall_elapsed:.2f}s")
        self.logger.info(f"Output files:")
        self.logger.info(f"  - Golden input: {self.config.golden_input_file}")
        self.logger.info(f"  - Execution trace: {self.config.trace_output}")
        
        return True


# ============================================================================
# CLI and Main Entry Point
# ============================================================================

def setup_logging(level: str, verbose: bool):
    """Configure logging"""
    log_level = getattr(logging, level.upper(), logging.INFO)
    
    # Create formatters
    detailed_formatter = logging.Formatter(
        '[%(asctime)s] %(name)-20s %(levelname)-8s %(message)s',
        datefmt='%H:%M:%S'
    )
    
    simple_formatter = logging.Formatter(
        '%(levelname)-8s %(message)s'
    )
    
    # Console handler
    console = logging.StreamHandler()
    console.setLevel(log_level)
    console.setFormatter(detailed_formatter if verbose else simple_formatter)
    
    # File handler
    file_handler = logging.FileHandler('harness.log', mode='w')
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(detailed_formatter)
    
    # Root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    root_logger.addHandler(console)
    root_logger.addHandler(file_handler)
    
    # Silence noisy libraries
    logging.getLogger('cle').setLevel(logging.WARNING)
    logging.getLogger('angr').setLevel(logging.WARNING)


def parse_arguments():
    """Parse command-line arguments"""
    parser = argparse.ArgumentParser(
        description='Active Tracing Harness for Firmware Analysis',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic usage - auto-detect everything
  python harness.py firmware.elf
  
  # Specify architecture and recv function
  python harness.py firmware.bin --arch arm --recv-func uart_read
  
  # Provide known recv address (from reverse engineering)
  python harness.py firmware.bin --recv-address 0x8048abc
  
  # Use custom rootfs for Qiling
  python harness.py firmware.bin --rootfs /path/to/arm_rootfs
  
  # Specify avoid addresses to guide symbolic execution
  python harness.py firmware.bin --avoid 0x8048100 --avoid 0x8048200
  
  # Skip Engine A and use existing golden input
  python harness.py firmware.bin --skip-solver --golden-input input.bin
        """
    )
    
    # Required
    parser.add_argument('binary', help='Path to the target firmware binary')
    
    # Architecture
    parser.add_argument('--arch', '--architecture',
                       choices=['auto', 'arm', 'aarch64', 'mips', 'x86_64', 'x86', 'avr'],
                       default='auto',
                       help='Target architecture (default: auto-detect)')
    
    parser.add_argument('--rootfs', help='Path to Qiling rootfs (optional)')
    
    # Engine A options
    parser.add_argument('--recv-func', default='recv',
                       help='Name of recv/read function (default: recv)')
    
    parser.add_argument('--recv-address', type=lambda x: int(x, 0),
                       help='Address of recv function (hex or decimal)')
    
    parser.add_argument('--angr-timeout', type=int, default=300,
                       help='angr timeout in seconds (default: 300)')
    
    parser.add_argument('--avoid', action='append', type=lambda x: int(x, 0),
                       help='Addresses to avoid during symbolic execution (can specify multiple)')
    
    parser.add_argument('--find', action='append', type=lambda x: int(x, 0),
                       help='Target addresses to find during symbolic execution')
    
    parser.add_argument('--skip-solver', action='store_true',
                       help='Skip Engine A (symbolic solver)')
    
    parser.add_argument('--golden-input', help='Path to existing golden input file')
    
    # Engine B options
    parser.add_argument('--qiling-timeout', type=int, default=60,
                       help='Qiling execution timeout in seconds (default: 60)')
    
    parser.add_argument('--max-instructions', type=int, default=100000,
                       help='Maximum instructions to trace (default: 100000)')
    
    parser.add_argument('--no-registers', action='store_true',
                       help='Do not capture register state (faster)')
    
    # Output
    parser.add_argument('-o', '--output', default='trace.jsonl',
                       help='Output trace file (default: trace.jsonl)')
    
    # Logging
    parser.add_argument('--log-level',
                       choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                       default='INFO',
                       help='Logging level (default: INFO)')
    
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')
    
    return parser.parse_args()


def main():
    """Main entry point"""
    args = parse_arguments()
    
    # Setup logging
    setup_logging(args.log_level, args.verbose)
    logger = logging.getLogger("Main")
    
    # Validate binary exists
    if not os.path.exists(args.binary):
        logger.error(f"Binary not found: {args.binary}")
        return 1
    
    # Build configuration
    config = HarnessConfig(
        binary_path=os.path.abspath(args.binary),
        architecture=args.arch,
        rootfs_path=args.rootfs,
        angr_timeout=args.angr_timeout,
        recv_func_name=args.recv_func,
        recv_address=args.recv_address,
        qiling_timeout=args.qiling_timeout,
        trace_output=args.output,
        golden_input_file=args.golden_input or 'golden_input.bin',
        log_level=args.log_level,
        explore_avoid_addresses=args.avoid or [],
        explore_find_addresses=args.find or [],
        max_trace_instructions=args.max_instructions,
        capture_registers=not args.no_registers,
        verbose=args.verbose
    )
    
    # If user provided golden input, skip Engine A
    if args.golden_input:
        logger.info(f"Using provided golden input: {args.golden_input}")
        config.golden_input_file = args.golden_input
        args.skip_solver = True
    
    # Check dependencies
    missing_deps = []
    if not ANGR_AVAILABLE and not args.skip_solver:
        missing_deps.append("angr")
    if not QILING_AVAILABLE:
        missing_deps.append("qiling")
    
    if missing_deps:
        logger.error(f"Missing required dependencies: {', '.join(missing_deps)}")
        logger.info("Install with: pip install " + " ".join(missing_deps))
        return 1
    
    # Run harness
    try:
        harness = ActiveTracingHarness(config)
        success = harness.run()
        return 0 if success else 1
    except KeyboardInterrupt:
        logger.warning("\nInterrupted by user")
        return 130
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        return 1


if __name__ == '__main__':
    sys.exit(main())
