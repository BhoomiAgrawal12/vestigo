import subprocess
import os
import logging
import time

class EmulatorRunner:
    def __init__(self, binary_path, architecture, sysroot_path):
        self.binary_path = binary_path
        self.architecture = architecture
        self.sysroot_path = sysroot_path
        self.process = None
        self.logger = logging.getLogger("EmulatorRunner")

    def _get_qemu_binary(self):
        """Maps architecture to the appropriate QEMU static binary."""
        arch_map = {
            "arm": "qemu-arm-static",
            "mips": "qemu-mips-static",
            "mipsel": "qemu-mipsel-static",
            "x86": "qemu-i386-static",
            "x86_64": "qemu-x86_64-static",
            "aarch64": "qemu-aarch64-static",
            # Add more mappings as needed
        }
        # Normalize architecture string
        arch_lower = self.architecture.lower()
        if arch_lower in arch_map:
            return arch_map[arch_lower]
        
        # Fallback or heuristic
        for key in arch_map:
            if key in arch_lower:
                return arch_map[key]
        
        raise ValueError(f"Unsupported architecture: {self.architecture}")

    def start(self, trace_mode=False):
        """Starts the QEMU emulation."""
        qemu_bin = self._get_qemu_binary()
        
        cmd = [qemu_bin]
        
        if self.sysroot_path:
             cmd.extend(["-L", self.sysroot_path])
             
        if trace_mode:
            cmd.append("-strace")
            
        cmd.append(self.binary_path)
        
        self.logger.info(f"Starting emulation: {' '.join(cmd)}")
        
        try:
            # Start QEMU as a subprocess
            # We use pipes for stdout/stderr to capture logs later if needed
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True, # Ensure we get string output
                bufsize=1  # Line buffered
            )
            return self.process
        except FileNotFoundError:
            self.logger.error(f"QEMU binary '{qemu_bin}' not found. Please install qemu-user-static.")
            raise
        except Exception as e:
            self.logger.error(f"Failed to start emulation: {e}")
            raise

    def stop(self):
        """Stops the emulated process."""
        if self.process:
            self.logger.info("Stopping emulation...")
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
            self.process = None

    def get_pid(self):
        """Returns the PID of the running process."""
        if self.process:
            return self.process.pid
        return None
