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
        binary_name = None
        if arch_lower in arch_map:
            binary_name = arch_map[arch_lower]
        else:
            # Fallback or heuristic
            for key in arch_map:
                if key in arch_lower:
                    binary_name = arch_map[key]
                    break
        
        if not binary_name:
            raise ValueError(f"Unsupported architecture: {self.architecture}")

        # Check local bin directory for DYNAMIC binary first (better for Frida)
        # e.g. qemu-arm-dynamic
        dynamic_name = binary_name.replace("-static", "-dynamic")
        local_dynamic = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'bin', dynamic_name)
        if os.path.exists(local_dynamic):
            return local_dynamic

        # Check local bin directory for STATIC binary
        local_bin = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'bin', binary_name)
        if os.path.exists(local_bin):
            return local_bin
        
        # Fallback to system path
        return binary_name

    def start(self, trace_mode=False, gadget_path=None):
        """Starts the QEMU emulation."""
        qemu_bin = self._get_qemu_binary()
        
        cmd = [qemu_bin, "-L", self.sysroot_path]
        
        if trace_mode:
            cmd.append("-strace")
            
        # Gadget Injection via QEMU_SET_ENV
        env = os.environ.copy()
        if gadget_path:
            # QEMU_SET_ENV passes env vars to the guest
            # We want to set LD_PRELOAD in the guest
            # Format: QEMU_SET_ENV=VAR=VAL,VAR2=VAL2
            # Note: If QEMU_SET_ENV is already set, we should append, but for now just set it.
            env["QEMU_SET_ENV"] = f"LD_PRELOAD={gadget_path}"
            self.logger.info(f"Injecting Frida Gadget: {gadget_path}")

        cmd.append(self.binary_path)
        
        self.logger.info(f"Starting emulation: {' '.join(cmd)}")
        
        try:
            # Start QEMU as a subprocess
            # We use pipes for stdout/stderr to capture logs later if needed
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, # Merge stderr for log monitoring
                text=True, # Ensure we get string output
                env=env # Pass environment with QEMU_SET_ENV
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
