import time
import threading
import logging
import sys
import os

# Ensure we can import modules from the current directory
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from emulator import EmulatorRunner
from instrumentation import Instrumentation
from log_monitor import LogMonitor

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("DynamicOrchestrator")

class DynamicOrchestrator:
    def __init__(self, binary_path, architecture, sysroot_path, findings):
        self.emulator = EmulatorRunner(binary_path, architecture, sysroot_path)
        self.instrumentation = Instrumentation(None) # PID will be set later
        self.log_monitor = LogMonitor()
        self.findings = findings
        self.duration = 30 # seconds

    def run(self):
        logger.info("Starting Dynamic Analysis Orchestration...")

        # 1. Start QEMU
        try:
            process = self.emulator.start(trace_mode=True)
        except Exception as e:
            logger.error(f"Aborting: {e}")
            return

        # 2. Wait for initialization (simple sleep for now)
        time.sleep(2)
        pid = self.emulator.get_pid()
        if not pid:
            logger.error("Process failed to start or died immediately.")
            return

        logger.info(f"Target process running with PID: {pid}")
        self.instrumentation.target = pid

        # 3. Inject Frida Hooks
        try:
            self.instrumentation.attach_and_inject(self.findings)
        except Exception as e:
            logger.error(f"Instrumentation failed: {e}")
            # We might continue even if instrumentation fails, to check logs
        
        # 4. Monitor Logs (in a separate thread to not block the timer)
        def monitor_stdout():
            if process.stdout:
                self.log_monitor.analyze_stream(process.stdout)
        
        monitor_thread = threading.Thread(target=monitor_stdout)
        monitor_thread.daemon = True
        monitor_thread.start()

        # 5. Run for duration
        logger.info(f"Running for {self.duration} seconds...")
        time.sleep(self.duration)

        # 6. Kill process and report
        self.emulator.stop()
        self.instrumentation.detach()
        
        logger.info("Analysis Complete.")
        self.report_findings()

    def report_findings(self):
        print("\n=== Dynamic Analysis Report ===")
        print("Log Analysis Findings:")
        for finding in self.log_monitor.get_findings():
            print(f" - {finding}")
        
        print("\nRuntime Secrets (from secrets.log):")
        if os.path.exists("secrets.log"):
            with open("secrets.log", "r") as f:
                print(f.read())
        else:
            print(" - No secrets captured.")
        print("===============================\n")

if __name__ == "__main__":
    # Example Usage / Test
    # In a real pipeline, these arguments would come from the previous modules
    if len(sys.argv) < 4:
        print("Usage: python dynamic_main.py <binary> <arch> <sysroot>")
        sys.exit(1)
        
    binary = sys.argv[1]
    arch = sys.argv[2]
    sysroot = sys.argv[3]
    
    # Mock findings from previous modules
    mock_findings = {
        'openssl_symbols': ['AES_encrypt', 'RSA_public_decrypt'],
        # 'custom_crypto': [{'address': '0x1234'}] 
    }
    
    orchestrator = DynamicOrchestrator(binary, arch, sysroot, mock_findings)
    orchestrator.run()
