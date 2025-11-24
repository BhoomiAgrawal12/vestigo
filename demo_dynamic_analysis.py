import sys
import os
import time
import logging
from unittest.mock import MagicMock, patch

# Mock frida before importing instrumentation
sys.modules["frida"] = MagicMock()

# Ensure we can import modules from the current directory
sys.path.append(os.path.join(os.getcwd(), 'dynamic_analysis'))

# Import the actual modules (now that frida is mocked)
from dynamic_main import DynamicOrchestrator
from emulator import EmulatorRunner
from instrumentation import Instrumentation

# Configure logging to match the main script
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("DemoRunner")

def run_demo():
    print("=== STARTING DEMO MODE ===")
    print("Note: This demo mocks QEMU and Frida to show the workflow logic.")
    print("---------------------------------------------------------------")

    # Mock findings
    findings = {
        'openssl_symbols': ['AES_encrypt', 'RSA_public_decrypt'],
        'custom_crypto': [{'address': '0x00401234'}]
    }

    # Patch the internal components to simulate behavior
    # When 'from module import Class' is used, we must patch the name in the importing module.
    with patch('dynamic_main.EmulatorRunner') as MockEmulator, \
         patch('dynamic_main.Instrumentation') as MockInstrumentation:
        
        # 1. Setup Emulator Mock
        emulator_instance = MockEmulator.return_value
        emulator_instance.get_pid.return_value = 1337
        
        # Simulate stdout stream with security leaks
        mock_process = MagicMock()
        mock_process.stdout = [
            "Booting firmware...",
            "Loading kernel...",
            "Error: Signature verification failed for image", # Leak 1
            "Retrying...",
            "Loading fallback kernel...", # Leak 2
            "System ready."
        ]
        emulator_instance.start.return_value = mock_process

        # 2. Setup Instrumentation Mock
        instr_instance = MockInstrumentation.return_value
        def side_effect_attach(findings):
            logger.info("Demo: Attached to process 1337")
            logger.info("Demo: Injected hooks for AES_encrypt, RSA_public_decrypt")
            # Simulate capturing a secret
            with open("secrets.log", "w") as f:
                f.write("{'type': 'openssl_call', 'symbol': 'AES_encrypt', 'args': {'arg0': '0xdeadbeef'}}\\n")
        
        instr_instance.attach_and_inject.side_effect = side_effect_attach

        # Create the orchestrator INSIDE the patch block so it uses the mocks
        orchestrator = DynamicOrchestrator("./demo_binary", "arm", "/tmp/sysroot", findings)

        # 3. Run the orchestrator (shortened duration)
        orchestrator.duration = 2
        orchestrator.run()

    print("\n=== DEMO COMPLETE ===")

if __name__ == "__main__":
    run_demo()
