import unittest
import os
import sys
import shutil
from unittest.mock import MagicMock

# Mock frida before importing instrumentation
sys.modules["frida"] = MagicMock()

# Ensure we can import modules from the current directory
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from emulator import EmulatorRunner
from log_monitor import LogMonitor
from instrumentation import Instrumentation

class TestDynamicAnalysis(unittest.TestCase):

    def test_emulator_command_construction(self):
        """Test if EmulatorRunner constructs the correct command."""
        runner = EmulatorRunner("/bin/ls", "arm", "/tmp/sysroot")
        # We can't easily test the private method _get_qemu_binary without mocking or accessing it directly
        # But we can check if start() fails with a specific error or if we can inspect the object
        
        # Let's just check the binary mapping logic via a helper if we exposed it, 
        # or trust the integration test. 
        # For unit test, let's verify the architecture mapping logic by subclassing or inspecting
        
        self.assertEqual(runner._get_qemu_binary(), "qemu-arm-static")
        
        runner_mips = EmulatorRunner("/bin/ls", "mips", "/tmp/sysroot")
        self.assertEqual(runner_mips._get_qemu_binary(), "qemu-mips-static")

    def test_log_monitor_regex(self):
        """Test if LogMonitor detects the correct patterns."""
        monitor = LogMonitor()
        
        # Test case 1: Secure Boot Failure
        monitor.analyze_line("Error: Signature verification failed for image")
        self.assertEqual(len(monitor.findings), 1)
        self.assertIn("Verification Failure", monitor.findings[0])
        
        # Test case 2: Fallback
        monitor.analyze_line("Loading fallback kernel...")
        self.assertEqual(len(monitor.findings), 2)
        self.assertIn("Downgrade Attack Window", monitor.findings[1])
        
        # Test case 3: Root Key
        monitor.analyze_line("Dump of Root Key: 0xDEADBEEF")
        self.assertEqual(len(monitor.findings), 3)
        self.assertIn("Root of Trust Exposure", monitor.findings[2])
        
        # Test case 4: Benign line
        monitor.analyze_line("System started successfully")
        self.assertEqual(len(monitor.findings), 3) # Should not increase

    def test_instrumentation_hook_generation(self):
        """Test if Instrumentation generates the correct JS code."""
        instr = Instrumentation(1234)
        findings = {
            'openssl_symbols': ['AES_encrypt'],
            'custom_crypto': [{'address': '0x400000'}]
        }
        
        script = instr.generate_hooks_script(findings)
        
        self.assertIn('Module.findExportByName(null, "AES_encrypt")', script)
        self.assertIn('Interceptor.attach(ptr("0x400000")', script)
        self.assertIn('logSecret("openssl_call"', script)
        self.assertIn('logSecret("custom_crypto"', script)

        self.assertIn('logSecret("custom_crypto"', script)

    def test_orchestrator(self):
        """Test the DynamicOrchestrator flow."""
        # Import first to ensure module is loaded
        from dynamic_main import DynamicOrchestrator
        from unittest.mock import patch

        # Mock dependencies where they are USED
        with patch('dynamic_main.EmulatorRunner') as MockEmulator, \
             patch('dynamic_main.Instrumentation') as MockInstrumentation, \
             patch('time.sleep') as mock_sleep:
            
            # Setup mocks
            mock_emulator_instance = MockEmulator.return_value
            mock_emulator_instance.start.return_value = MagicMock(stdout=[]) # Mock process
            mock_emulator_instance.get_pid.return_value = 9999
            
            mock_instrumentation_instance = MockInstrumentation.return_value
            
            # Run orchestrator
            orchestrator = DynamicOrchestrator("/bin/ls", "arm", "/tmp", {})
            orchestrator.duration = 0.1 # Shorten duration
            orchestrator.run()
            
            # Verify calls
            mock_emulator_instance.start.assert_called_once()
            mock_instrumentation_instance.attach_and_inject.assert_called_once()
            mock_emulator_instance.stop.assert_called_once()

if __name__ == '__main__':
    unittest.main()
