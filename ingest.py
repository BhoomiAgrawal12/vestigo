import os
import sys
import shutil
import json
import magic 
from unpack import automate_unpacking 

class IngestionModule:
    def __init__(self, output_base_dir="./analysis_workspace"):
        self.output_base_dir = os.path.abspath(output_base_dir)
        if not os.path.exists(self.output_base_dir):
            os.makedirs(self.output_base_dir)

    def _get_file_type(self, file_path):
        """Uses libmagic to get the true file type."""
        try:
            return magic.from_file(file_path)
        except Exception:
            return "Unknown"

    def _is_linux_fs(self, extracted_path):
        """Heuristic: Does this look like a Linux Filesystem?"""
        indicators = ["bin", "etc", "lib", "usr", "sbin"]
        hits = 0
        # Walk only the top few levels to save time
        for root, dirs, files in os.walk(extracted_path):
            # Check current directory names
            for dirname in dirs:
                if dirname in indicators:
                    hits += 1
            # Check for squashfs-root folder pattern which binwalk creates
            if "squashfs-root" in root:
                hits += 2
                
            if hits >= 2:
                return True
        return False

    def process(self, input_file_path):
        print(f"[\u25B6] Module 1: Ingesting {os.path.basename(input_file_path)}...")
        
        report = {
            "status": "FAILED",
            "file_info": {"original_name": os.path.basename(input_file_path)},
            "extraction": {"was_extracted": False},
            "routing": {"decision": "UNKNOWN"}
        }

        # 1. Identification
        file_type = self._get_file_type(input_file_path)
        report["file_info"]["detected_type"] = file_type
        print(f"    \u21B3 Identified: {file_type}")

        # 2. Extraction (Binwalk)
        # Create a specific folder for this analysis
        analysis_dir = os.path.join(self.output_base_dir, report["file_info"]["original_name"] + "_analysis")
        if os.path.exists(analysis_dir): shutil.rmtree(analysis_dir)
        os.makedirs(analysis_dir)
        
        # Copy input file to analysis dir to keep original safe
        working_file = os.path.join(analysis_dir, os.path.basename(input_file_path))
        shutil.copy(input_file_path, working_file)

        print(f"    \u21B3 Running Recursive Extraction (this may take time)...")
        try:
            # Use the shared unpacker module
            extracted_full_path = automate_unpacking(working_file, analysis_dir)

            if extracted_full_path and os.path.exists(extracted_full_path) and len(os.listdir(extracted_full_path)) > 0:
                report["extraction"]["was_extracted"] = True
                report["extraction"]["extracted_path"] = extracted_full_path
                print(f"    \u21B3 Extraction Successful.")
            else:
                print(f"    \u21B3 No files extracted.")
                
        except Exception as e:
            print(f"    \u26A0 Extraction Error: {e}")

        # 3. Routing Logic
        if "ELF" in file_type and "executable" in file_type:
            # It's a single binary, not a firmware image
            report["routing"]["decision"] = "PATH_C_BARE_METAL" # Or 'Direct Binary Analysis'
            report["routing"]["reason"] = "Input is a standalone ELF executable."
            
        elif report["extraction"]["was_extracted"]:
            # Check if it extracted a File System or just junk
            if self._is_linux_fs(report["extraction"]["extracted_path"]):
                report["routing"]["decision"] = "PATH_A_LINUX_FS"
                report["routing"]["reason"] = "Found Linux FS structure (/bin, /etc)."
            else:
                # Extracted something, but no OS structure -> Likely Bare Metal / RTOS blobs
                report["routing"]["decision"] = "PATH_C_BARE_METAL"
                report["routing"]["reason"] = "Extracted data, but no Linux FS found. Treating as Bare Metal/RTOS."
                
        else:
            # Extraction failed. Is it encrypted?
            # Heuristic: Binwalk failed + High Entropy (implied) usually means encrypted
            # In a real tool, we'd calculate entropy here. Assuming extraction failure on non-trivial file = Encrypted
            report["routing"]["decision"] = "PATH_B_HARD_TARGET"
            report["routing"]["reason"] = "Extraction failed. File may be Encrypted, Obfuscated, or Unsupported."

        report["status"] = "COMPLETE"
        print(f"[\u2713] Routing to: {report['routing']['decision']}")
        return report

# CLI Wrapper for testing
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python ingest.py <firmware_file>")
        sys.exit(1)
    
    module = IngestionModule()
    result = module.process(sys.argv[1])
    print(json.dumps(result, indent=4))
