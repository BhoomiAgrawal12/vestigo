import sys
import json
import os

# Import your modules
from ingest import IngestionModule
from fs_scan import AdvancedLinuxAnalyzer

# --- Placeholder Classes for Future Modules ---
# We will implement these one by one later.
# LinuxFSAnalyzer is now imported from fs_scan.py

class BareMetalAnalyzer:
    def analyze(self, binary_path):
        print(f"[\u2699\ufe0f] Module 3: Running ML & Ghidra on {binary_path}...")
        # Real logic goes here (Yara, Floss, Ghidra)
        return {"module": "Bare_Metal_ML", "findings": ["AES S-Box Detected", "High Entropy Code"]}

class HardTargetAnalyzer:
    def analyze(self, file_path):
        print(f"[\u2699\ufe0f] Module 4: Analyzing Encrypted/Hard Target {file_path}...")
        # Real logic goes here (Entropy, Bootloader grep)
        return {"module": "Hard_Target", "findings": ["Entropy=0.99", "Secure Boot Signature found"]}

# --- The Orchestrator ---
def main():
    if len(sys.argv) < 2:
        print("Usage: python main.py <firmware_file>")
        sys.exit(1)

    target_file = sys.argv[1]
    
    # 1. Initialize & Run Module 1 (Ingestion)
    ingestor = IngestionModule()
    ingestion_report = ingestor.process(target_file)
    
    # 2. Check Routing Decision
    route = ingestion_report["routing"]["decision"]
    extracted_path = ingestion_report["extraction"].get("extracted_path")
    
    final_analysis = {}

    # 3. Dispatch to Specific Modules
    if route == "PATH_A_LINUX_FS":
        print("\n[+] Routing to Path A: Linux/FS Analyzer")
        analyzer = AdvancedLinuxAnalyzer()
        # We pass the folder where binwalk dumped the files
        final_analysis = analyzer.analyze(extracted_path)

    elif route == "PATH_C_BARE_METAL":
        print("\n[+] Routing to Path C: Bare Metal / ML Engine")
        analyzer = BareMetalAnalyzer()
        
        # For bare metal, we might need to find the largest .bin file in the extraction
        # Or pass the original file if extraction was partial.
        # For now, we pass the extraction root.
        final_analysis = analyzer.analyze(extracted_path)

    elif route == "PATH_B_HARD_TARGET":
        print("\n[+] Routing to Path B: Hard Target Analyzer")
        analyzer = HardTargetAnalyzer()
        # Hard targets usually failed extraction, so we pass the ORIGINAL file
        final_analysis = analyzer.analyze(target_file)

    else:
        print("\n[!] Unknown Route. Manual analysis required.")

    # 4. Merge & Save Report
    full_report = {
        "ingestion": ingestion_report,
        "analysis": final_analysis
    }
    
    output_filename = f"report_{os.path.basename(target_file)}.json"
    with open(output_filename, "w") as f:
        json.dump(full_report, f, indent=4)
        
    print(f"\n[\u2705] Full Analysis Complete. Report saved to {output_filename}")

if __name__ == "__main__":
    main()
