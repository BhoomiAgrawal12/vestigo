import os
import subprocess
import argparse
import sys

# Configuration Matrix
ARCHITECTURES = {
    "x86_64": {
        "gcc": "gcc",
        "clang": "clang",
        "flags": []
    },
    "arm": {
        "gcc": "arm-linux-gnueabihf-gcc",
        "clang": "clang --target=arm-linux-gnueabihf",
        "flags": ["-static"] # Static linking for easier analysis/running
    },
    "mips": {
        "gcc": "mips-linux-gnu-gcc",
        "clang": "clang --target=mips-linux-gnu",
        "flags": ["-static"]
    },
    "riscv": {
        "gcc": "riscv64-linux-gnu-gcc",
        "clang": "clang --target=riscv64-linux-gnu",
        "flags": ["-static"]
    },
    "avr": {
        "gcc": "avr-gcc",
        "clang": "clang --target=avr",
        "flags": ["-mmcu=atmega328p"]
    }
}

COMPILERS = ["gcc", "clang"]
OPTIMIZATIONS = ["-O0", "-O1", "-O2", "-O3", "-Os"]

IMAGE_NAME = "permutation-factory"

def run_command(cmd):
    """Runs a shell command and prints output."""
    try:
        subprocess.check_call(cmd)
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {' '.join(cmd)}\n{e}")
        return False

def build_docker_image():
    print(f"Building Docker image '{IMAGE_NAME}'...")
    return run_command(["docker", "build", "-t", IMAGE_NAME, "."])

def build_matrix(source_file, output_dir):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Ensure source file path is absolute or relative to CWD for mounting
    abs_source = os.path.abspath(source_file)
    cwd = os.getcwd()
    
    if not abs_source.startswith(cwd):
        print(f"Error: Source file {source_file} must be within the current working directory {cwd} for Docker mounting.")
        return

    rel_source = os.path.relpath(abs_source, cwd)
    source_name = os.path.splitext(os.path.basename(source_file))[0]

    print(f"Starting build matrix for {rel_source}...")

    success_count = 0
    total_count = 0

    for arch, arch_config in ARCHITECTURES.items():
        for compiler in COMPILERS:
            for opt in OPTIMIZATIONS:
                total_count += 1
                
                compiler_bin = arch_config[compiler]
                output_filename = f"{source_name}_{arch}_{compiler}_{opt.replace('-', '')}.elf"
                # Output path inside the container
                container_output_path = os.path.join(output_dir, output_filename)
                
                # Construct the compiler command to run INSIDE the container
                # We map CWD to /app, so paths are relative to /app
                build_cmd = compiler_bin.split() + arch_config["flags"] + [opt, "-o", container_output_path, rel_source]
                
                print(f"[{success_count+1}/{total_count}] Building {output_filename} ({arch}, {compiler}, {opt})...")
                
                # Docker run command
                docker_cmd = [
                    "docker", "run", "--rm",
                    "-v", f"{cwd}:/app",
                    "-w", "/app",
                    IMAGE_NAME
                ] + build_cmd

                if run_command(docker_cmd):
                    success_count += 1
                else:
                    print(f"Failed to build {output_filename}")

    print(f"\nBuild complete. {success_count}/{total_count} binaries generated in '{output_dir}'.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Permutation Factory Builder")
    parser.add_argument("--source", required=True, help="Source C file (must be in current directory or subdir)")
    parser.add_argument("--output", default="bin", help="Output directory (relative to current directory)")
    parser.add_argument("--build-image", action="store_true", help="Build the Docker image before running")
    
    args = parser.parse_args()

    if args.build_image:
        if not build_docker_image():
            sys.exit(1)

    build_matrix(args.source, args.output)
