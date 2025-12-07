#!/usr/bin/env python3
"""
Script to convert JSON files from ghidra_json_new folder to CSV format.
Extracts features for each function and uses the label field from JSON directly.
"""

import json
import csv
import os
from pathlib import Path
import re


def extract_architecture_from_filename(filename):
    """
    Extract architecture from filename.
    Supported architectures: arm32, arm64, mips, riscv, x86, avr
    """
    filename_lower = filename.lower()
    
    architectures = ['arm32', 'arm64', 'mips', 'riscv', 'x86', 'avr']
    
    for arch in architectures:
        if arch in filename_lower:
            return arch
    
    return 'unknown'


def extract_algorithm_from_filename(filename):
    """
    Extract algorithm/library name from filename.
    Examples: mbedtls, openssl, wolfssl, etc.
    """
    # Remove file extension
    name = filename.replace('_features.json', '').replace('.o_features.json', '')
    
    # Remove architecture and optimization level
    architectures = ['arm32', 'arm64', 'mips', 'riscv', 'x86', 'avr']
    optimizations = ['_O0', '_O1', '_O2', '_O3', '_Os']
    
    for arch in architectures:
        name = name.replace('_' + arch, '').replace(arch + '_', '')
    
    for opt in optimizations:
        name = name.replace(opt, '')
    
    # Clean up any trailing/leading underscores
    name = name.strip('_')
    
    return name if name else 'unknown'


def extract_optimization_from_filename(filename):
    """
    Extract optimization level from filename.
    Examples: O0, O1, O2, O3, Os
    """
    match = re.search(r'_O([0-3s])', filename, re.IGNORECASE)
    if match:
        return 'O' + match.group(1)
    return 'unknown'


def extract_compiler_from_filename(filename):
    """
    Extract compiler from filename if present, otherwise default to 'gcc'
    """
    if 'clang' in filename.lower():
        return 'clang'
    elif 'gcc' in filename.lower():
        return 'gcc'
    return 'gcc'  # default


def process_function(function_data, metadata):
    """
    Extract all required features from a single function.
    Returns a dictionary with all feature values.
    """
    features = {}
    
    # Graph-level features
    graph = function_data.get('graph_level', {})
    features['num_basic_blocks'] = graph.get('num_basic_blocks', 0)
    features['num_edges'] = graph.get('num_edges', 0)
    features['cyclomatic_complexity'] = graph.get('cyclomatic_complexity', 0)
    features['loop_count'] = graph.get('loop_count', 0)
    features['loop_depth'] = graph.get('loop_depth', 0)
    features['branch_density'] = graph.get('branch_density', 0)
    features['average_block_size'] = graph.get('average_block_size', 0)
    features['num_entry_exit_paths'] = graph.get('num_entry_exit_paths', 0)
    features['strongly_connected_components'] = graph.get('strongly_connected_components', 0)
    
    # Edge-level aggregations
    features['num_conditional_edges'] = graph.get('num_conditional_edges', 0)
    features['num_unconditional_edges'] = graph.get('num_unconditional_edges', 0)
    features['num_loop_edges'] = graph.get('num_loop_edges', 0)
    features['avg_edge_branch_condition_complexplexity'] = graph.get('avg_edge_branch_condition_complexity', 0)
    
    # Node-level aggregated features
    node_list = function_data.get('node_level', [])
    if node_list:
        # Aggregate node features
        total_instruction_count = sum(node.get('instruction_count', 0) for node in node_list)
        total_crypto_hits = sum(node.get('crypto_constant_hits', 0) for node in node_list)
        total_bitwise_density = sum(node.get('bitwise_op_density', 0) for node in node_list)
        total_immediate_entropy = sum(node.get('immediate_entropy', 0) for node in node_list)
        
        # Check for table lookup presence (any node has it)
        table_lookup = any(node.get('table_lookup_presence', False) for node in node_list)
        
        # Average values
        num_nodes = len(node_list)
        features['instruction_count'] = total_instruction_count
        features['immediate_entropy'] = total_immediate_entropy / num_nodes if num_nodes > 0 else 0
        features['bitwise_op_density'] = total_bitwise_density / num_nodes if num_nodes > 0 else 0
        features['table_lookup_presence'] = 1 if table_lookup else 0
        features['crypto_constant_hits'] = total_crypto_hits
        
        # Branch condition complexity (from edges, not nodes)
        edges = function_data.get('edge_level', [])
        if edges:
            total_complexity = sum(edge.get('branch_condition_complexity', 0) for edge in edges)
            features['branch_condition_complexity'] = total_complexity / len(edges) if edges else 0
        else:
            features['branch_condition_complexity'] = 0
    else:
        features['instruction_count'] = 0
        features['immediate_entropy'] = 0
        features['bitwise_op_density'] = 0
        features['table_lookup_presence'] = 0
        features['crypto_constant_hits'] = 0
        features['branch_condition_complexity'] = 0
    
    # Operation category counts
    op_counts = function_data.get('op_category_counts', {})
    features['add_ratio'] = op_counts.get('add_ratio', 0)
    features['logical_ratio'] = op_counts.get('logical_ratio', 0)
    features['load_store_ratio'] = op_counts.get('load_store_ratio', 0)
    features['xor_ratio'] = op_counts.get('xor_ratio', 0)
    features['multiply_ratio'] = op_counts.get('multiply_ratio', 0)
    features['rotate_ratio'] = op_counts.get('rotate_ratio', 0)
    features['bitwise_ops'] = op_counts.get('bitwise_ops', 0)
    features['crypto_like_ops'] = op_counts.get('crypto_like_ops', 0)
    features['arithmetic_ops'] = op_counts.get('arithmetic_ops', 0)
    features['mem_ops_ratio'] = op_counts.get('mem_ops_ratio', 0)
    
    # Advanced features
    adv = function_data.get('advanced_features', {})
    features['has_aes_sbox'] = 1 if adv.get('has_aes_sbox', False) else 0
    features['rsa_bigint_detected'] = 1 if adv.get('bigint_op_count', 0) > 0 else 0
    features['has_aes_rcon'] = 1 if adv.get('has_aes_rcon', False) else 0
    
    # SHA constants detection
    sha_k_hits = adv.get('sha_k_table_hits', 0)
    sha_init_hits = adv.get('sha_init_constants_hits', 0)
    features['has_sha_constants'] = 1 if (sha_k_hits > 0 or sha_init_hits > 0) else 0
    
    features['rodata_refs_count'] = adv.get('rodata_refs_count', 0)
    features['string_refs_count'] = adv.get('string_refs_count', 0)
    features['stack_frame_size'] = adv.get('stack_frame_size', 0)
    
    # Entropy metrics
    entropy = function_data.get('entropy_metrics', {})
    features['function_byte_entropy'] = entropy.get('function_byte_entropy', 0)
    features['opcode_entropy'] = entropy.get('opcode_entropy', 0)
    features['cyclomatic_complexity_density'] = entropy.get('cyclomatic_complexity_density', 0)
    
    # Instruction sequence
    instr_seq = function_data.get('instruction_sequence', {})
    features['unique_ngram_count'] = instr_seq.get('unique_ngram_count', 0)
    
    # Function metadata
    features['function_name'] = function_data.get('name', 'unknown')
    features['function_address'] = function_data.get('address', '0')
    
    # Use label directly from JSON
    features['label'] = function_data.get('label', 'Unknown')
    
    return features


def convert_json_to_csv(json_dir, output_csv):
    """
    Convert all JSON files in json_dir to a single CSV file.
    """
    # Define CSV columns in the required order
    csv_columns = [
        'architecture',
        'algorithm',
        'compiler',
        'optimization',
        'filename',
        'function_name',
        'function_address',
        'label',
        'num_basic_blocks',
        'num_edges',
        'cyclomatic_complexity',
        'loop_count',
        'loop_depth',
        'branch_density',
        'average_block_size',
        'num_entry_exit_paths',
        'strongly_connected_components',
        'instruction_count',
        'immediate_entropy',
        'bitwise_op_density',
        'table_lookup_presence',
        'crypto_constant_hits',
        'branch_condition_complexity',
        'add_ratio',
        'logical_ratio',
        'load_store_ratio',
        'xor_ratio',
        'multiply_ratio',
        'rotate_ratio',
        'num_conditional_edges',
        'num_unconditional_edges',
        'num_loop_edges',
        'avg_edge_branch_condition_complexplexity',
        'has_aes_sbox',
        'rsa_bigint_detected',
        'has_aes_rcon',
        'has_sha_constants',
        'rodata_refs_count',
        'string_refs_count',
        'stack_frame_size',
        'bitwise_ops',
        'crypto_like_ops',
        'arithmetic_ops',
        'mem_ops_ratio',
        'function_byte_entropy',
        'opcode_entropy',
        'cyclomatic_complexity_density',
        'unique_ngram_count'
    ]
    
    # Collect JSON files from main directory and negative subdirectory
    json_files = []
    
    # Get files from main directory
    json_files.extend(list(Path(json_dir).glob('*.json')))
    
    # Get files from negative subdirectory
    negative_dir = Path(json_dir) / 'negative'
    if negative_dir.exists():
        json_files.extend(list(negative_dir.glob('*.json')))
        print(f"Including negative samples from {negative_dir}/")
    
    if not json_files:
        print(f"No JSON files found in {json_dir}")
        return
    
    print(f"Found {len(json_files)} JSON files to process")
    
    all_rows = []
    
    for json_file in json_files:
        print(f"Processing {json_file.name}...")
        
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Extract metadata from filename
            filename = json_file.name
            architecture = extract_architecture_from_filename(filename)
            algorithm = extract_algorithm_from_filename(filename)
            compiler = extract_compiler_from_filename(filename)
            optimization = extract_optimization_from_filename(filename)
            
            # Process each function
            functions = data.get('functions', [])
            metadata = data.get('metadata', {})
            
            for func in functions:
                features = process_function(func, metadata)
                
                # Add file-level metadata
                features['architecture'] = architecture
                features['algorithm'] = algorithm
                features['compiler'] = compiler
                features['optimization'] = optimization
                features['filename'] = filename
                
                # Create row in correct column order
                row = {col: features.get(col, '') for col in csv_columns}
                all_rows.append(row)
            
            print(f"  Extracted {len(functions)} functions")
            
        except Exception as e:
            print(f"Error processing {json_file.name}: {e}")
            continue
    
    # Write to CSV
    print(f"\nWriting {len(all_rows)} rows to {output_csv}...")
    
    with open(output_csv, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=csv_columns)
        writer.writeheader()
        writer.writerows(all_rows)
    
    print(f"✓ Successfully created {output_csv} with {len(all_rows)} function entries")


def main():
    # Paths
    script_dir = Path(__file__).parent
    json_dir = script_dir / 'filtered_json'
    output_csv = script_dir / 'filtered_json_features.csv'
    
    # Check if json directory exists
    if not json_dir.exists():
        print(f"Error: Directory {json_dir} does not exist")
        return
    
    # Convert
    convert_json_to_csv(json_dir, output_csv)


if __name__ == '__main__':
    main()
