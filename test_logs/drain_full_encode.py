#!/usr/bin/env python3
"""
Drain-based encoding WITH variable values for lossless compression.
"""
import sys
import struct
import time
import re
from collections import defaultdict
from drain3 import TemplateMiner
from drain3.template_miner_config import TemplateMinerConfig

def extract_variables(template, line):
    """Extract variable values from line given template with <*> placeholders"""
    # Convert template to regex
    pattern = re.escape(template)
    pattern = pattern.replace(r'\<\*\>', '(.*?)')
    pattern = '^' + pattern + '$'
    
    try:
        match = re.match(pattern, line)
        if match:
            return list(match.groups())
    except:
        pass
    return []

def encode_with_drain(lines):
    """Use Drain to discover templates and encode logs with variables"""
    
    config = TemplateMinerConfig()
    config.profiling_enabled = False
    
    miner = TemplateMiner(config=config)
    
    # First pass: build templates
    cluster_ids = []
    for line in lines:
        result = miner.add_log_message(line)
        cluster_ids.append(result["cluster_id"])
    
    # Get template mapping
    clusters = {c.cluster_id: c.get_template() for c in miner.drain.clusters}
    
    # Assign sequential IDs
    unique_clusters = sorted(set(cluster_ids))
    cluster_to_tid = {cid: i for i, cid in enumerate(unique_clusters)}
    templates = {cluster_to_tid[cid]: clusters[cid] for cid in unique_clusters}
    
    # Second pass: extract variables
    results = []
    all_variables = []
    
    for line, cid in zip(lines, cluster_ids):
        tid = cluster_to_tid[cid]
        template = templates[tid]
        variables = extract_variables(template, line)
        results.append(tid)
        all_variables.append(variables)
    
    return templates, results, all_variables

def write_encoded(output_file, templates, results, all_variables):
    """Write binary encoded format"""
    output = bytearray()
    
    # Template dictionary
    output.extend(struct.pack('<I', len(templates)))
    for tid in range(len(templates)):
        tmpl = templates.get(tid, "")
        tb = tmpl.encode('utf-8')
        output.extend(struct.pack('<H', len(tb)))
        output.extend(tb)
    
    # Template IDs
    output.extend(struct.pack('<I', len(results)))
    if len(templates) <= 256:
        output.extend(bytes(results))
    else:
        for tid in results:
            output.extend(struct.pack('<H', tid))
    
    # Group variables by position for better compression
    max_vars = max((len(v) for v in all_variables), default=0)
    
    output.extend(struct.pack('<I', max_vars))
    
    for pos in range(max_vars):
        # Collect all values at this position
        values = []
        for vars in all_variables:
            if pos < len(vars):
                values.append(vars[pos])
            else:
                values.append("")
        
        # Dictionary encode this column
        unique = list(dict.fromkeys(values))
        val_to_id = {v: i for i, v in enumerate(unique)}
        
        # Write dictionary
        output.extend(struct.pack('<I', len(unique)))
        for v in unique:
            vb = v.encode('utf-8', errors='replace')
            if len(vb) > 65535:
                vb = vb[:65535]
            output.extend(struct.pack('<H', len(vb)))
            output.extend(vb)
        
        # Write IDs
        if len(unique) <= 256:
            output.extend(bytes(val_to_id[v] for v in values))
        elif len(unique) <= 65536:
            for v in values:
                output.extend(struct.pack('<H', val_to_id[v]))
        else:
            for v in values:
                output.extend(struct.pack('<I', val_to_id[v]))
    
    with open(output_file, 'wb') as f:
        f.write(output)
    
    return len(output)

def main():
    input_file = sys.argv[1]
    
    with open(input_file, 'r', errors='replace') as f:
        lines = [l.rstrip('\n') for l in f]
    
    print(f"Lines: {len(lines)}")
    
    start = time.time()
    templates, results, all_variables = encode_with_drain(lines)
    encode_time = time.time() - start
    
    print(f"Encode time: {encode_time:.2f}s ({len(lines)/encode_time:.0f} lines/sec)")
    print(f"Unique templates: {len(templates)}")
    
    # Count variables
    total_vars = sum(len(v) for v in all_variables)
    print(f"Total variables: {total_vars}")
    
    output_file = f"{input_file}.drain_full"
    size = write_encoded(output_file, templates, results, all_variables)
    print(f"Encoded size: {size:,} bytes")

if __name__ == '__main__':
    main()
