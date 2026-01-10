#!/usr/bin/env python3
"""
Use Drain algorithm for automatic log template discovery and encoding.
Drain builds a parse tree to efficiently match log lines to templates.
"""
import sys
import struct
import time
from collections import defaultdict
from drain3 import TemplateMiner
from drain3.template_miner_config import TemplateMinerConfig

def encode_with_drain(lines):
    """Use Drain to discover templates and encode logs"""
    
    # Configure Drain
    config = TemplateMinerConfig()
    config.load("drain3.ini") if False else None  # Use defaults
    config.profiling_enabled = False
    
    miner = TemplateMiner(config=config)
    
    # Process all lines
    results = []
    template_to_id = {}
    
    start = time.time()
    for line in lines:
        result = miner.add_log_message(line)
        cluster_id = result["cluster_id"]
        
        if cluster_id not in template_to_id:
            template_to_id[cluster_id] = len(template_to_id)
        
        # Extract parameters (variables)
        params = result.get("template_mined", "").split("<*>")
        # The actual parameter values need to be extracted by comparing template to line
        results.append((template_to_id[cluster_id], result["cluster_id"]))
    
    parse_time = time.time() - start
    
    # Get all templates
    clusters = miner.drain.clusters
    templates = {template_to_id[c.cluster_id]: c.get_template() for c in clusters}
    
    return templates, results, parse_time, miner

def main():
    input_file = sys.argv[1]
    
    with open(input_file, 'r', errors='replace') as f:
        lines = [l.rstrip('\n') for l in f]
    
    print(f"Lines: {len(lines)}")
    
    templates, results, parse_time, miner = encode_with_drain(lines)
    
    print(f"Parse time: {parse_time:.2f}s ({len(lines)/parse_time:.0f} lines/sec)")
    print(f"Unique templates: {len(templates)}")
    
    # Show template distribution
    template_counts = defaultdict(int)
    for tid, _ in results:
        template_counts[tid] += 1
    
    top5 = sorted(template_counts.items(), key=lambda x: -x[1])[:5]
    coverage = sum(c for _, c in top5) / len(lines) * 100
    print(f"Top 5 templates cover: {coverage:.1f}% of lines")
    
    # Show sample templates
    print("\nSample templates:")
    for tid, count in top5[:3]:
        tmpl = templates[tid]
        if len(tmpl) > 80:
            tmpl = tmpl[:77] + "..."
        print(f"  [{count:6d}x] {tmpl}")
    
    # Encode to binary: [template_ids] + [template_dict]
    output = bytearray()
    
    # Template dictionary
    output.extend(struct.pack('<I', len(templates)))
    for tid in range(len(templates)):
        tmpl = templates.get(tid, "")
        tb = tmpl.encode('utf-8')
        output.extend(struct.pack('<H', len(tb)))
        output.extend(tb)
    
    # Template IDs per line
    output.extend(struct.pack('<I', len(results)))
    if len(templates) <= 256:
        output.extend(bytes(tid for tid, _ in results))
    elif len(templates) <= 65536:
        for tid, _ in results:
            output.extend(struct.pack('<H', tid))
    else:
        for tid, _ in results:
            output.extend(struct.pack('<I', tid))
    
    with open(f"{input_file}.drain", 'wb') as f:
        f.write(output)
    
    print(f"\nEncoded size: {len(output):,} bytes")

if __name__ == '__main__':
    main()
