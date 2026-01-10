#!/usr/bin/env python3
"""
Template-based encoding: discover log templates, encode as (template_id, variables).
This is closer to CLP's approach.
"""
import re
import sys
import struct
from collections import defaultdict

# Patterns to extract as variables
VAR_PATTERNS = [
    (r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?\b', 'IP'),      # IP addresses
    (r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b', 'UUID'),  # UUIDs
    (r'\bblk_-?\d+\b', 'BLK'),                                       # HDFS blocks
    (r'\b0x[0-9a-fA-F]+\b', 'HEX'),                                  # Hex numbers
    (r'\b\d{10,}\b', 'BIGINT'),                                      # Large integers (timestamps, IDs)
    (r'\b\d+\.\d+\b', 'FLOAT'),                                      # Floats
    (r'\b\d+\b', 'INT'),                                             # Integers
]

def extract_template(line):
    """Extract template and variables from a log line"""
    variables = []
    template = line
    
    for pattern, var_type in VAR_PATTERNS:
        def replace(m):
            variables.append((var_type, m.group(0)))
            return f'<{var_type}>'
        template = re.sub(pattern, replace, template, flags=re.I)
    
    return template, variables

def encode_logs(lines):
    """Encode logs as templates + variables"""
    template_dict = {}
    template_id = 0
    
    encoded_lines = []
    all_variables = []
    
    for line in lines:
        template, variables = extract_template(line)
        
        if template not in template_dict:
            template_dict[template] = template_id
            template_id += 1
        
        tid = template_dict[template]
        encoded_lines.append(tid)
        all_variables.append(variables)
    
    return template_dict, encoded_lines, all_variables

def write_binary(output_file, template_dict, encoded_lines, all_variables):
    """Write binary encoded format"""
    # Separate variable types for better compression
    var_streams = defaultdict(list)
    var_counts = []
    
    for vars in all_variables:
        var_counts.append(len(vars))
        for var_type, value in vars:
            var_streams[var_type].append(value)
    
    with open(output_file, 'wb') as f:
        # Write template dictionary
        templates = sorted(template_dict.items(), key=lambda x: x[1])
        f.write(struct.pack('<I', len(templates)))
        for tmpl, _ in templates:
            b = tmpl.encode('utf-8')
            f.write(struct.pack('<H', len(b)))
            f.write(b)
        
        # Write template IDs (use appropriate width)
        max_tid = len(templates)
        f.write(struct.pack('<I', len(encoded_lines)))
        if max_tid <= 256:
            f.write(b''.join(struct.pack('B', tid) for tid in encoded_lines))
        elif max_tid <= 65536:
            f.write(b''.join(struct.pack('<H', tid) for tid in encoded_lines))
        else:
            f.write(b''.join(struct.pack('<I', tid) for tid in encoded_lines))
        
        # Write variable counts per line
        f.write(b''.join(struct.pack('B', min(c, 255)) for c in var_counts))
        
        # Write each variable stream
        f.write(struct.pack('<I', len(var_streams)))
        for var_type, values in var_streams.items():
            type_b = var_type.encode('utf-8')
            f.write(struct.pack('B', len(type_b)))
            f.write(type_b)
            
            # Write values
            f.write(struct.pack('<I', len(values)))
            for v in values:
                vb = v.encode('utf-8')
                f.write(struct.pack('B', min(len(vb), 255)))
                f.write(vb[:255])

def main():
    input_file = sys.argv[1]
    
    with open(input_file, 'r', errors='replace') as f:
        lines = [l.rstrip('\n') for l in f]
    
    template_dict, encoded_lines, all_variables = encode_logs(lines)
    
    print(f"Lines: {len(lines)}")
    print(f"Unique templates: {len(template_dict)}")
    
    # Show top templates
    template_counts = defaultdict(int)
    for tid in encoded_lines:
        template_counts[tid] += 1
    
    top = sorted(template_counts.items(), key=lambda x: -x[1])[:5]
    print(f"Top templates cover: {sum(c for _, c in top) / len(lines) * 100:.1f}% of lines")
    
    output_file = f"{input_file}.tmpl"
    write_binary(output_file, template_dict, encoded_lines, all_variables)
    
    print(f"Output size: {os.path.getsize(output_file):,} bytes")

import os
if __name__ == '__main__':
    main()
