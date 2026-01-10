#!/usr/bin/env python3
"""
Test if simple preprocessing improves Zstd compression.
Approaches:
1. Template extraction - replace variables with placeholders
2. Binary encoding - pack common patterns
3. Column reordering - group similar data together
"""

import re
import sys
import struct
from collections import defaultdict

def extract_templates_simple(lines):
    """Replace numbers, IPs, hex, UUIDs with placeholders"""
    result = []
    variables = []
    
    for line in lines:
        vars_this_line = []
        
        # Replace IP addresses
        line = re.sub(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:\d+)?\b', 
                      lambda m: (vars_this_line.append(m.group(0)), '\x01')[1], line)
        
        # Replace UUIDs
        line = re.sub(r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b',
                      lambda m: (vars_this_line.append(m.group(0)), '\x02')[1], line, flags=re.I)
        
        # Replace hex strings (8+ chars)
        line = re.sub(r'\b0x[0-9a-fA-F]{4,}\b|\b[0-9a-fA-F]{8,}\b',
                      lambda m: (vars_this_line.append(m.group(0)), '\x03')[1], line)
        
        # Replace large numbers (likely IDs, sizes, timestamps)
        line = re.sub(r'\b\d{6,}\b',
                      lambda m: (vars_this_line.append(m.group(0)), '\x04')[1], line)
        
        # Replace smaller numbers
        line = re.sub(r'\b\d+\b',
                      lambda m: (vars_this_line.append(m.group(0)), '\x05')[1], line)
        
        result.append(line)
        variables.append(vars_this_line)
    
    return result, variables

def encode_templates_binary(templates, variables):
    """Encode templates + variables in binary format"""
    # Build template dictionary
    template_dict = {}
    template_id = 0
    
    output = bytearray()
    
    for tmpl, vars in zip(templates, variables):
        if tmpl not in template_dict:
            template_dict[tmpl] = template_id
            template_id += 1
        
        tid = template_dict[tmpl]
        
        # Write: [2-byte template ID] [1-byte var count] [vars...]
        output.extend(struct.pack('<H', tid))
        output.append(len(vars))
        for v in vars:
            v_bytes = v.encode('utf-8')
            output.append(len(v_bytes))
            output.extend(v_bytes)
    
    # Prepend template dictionary
    header = bytearray()
    header.extend(struct.pack('<I', len(template_dict)))
    for tmpl, tid in sorted(template_dict.items(), key=lambda x: x[1]):
        t_bytes = tmpl.encode('utf-8')
        header.extend(struct.pack('<H', len(t_bytes)))
        header.extend(t_bytes)
    
    return bytes(header + output)

def main():
    input_file = sys.argv[1]
    
    with open(input_file, 'r', errors='replace') as f:
        lines = [l.rstrip('\n') for l in f]
    
    # Method 1: Just templates (text)
    templates, variables = extract_templates_simple(lines)
    with open(input_file + '.templates', 'w') as f:
        f.write('\n'.join(templates))
    with open(input_file + '.variables', 'w') as f:
        for vars in variables:
            f.write('\t'.join(vars) + '\n')
    
    # Method 2: Binary encoding
    binary_data = encode_templates_binary(templates, variables)
    with open(input_file + '.binary', 'wb') as f:
        f.write(binary_data)
    
    print(f"Original lines: {len(lines)}")
    print(f"Unique templates: {len(set(templates))}")
    print(f"Template file size: {len(''.join(templates))}")
    print(f"Binary file size: {len(binary_data)}")

if __name__ == '__main__':
    main()
