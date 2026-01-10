#!/usr/bin/env python3
"""
Generic columnar encoding - works on any log format.
Splits on whitespace and common delimiters, encodes each "column" separately.
"""
import re
import sys
import struct

def tokenize(line):
    """Split line into tokens, preserving structure"""
    # Split on whitespace and common delimiters, keep delimiters
    tokens = re.split(r'(\s+|[,;:=\[\]{}()"<>])', line)
    return [t for t in tokens if t]

def encode_column_dict(values):
    """Dictionary encode with variable-width IDs"""
    unique = list(dict.fromkeys(values))
    val_to_id = {v: i for i, v in enumerate(unique)}
    
    dict_bytes = bytearray()
    dict_bytes.extend(struct.pack('<I', len(unique)))
    for v in unique:
        b = v.encode('utf-8', errors='replace')
        if len(b) > 65535:
            b = b[:65535]
        dict_bytes.extend(struct.pack('<H', len(b)))
        dict_bytes.extend(b)
    
    # Choose ID width
    if len(unique) <= 256:
        id_bytes = bytes(val_to_id[v] for v in values)
    elif len(unique) <= 65536:
        id_bytes = b''.join(struct.pack('<H', val_to_id[v]) for v in values)
    else:
        id_bytes = b''.join(struct.pack('<I', val_to_id[v]) for v in values)
    
    return bytes(dict_bytes), id_bytes

def main():
    input_file = sys.argv[1]
    max_cols = 50  # Limit columns to avoid explosion
    
    with open(input_file, 'r', errors='replace') as f:
        lines = [l.rstrip('\n') for l in f]
    
    # Tokenize all lines
    tokenized = [tokenize(line) for line in lines]
    
    # Find max tokens
    max_tokens = max(len(t) for t in tokenized)
    max_tokens = min(max_tokens, max_cols)
    
    print(f"Lines: {len(lines)}, Max tokens: {max_tokens}")
    
    # Pad/truncate to same length
    for t in tokenized:
        while len(t) < max_tokens:
            t.append('')
        del t[max_tokens:]
    
    # Transpose to columns
    columns = []
    for i in range(max_tokens):
        col = [t[i] for t in tokenized]
        columns.append(col)
    
    # Encode each column
    total_size = 0
    encoded_parts = []
    
    for i, col in enumerate(columns):
        unique = len(set(col))
        dict_bytes, data_bytes = encode_column_dict(col)
        encoded_parts.append((dict_bytes, data_bytes))
        total_size += len(dict_bytes) + len(data_bytes)
        if unique < 100:
            print(f"  Col {i}: {unique} unique values")
    
    # Write output
    with open(f"{input_file}.gcol", 'wb') as f:
        f.write(struct.pack('<I', len(columns)))
        for dict_bytes, data_bytes in encoded_parts:
            f.write(struct.pack('<I', len(dict_bytes)))
            f.write(dict_bytes)
            f.write(struct.pack('<I', len(data_bytes)))
            f.write(data_bytes)
    
    print(f"Total encoded size: {total_size:,} bytes")

if __name__ == '__main__':
    main()
