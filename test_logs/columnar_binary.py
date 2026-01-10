#!/usr/bin/env python3
"""
Binary columnar encoding with dictionary compression for repeated values.
"""
import re
import sys
import struct

CLF_PATTERN = re.compile(
    r'^(\S+)\s+(\S+)\s+(\S+)\s+\[([^\]]+)\]\s+"([^"]*)"\s+(\d+)\s+(\S+)'
)

def encode_column_dict(values):
    """Dictionary encode a column - returns (dict_bytes, data_bytes)"""
    unique = list(dict.fromkeys(values))  # Preserve order, dedupe
    val_to_id = {v: i for i, v in enumerate(unique)}
    
    # Dictionary: [4-byte count] [entries: 2-byte len, bytes]
    dict_bytes = bytearray()
    dict_bytes.extend(struct.pack('<I', len(unique)))
    for v in unique:
        b = v.encode('utf-8')
        dict_bytes.extend(struct.pack('<H', len(b)))
        dict_bytes.extend(b)
    
    # Data: variable-width IDs based on dict size
    if len(unique) <= 256:
        fmt = 'B'
    elif len(unique) <= 65536:
        fmt = '<H'
    else:
        fmt = '<I'
    
    data_bytes = bytearray()
    for v in values:
        data_bytes.extend(struct.pack(fmt, val_to_id[v]))
    
    return bytes(dict_bytes), bytes(data_bytes)

def encode_ints(values):
    """Delta encode integers"""
    ints = []
    for v in values:
        try:
            ints.append(int(v))
        except:
            ints.append(0)
    
    # Delta encode
    deltas = [ints[0]] if ints else []
    for i in range(1, len(ints)):
        deltas.append(ints[i] - ints[i-1])
    
    # Varint encode
    result = bytearray()
    for d in deltas:
        # Zigzag encode for signed
        d = (d << 1) ^ (d >> 63)
        while d >= 0x80:
            result.append((d & 0x7f) | 0x80)
            d >>= 7
        result.append(d)
    
    return bytes(result)

def main():
    input_file = sys.argv[1]
    
    with open(input_file, 'r', errors='replace') as f:
        lines = [l.rstrip('\n') for l in f]
    
    ips, timestamps, methods, paths, statuses, sizes = [], [], [], [], [], []
    
    for line in lines:
        m = CLF_PATTERN.match(line)
        if m:
            ip, ident, user, ts, request, status, size = m.groups()
            ips.append(ip)
            timestamps.append(ts)
            parts = request.split(' ', 2)
            methods.append(parts[0] if parts else '')
            paths.append(parts[1] if len(parts) > 1 else '')
            statuses.append(status)
            sizes.append(size)
    
    print(f"Parsed {len(ips)} lines")
    print(f"Unique IPs: {len(set(ips))}")
    print(f"Unique methods: {len(set(methods))}")
    print(f"Unique paths: {len(set(paths))}")
    print(f"Unique statuses: {len(set(statuses))}")
    
    # Encode columns
    ip_dict, ip_data = encode_column_dict(ips)
    method_dict, method_data = encode_column_dict(methods)
    path_dict, path_data = encode_column_dict(paths)
    status_dict, status_data = encode_column_dict(statuses)
    ts_dict, ts_data = encode_column_dict(timestamps)
    size_data = encode_ints(sizes)
    
    # Write binary format
    with open(f"{input_file}.binary2", 'wb') as f:
        for data in [ip_dict, ip_data, method_dict, method_data, 
                     path_dict, path_data, status_dict, status_data,
                     ts_dict, ts_data, size_data]:
            f.write(struct.pack('<I', len(data)))
            f.write(data)
    
    total = sum(len(d) for d in [ip_dict, ip_data, method_dict, method_data,
                                  path_dict, path_data, status_dict, status_data,
                                  ts_dict, ts_data, size_data])
    print(f"Binary size: {total:,} bytes")

if __name__ == '__main__':
    main()
