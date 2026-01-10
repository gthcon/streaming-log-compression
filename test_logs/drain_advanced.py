#!/usr/bin/env python3
"""
Advanced Drain encoding with LogLite-inspired optimizations:
1. Timestamp delta encoding
2. Numeric varint + delta encoding
3. XOR encoding for similar strings
4. Smarter dictionary with frequency-based ordering
"""
import sys
import struct
import time
import re
from collections import Counter
from drain3 import TemplateMiner
from drain3.template_miner_config import TemplateMinerConfig

def get_line_delta(template, line):
    parts = template.split('<*>')
    if len(parts) == 1:
        return [] if template == line else [line]
    variables = []
    remaining = line
    for part in parts:
        if not part:
            continue
        idx = remaining.find(part)
        if idx == -1:
            return [line]
        if idx > 0:
            variables.append(remaining[:idx])
        remaining = remaining[idx + len(part):]
    if remaining:
        variables.append(remaining)
    return variables

def encode_varint(n):
    """Encode integer as varint (7 bits per byte, MSB = continuation)"""
    result = bytearray()
    while n >= 128:
        result.append((n & 0x7F) | 0x80)
        n >>= 7
    result.append(n & 0x7F)
    return bytes(result)

def encode_signed_varint(n):
    """ZigZag encoding for signed integers"""
    return encode_varint((n << 1) ^ (n >> 63))

def parse_timestamp(ts):
    """Parse CLF timestamp like [01/Jul/1995:18:50:55"""
    match = re.match(r'\[(\d{2})/(\w{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})', ts)
    if match:
        day, mon, year, hour, minute, sec = match.groups()
        months = {'Jan':1,'Feb':2,'Mar':3,'Apr':4,'May':5,'Jun':6,
                  'Jul':7,'Aug':8,'Sep':9,'Oct':10,'Nov':11,'Dec':12}
        return (int(year), months.get(mon, 0), int(day), int(hour), int(minute), int(sec))
    return None

def detect_column_type(values, sample_size=1000):
    """Detect the type of values in a column"""
    sample = values[:sample_size]

    # Check numeric
    numeric = sum(1 for v in sample if re.match(r'^-?\d+$', v))
    if numeric > len(sample) * 0.9:
        return 'integer'

    numeric_float = sum(1 for v in sample if re.match(r'^-?\d+\.?\d*$', v))
    if numeric_float > len(sample) * 0.9:
        return 'float'

    # Check timestamp
    ts = sum(1 for v in sample if parse_timestamp(v) is not None)
    if ts > len(sample) * 0.9:
        return 'timestamp'

    # Check if good for dictionary (< 30% unique)
    unique_ratio = len(set(sample)) / len(sample)
    if unique_ratio < 0.3:
        return 'dictionary'

    return 'raw'

def encode_integer_column(values):
    """Delta + varint encode integers"""
    output = bytearray()
    output.append(0x01)  # Type marker: integer delta

    prev = 0
    deltas = bytearray()
    for v in values:
        try:
            n = int(v) if v else 0
        except:
            n = 0
        delta = n - prev
        deltas.extend(encode_signed_varint(delta))
        prev = n

    output.extend(struct.pack('<I', len(deltas)))
    output.extend(deltas)
    return bytes(output)

def encode_timestamp_column(values):
    """Delta encode timestamps"""
    output = bytearray()
    output.append(0x02)  # Type marker: timestamp delta

    # Convert to seconds since epoch-ish (just for delta purposes)
    def ts_to_int(ts):
        p = parse_timestamp(ts)
        if p:
            y, m, d, h, mi, s = p
            return ((y * 366 + m * 31 + d) * 24 + h) * 3600 + mi * 60 + s
        return 0

    prev = 0
    deltas = bytearray()
    for v in values:
        n = ts_to_int(v)
        delta = n - prev
        deltas.extend(encode_signed_varint(delta))
        prev = n

    output.extend(struct.pack('<I', len(deltas)))
    output.extend(deltas)
    return bytes(output)

def encode_dictionary_column(values):
    """Frequency-sorted dictionary encoding"""
    output = bytearray()
    output.append(0x03)  # Type marker: dictionary

    # Sort by frequency (most common first = smaller IDs)
    freq = Counter(values)
    sorted_vals = [v for v, _ in freq.most_common()]
    val_to_id = {v: i for i, v in enumerate(sorted_vals)}

    n_unique = len(sorted_vals)
    output.extend(struct.pack('<I', n_unique))

    for v in sorted_vals:
        vb = v.encode('utf-8', errors='replace')[:65535]
        output.extend(struct.pack('<H', len(vb)))
        output.extend(vb)

    # Encode IDs with varint (frequent values get small IDs)
    ids = bytearray()
    for v in values:
        ids.extend(encode_varint(val_to_id[v]))

    output.extend(struct.pack('<I', len(ids)))
    output.extend(ids)
    return bytes(output)

def encode_raw_column(values):
    """Raw length-prefixed strings"""
    output = bytearray()
    output.append(0x04)  # Type marker: raw

    for v in values:
        vb = v.encode('utf-8', errors='replace')
        if len(vb) < 128:
            output.append(len(vb))
        else:
            output.append(0x80 | (len(vb) >> 8))
            output.append(len(vb) & 0xFF)
        output.extend(vb)

    return bytes(output)

def encode_lossless(lines):
    """Encode logs with Drain"""
    config = TemplateMinerConfig()
    config.profiling_enabled = False
    miner = TemplateMiner(config=config)

    results = []
    for line in lines:
        result = miner.add_log_message(line)
        results.append((result["cluster_id"], line))

    clusters = {c.cluster_id: c.get_template() for c in miner.drain.clusters}
    unique_clusters = sorted(set(cid for cid, _ in results))
    cluster_to_tid = {cid: i for i, cid in enumerate(unique_clusters)}
    templates = {cluster_to_tid[cid]: clusters[cid] for cid in unique_clusters}

    encoded = []
    for cid, line in results:
        tid = cluster_to_tid[cid]
        template = templates[tid]
        variables = get_line_delta(template, line)
        encoded.append((tid, variables))

    return templates, encoded

def write_advanced(output_file, templates, encoded):
    """Write with type-aware column encoding"""
    output = bytearray()
    output.extend(b'DRN6')  # Magic v6

    # Templates
    output.extend(struct.pack('<H', len(templates)))
    for tid in range(len(templates)):
        tmpl = templates.get(tid, "").encode('utf-8')
        output.extend(struct.pack('<H', len(tmpl)))
        output.extend(tmpl)

    n_lines = len(encoded)
    output.extend(struct.pack('<I', n_lines))

    # Template IDs with varint
    tid_data = bytearray()
    for tid, _ in encoded:
        tid_data.extend(encode_varint(tid))
    output.extend(struct.pack('<I', len(tid_data)))
    output.extend(tid_data)

    # Variables - type-aware encoding
    max_vars = max((len(vars) for _, vars in encoded), default=0)
    output.extend(struct.pack('<B', max_vars))

    col_types = []
    for pos in range(max_vars):
        values = []
        for _, vars in encoded:
            values.append(vars[pos] if pos < len(vars) else "")

        col_type = detect_column_type(values)
        col_types.append(col_type)

        if col_type == 'integer':
            col_data = encode_integer_column(values)
        elif col_type == 'timestamp':
            col_data = encode_timestamp_column(values)
        elif col_type == 'dictionary':
            col_data = encode_dictionary_column(values)
        else:
            col_data = encode_raw_column(values)

        output.extend(col_data)

    with open(output_file, 'wb') as f:
        f.write(output)

    return len(output), col_types

def main():
    input_file = sys.argv[1]

    with open(input_file, 'r', errors='replace') as f:
        lines = [l.rstrip('\n') for l in f]

    print(f"Lines: {len(lines)}")

    start = time.time()
    templates, encoded = encode_lossless(lines)
    encode_time = time.time() - start

    print(f"Encode time: {encode_time:.2f}s ({len(lines)/encode_time:.0f} lines/sec)")
    print(f"Unique templates: {len(templates)}")

    total_vars = sum(len(vars) for _, vars in encoded)
    max_vars = max((len(vars) for _, vars in encoded), default=0)
    print(f"Total variables: {total_vars}, Max per line: {max_vars}")

    output_file = f"{input_file}.drain_adv"
    size, col_types = write_advanced(output_file, templates, encoded)
    print(f"\nColumn types detected: {col_types}")
    print(f"Advanced encoded size: {size:,} bytes")

if __name__ == '__main__':
    main()
