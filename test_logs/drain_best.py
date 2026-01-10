#!/usr/bin/env python3
"""
Best combined Drain encoding:
1. Dictionary for low-cardinality string columns
2. Delta + varint for numeric columns (compresses better with zstd)
3. Timestamp conversion to delta epoch seconds
4. Raw for high-cardinality strings (let zstd handle)
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
    result = bytearray()
    while n >= 128:
        result.append((n & 0x7F) | 0x80)
        n >>= 7
    result.append(n & 0x7F)
    return bytes(result)

def encode_signed_varint(n):
    return encode_varint((n << 1) ^ (n >> 63))

MONTHS = {'Jan':1,'Feb':2,'Mar':3,'Apr':4,'May':5,'Jun':6,
          'Jul':7,'Aug':8,'Sep':9,'Oct':10,'Nov':11,'Dec':12}

def parse_clf_timestamp(ts):
    """Parse CLF timestamp like [01/Jul/1995:18:50:55"""
    match = re.match(r'\[?(\d{2})/(\w{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})', ts)
    if match:
        day, mon, year, hour, minute, sec = match.groups()
        # Convert to approximate seconds since epoch
        y = int(year)
        m = MONTHS.get(mon, 0)
        d = int(day)
        days = (y - 1970) * 365 + (m - 1) * 30 + d
        return days * 86400 + int(hour) * 3600 + int(minute) * 60 + int(sec)
    return None

def detect_column_type(values, sample_size=1000):
    sample = values[:sample_size]

    # Check pure integer
    int_count = sum(1 for v in sample if v and re.match(r'^-?\d+$', v))
    if int_count > len(sample) * 0.9:
        return 'integer'

    # Check CLF timestamp
    ts_count = sum(1 for v in sample if parse_clf_timestamp(v) is not None)
    if ts_count > len(sample) * 0.9:
        return 'timestamp'

    # Check cardinality for dictionary
    unique_ratio = len(set(sample)) / len(sample) if sample else 1
    if unique_ratio < 0.3:
        return 'dictionary'

    return 'raw'

def encode_lossless(lines):
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

def write_best(output_file, templates, encoded):
    output = bytearray()
    output.extend(b'DRNA')  # Magic vA (best)

    # Templates
    output.extend(struct.pack('<H', len(templates)))
    for tid in range(len(templates)):
        tmpl = templates.get(tid, "").encode('utf-8')
        output.extend(struct.pack('<H', len(tmpl)))
        output.extend(tmpl)

    n_lines = len(encoded)
    output.extend(struct.pack('<I', n_lines))

    # Template IDs
    if len(templates) <= 256:
        output.extend(bytes(tid for tid, _ in encoded))
    else:
        for tid, _ in encoded:
            output.extend(struct.pack('<H', tid))

    # Variables
    max_vars = max((len(vars) for _, vars in encoded), default=0)
    output.extend(struct.pack('<B', max_vars))

    col_types = []
    for pos in range(max_vars):
        values = [vars[pos] if pos < len(vars) else "" for _, vars in encoded]
        col_type = detect_column_type(values)
        col_types.append(col_type)

        if col_type == 'integer':
            # Delta + signed varint
            output.extend(struct.pack('<B', 1))  # Type: integer
            prev = 0
            for v in values:
                try:
                    n = int(v) if v else 0
                except:
                    n = 0
                delta = n - prev
                output.extend(encode_signed_varint(delta))
                prev = n

        elif col_type == 'timestamp':
            # Convert to epoch, delta encode
            output.extend(struct.pack('<B', 2))  # Type: timestamp
            prev = 0
            for v in values:
                ts = parse_clf_timestamp(v)
                n = ts if ts is not None else prev
                delta = n - prev
                output.extend(encode_signed_varint(delta))
                prev = n

        elif col_type == 'dictionary':
            # Frequency-sorted dictionary
            output.extend(struct.pack('<B', 3))  # Type: dictionary
            freq = Counter(values)
            sorted_vals = [v for v, _ in freq.most_common()]
            val_to_id = {v: i for i, v in enumerate(sorted_vals)}
            n_unique = len(sorted_vals)

            output.extend(struct.pack('<I', n_unique))
            for v in sorted_vals:
                vb = v.encode('utf-8', errors='replace')[:65535]
                output.extend(struct.pack('<H', len(vb)))
                output.extend(vb)

            # IDs with adaptive width
            if n_unique <= 256:
                output.extend(bytes(val_to_id[v] for v in values))
            elif n_unique <= 65536:
                for v in values:
                    output.extend(struct.pack('<H', val_to_id[v]))
            else:
                for v in values:
                    output.extend(struct.pack('<I', val_to_id[v]))

        else:  # raw
            output.extend(struct.pack('<B', 4))  # Type: raw
            for v in values:
                vb = v.encode('utf-8', errors='replace')
                if len(vb) < 128:
                    output.append(len(vb))
                else:
                    output.append(0x80 | ((len(vb) >> 8) & 0x7F))
                    output.append(len(vb) & 0xFF)
                output.extend(vb)

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

    output_file = f"{input_file}.drain_best"
    size, col_types = write_best(output_file, templates, encoded)
    print(f"Column types: {col_types}")
    print(f"Best encoded size: {size:,} bytes")

if __name__ == '__main__':
    main()
