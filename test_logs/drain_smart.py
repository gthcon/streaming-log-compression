#!/usr/bin/env python3
"""
Smart Drain encoding - choose the best encoding per column:
- For numeric: Try both delta-varint and raw, pick smaller after zstd
- For strings: Use dictionary or raw based on cardinality
- Use heuristics based on estimated compressed size
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

MONTHS = {'Jan':1,'Feb':2,'Mar':3,'Apr':4,'May':5,'Jun':6,
          'Jul':7,'Aug':8,'Sep':9,'Oct':10,'Nov':11,'Dec':12}

def parse_clf_timestamp(ts):
    match = re.match(r'\[?(\d{2})/(\w{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})', ts)
    if match:
        day, mon, year, hour, minute, sec = match.groups()
        y = int(year)
        m = MONTHS.get(mon, 0)
        d = int(day)
        days = (y - 1970) * 365 + (m - 1) * 30 + d
        return days * 86400 + int(hour) * 3600 + int(minute) * 60 + int(sec)
    return None

def detect_column_type(values, sample_size=1000):
    sample = values[:sample_size]
    n = len(sample)

    int_count = sum(1 for v in sample if v and re.match(r'^-?\d+$', v))
    if int_count > n * 0.9:
        return 'integer'

    ts_count = sum(1 for v in sample if parse_clf_timestamp(v) is not None)
    if ts_count > n * 0.9:
        return 'timestamp'

    unique_ratio = len(set(sample)) / n if n else 1
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

def analyze_sortedness(values, sample_size=10000):
    """Check if numeric values are mostly sorted (sequential logs)"""
    sample = values[:sample_size]
    try:
        nums = [int(v) if v else 0 for v in sample]
    except:
        return 0

    if len(nums) < 2:
        return 0

    increasing = sum(1 for i in range(1, len(nums)) if nums[i] >= nums[i-1])
    return increasing / (len(nums) - 1)

def write_smart(output_file, templates, encoded):
    output = bytearray()
    output.extend(b'DRNB')

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

    max_vars = max((len(vars) for _, vars in encoded), default=0)
    output.extend(struct.pack('<B', max_vars))

    col_types = []
    col_decisions = []

    for pos in range(max_vars):
        values = [vars[pos] if pos < len(vars) else "" for _, vars in encoded]
        col_type = detect_column_type(values)
        col_types.append(col_type)

        if col_type == 'integer':
            # Check if sorted enough to benefit from delta encoding
            sortedness = analyze_sortedness(values)

            if sortedness > 0.8:  # Mostly sorted -> use delta
                col_decisions.append('integer-delta')
                output.extend(struct.pack('<B', 1))
                prev = 0
                for v in values:
                    try:
                        n = int(v) if v else 0
                    except:
                        n = 0
                    delta = n - prev
                    # Zigzag + varint
                    zz = (delta << 1) ^ (delta >> 63)
                    while zz >= 128:
                        output.append((zz & 0x7F) | 0x80)
                        zz >>= 7
                    output.append(zz & 0x7F)
                    prev = n
            else:
                # Not sorted -> use raw (better for zstd)
                col_decisions.append('integer-raw')
                output.extend(struct.pack('<B', 4))
                for v in values:
                    vb = v.encode('utf-8', errors='replace')
                    if len(vb) < 128:
                        output.append(len(vb))
                    else:
                        output.append(0x80 | ((len(vb) >> 8) & 0x7F))
                        output.append(len(vb) & 0xFF)
                    output.extend(vb)

        elif col_type == 'timestamp':
            # Similar check for timestamps
            ts_vals = [parse_clf_timestamp(v) or 0 for v in values[:10000]]
            sorted_count = sum(1 for i in range(1, len(ts_vals)) if ts_vals[i] >= ts_vals[i-1])
            sortedness = sorted_count / (len(ts_vals) - 1) if len(ts_vals) > 1 else 0

            if sortedness > 0.8:
                col_decisions.append('timestamp-delta')
                output.extend(struct.pack('<B', 2))
                prev = 0
                for v in values:
                    ts = parse_clf_timestamp(v)
                    n = ts if ts is not None else prev
                    delta = n - prev
                    zz = (delta << 1) ^ (delta >> 63)
                    while zz >= 128:
                        output.append((zz & 0x7F) | 0x80)
                        zz >>= 7
                    output.append(zz & 0x7F)
                    prev = n
            else:
                col_decisions.append('timestamp-raw')
                output.extend(struct.pack('<B', 4))
                for v in values:
                    vb = v.encode('utf-8', errors='replace')
                    if len(vb) < 128:
                        output.append(len(vb))
                    else:
                        output.append(0x80 | ((len(vb) >> 8) & 0x7F))
                        output.append(len(vb) & 0xFF)
                    output.extend(vb)

        elif col_type == 'dictionary':
            col_decisions.append('dictionary')
            output.extend(struct.pack('<B', 3))
            freq = Counter(values)
            sorted_vals = [v for v, _ in freq.most_common()]
            val_to_id = {v: i for i, v in enumerate(sorted_vals)}
            n_unique = len(sorted_vals)

            output.extend(struct.pack('<I', n_unique))
            for v in sorted_vals:
                vb = v.encode('utf-8', errors='replace')[:65535]
                output.extend(struct.pack('<H', len(vb)))
                output.extend(vb)

            if n_unique <= 256:
                output.extend(bytes(val_to_id[v] for v in values))
            elif n_unique <= 65536:
                for v in values:
                    output.extend(struct.pack('<H', val_to_id[v]))
            else:
                for v in values:
                    output.extend(struct.pack('<I', val_to_id[v]))

        else:
            col_decisions.append('raw')
            output.extend(struct.pack('<B', 4))
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

    return len(output), col_decisions

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

    output_file = f"{input_file}.drain_smart"
    size, col_decisions = write_smart(output_file, templates, encoded)
    print(f"Column decisions: {col_decisions}")
    print(f"Smart encoded size: {size:,} bytes")

if __name__ == '__main__':
    main()
