#!/usr/bin/env python3
"""
Drain + XOR encoding: XOR consecutive values in each column.
This creates lots of zeros when values are similar, which compresses well.
"""
import sys
import struct
import time
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

def xor_strings(a, b):
    """XOR two strings, pad shorter one with zeros"""
    max_len = max(len(a), len(b))
    a = a.ljust(max_len, '\x00')
    b = b.ljust(max_len, '\x00')
    return bytes(ord(x) ^ ord(y) for x, y in zip(a, b))

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

def write_xor(output_file, templates, encoded):
    """XOR consecutive values in each column"""
    output = bytearray()
    output.extend(b'DRN7')

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

    # Variables with XOR encoding
    max_vars = max((len(vars) for _, vars in encoded), default=0)
    output.extend(struct.pack('<B', max_vars))

    total_zeros = 0
    total_bytes = 0

    for pos in range(max_vars):
        values = []
        for _, vars in encoded:
            values.append(vars[pos] if pos < len(vars) else "")

        # XOR consecutive values
        col_data = bytearray()
        prev = ""
        for v in values:
            xored = xor_strings(prev, v)
            # Store length then XOR'd data
            col_data.extend(struct.pack('<H', len(xored)))
            col_data.extend(xored)
            prev = v
            total_zeros += xored.count(0)
            total_bytes += len(xored)

        output.extend(struct.pack('<I', len(col_data)))
        output.extend(col_data)

    with open(output_file, 'wb') as f:
        f.write(output)

    zero_pct = 100 * total_zeros / total_bytes if total_bytes > 0 else 0
    return len(output), zero_pct

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

    output_file = f"{input_file}.drain_xor"
    size, zero_pct = write_xor(output_file, templates, encoded)
    print(f"XOR zero bytes: {zero_pct:.1f}%")
    print(f"XOR encoded size: {size:,} bytes")

if __name__ == '__main__':
    main()
