#!/usr/bin/env python3
"""
Drain + Sorted encoding: Sort lines by template, then by first variable.
This groups similar lines together, making both dictionary and XOR encoding more effective.
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

def encode_lossless(lines):
    config = TemplateMinerConfig()
    config.profiling_enabled = False
    miner = TemplateMiner(config=config)

    results = []
    for i, line in enumerate(lines):
        result = miner.add_log_message(line)
        results.append((result["cluster_id"], i, line))

    clusters = {c.cluster_id: c.get_template() for c in miner.drain.clusters}
    unique_clusters = sorted(set(cid for cid, _, _ in results))
    cluster_to_tid = {cid: i for i, cid in enumerate(unique_clusters)}
    templates = {cluster_to_tid[cid]: clusters[cid] for cid in unique_clusters}

    # Sort by template ID, then by first variable (to group similar lines)
    sorted_results = []
    for cid, orig_idx, line in results:
        tid = cluster_to_tid[cid]
        template = templates[tid]
        variables = get_line_delta(template, line)
        sort_key = (tid, variables[0] if variables else "")
        sorted_results.append((sort_key, orig_idx, tid, variables))

    sorted_results.sort(key=lambda x: x[0])

    # Store original indices for reconstruction
    original_order = [orig_idx for _, orig_idx, _, _ in sorted_results]
    encoded = [(tid, variables) for _, _, tid, variables in sorted_results]

    return templates, encoded, original_order

def write_sorted(output_file, templates, encoded, original_order):
    """Write sorted data with index mapping for reconstruction"""
    output = bytearray()
    output.extend(b'DRN8')

    # Templates
    output.extend(struct.pack('<H', len(templates)))
    for tid in range(len(templates)):
        tmpl = templates.get(tid, "").encode('utf-8')
        output.extend(struct.pack('<H', len(tmpl)))
        output.extend(tmpl)

    n_lines = len(encoded)
    output.extend(struct.pack('<I', n_lines))

    # Original order indices (for reconstruction)
    # Delta encode the indices
    prev = 0
    idx_data = bytearray()
    for idx in original_order:
        delta = idx - prev
        # Varint encode
        n = (delta << 1) ^ (delta >> 31)  # zigzag
        while n >= 128:
            idx_data.append((n & 0x7F) | 0x80)
            n >>= 7
        idx_data.append(n & 0x7F)
        prev = idx
    output.extend(struct.pack('<I', len(idx_data)))
    output.extend(idx_data)

    # Template IDs (now sorted, so lots of runs)
    if len(templates) <= 256:
        output.extend(bytes(tid for tid, _ in encoded))
    else:
        for tid, _ in encoded:
            output.extend(struct.pack('<H', tid))

    # Variables - hybrid encoding (dictionary for low cardinality)
    max_vars = max((len(vars) for _, vars in encoded), default=0)
    output.extend(struct.pack('<B', max_vars))

    for pos in range(max_vars):
        values = []
        for _, vars in encoded:
            values.append(vars[pos] if pos < len(vars) else "")

        unique = list(dict.fromkeys(values))
        n_unique = len(unique)
        use_dict = n_unique < 0.3 * n_lines and n_unique < 65536

        if use_dict:
            output.extend(struct.pack('<B', 0))
            val_to_id = {v: i for i, v in enumerate(unique)}
            output.extend(struct.pack('<I', n_unique))
            for v in unique:
                vb = v.encode('utf-8', errors='replace')[:65535]
                output.extend(struct.pack('<H', len(vb)))
                output.extend(vb)
            if n_unique <= 256:
                output.extend(bytes(val_to_id[v] for v in values))
            elif n_unique <= 65536:
                for v in values:
                    output.extend(struct.pack('<H', val_to_id[v]))
        else:
            output.extend(struct.pack('<B', 1))
            for v in values:
                vb = v.encode('utf-8', errors='replace')
                if len(vb) < 128:
                    output.append(len(vb))
                else:
                    output.append(0x80 | (len(vb) >> 8))
                    output.append(len(vb) & 0xFF)
                output.extend(vb)

    with open(output_file, 'wb') as f:
        f.write(output)

    return len(output)

def main():
    input_file = sys.argv[1]

    with open(input_file, 'r', errors='replace') as f:
        lines = [l.rstrip('\n') for l in f]

    print(f"Lines: {len(lines)}")

    start = time.time()
    templates, encoded, original_order = encode_lossless(lines)
    encode_time = time.time() - start

    print(f"Encode time: {encode_time:.2f}s ({len(lines)/encode_time:.0f} lines/sec)")
    print(f"Unique templates: {len(templates)}")

    output_file = f"{input_file}.drain_sort"
    size = write_sorted(output_file, templates, encoded, original_order)
    print(f"Sorted encoded size: {size:,} bytes")

if __name__ == '__main__':
    main()
