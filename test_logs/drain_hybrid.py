#!/usr/bin/env python3
"""
Hybrid Drain encoding - smart per-column encoding decision.
- Dictionary encode low-cardinality columns (< 50% unique)
- Raw encode high-cardinality columns
"""
import sys
import struct
import time
from drain3 import TemplateMiner
from drain3.template_miner_config import TemplateMinerConfig

def get_line_delta(template, line):
    """Extract variable values from line given template."""
    parts = template.split('<*>')

    if len(parts) == 1:
        return [] if template == line else [line]

    variables = []
    remaining = line

    for i, part in enumerate(parts):
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
    """Encode logs with Drain - fully lossless"""
    config = TemplateMinerConfig()
    config.profiling_enabled = False

    miner = TemplateMiner(config=config)

    results = []
    for line in lines:
        result = miner.add_log_message(line)
        cluster_id = result["cluster_id"]
        results.append((cluster_id, line))

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

def write_hybrid(output_file, templates, encoded):
    """Hybrid format - dictionary for low cardinality, raw for high cardinality."""
    output = bytearray()

    # Magic
    output.extend(b'DRN4')

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

    for pos in range(max_vars):
        values = []
        for _, vars in encoded:
            if pos < len(vars):
                values.append(vars[pos])
            else:
                values.append("")

        unique = list(dict.fromkeys(values))
        n_unique = len(unique)

        # Cardinality threshold: use dictionary if < 30% unique
        use_dict = n_unique < 0.3 * n_lines and n_unique < 65536

        if use_dict:
            # Dictionary encoding
            output.extend(struct.pack('<B', 0))  # Mode 0 = dictionary
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
            # Raw encoding
            output.extend(struct.pack('<B', 1))  # Mode 1 = raw

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
    templates, encoded = encode_lossless(lines)
    encode_time = time.time() - start

    print(f"Encode time: {encode_time:.2f}s ({len(lines)/encode_time:.0f} lines/sec)")
    print(f"Unique templates: {len(templates)}")

    total_vars = sum(len(vars) for _, vars in encoded)
    max_vars = max((len(vars) for _, vars in encoded), default=0)
    print(f"Total variables: {total_vars}, Max per line: {max_vars}")

    output_file = f"{input_file}.drain_h"
    size = write_hybrid(output_file, templates, encoded)
    print(f"\nHybrid encoded size: {size:,} bytes")

if __name__ == '__main__':
    main()
