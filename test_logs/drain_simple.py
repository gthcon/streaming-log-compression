#!/usr/bin/env python3
"""
Simplified Drain encoding - let zstd do the heavy lifting.
Just output template IDs and raw variable values in a format that zstd compresses well.
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

def write_simple(output_file, templates, encoded):
    """Write simple format - templates, IDs column, then raw variable columns."""
    output = bytearray()

    # Magic + version
    output.extend(b'DRN3')

    # Templates
    output.extend(struct.pack('<H', len(templates)))
    for tid in range(len(templates)):
        tmpl = templates.get(tid, "").encode('utf-8')
        output.extend(struct.pack('<H', len(tmpl)))
        output.extend(tmpl)

    n_lines = len(encoded)
    output.extend(struct.pack('<I', n_lines))

    # Template IDs - all together for better RLE
    if len(templates) <= 256:
        output.extend(bytes(tid for tid, _ in encoded))
    else:
        for tid, _ in encoded:
            output.extend(struct.pack('<H', tid))

    # Variables - group by position, store raw (no dictionary)
    max_vars = max((len(vars) for _, vars in encoded), default=0)
    output.extend(struct.pack('<B', max_vars))

    for pos in range(max_vars):
        # Collect all values at this position
        col_data = bytearray()
        for _, vars in encoded:
            if pos < len(vars):
                vb = vars[pos].encode('utf-8', errors='replace')
            else:
                vb = b''

            # Variable-length encoding: 1-byte len if < 128, else 2-byte
            if len(vb) < 128:
                col_data.append(len(vb))
            else:
                col_data.append(0x80 | (len(vb) >> 8))
                col_data.append(len(vb) & 0xFF)
            col_data.extend(vb)

        # Store column with length prefix
        output.extend(struct.pack('<I', len(col_data)))
        output.extend(col_data)

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

    output_file = f"{input_file}.drain_s"
    size = write_simple(output_file, templates, encoded)
    print(f"\nSimple encoded size: {size:,} bytes")

if __name__ == '__main__':
    main()
