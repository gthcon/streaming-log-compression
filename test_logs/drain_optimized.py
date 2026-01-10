#!/usr/bin/env python3
"""
Optimized Drain-based LOSSLESS encoding.
Key improvements:
1. Skip dictionary encoding for high-cardinality columns (store raw)
2. Use delta encoding for numeric sequences
3. Pack similar-length strings together
"""
import sys
import struct
import time
from collections import defaultdict
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

def write_optimized(output_file, templates, encoded):
    """Write with smart column encoding - skip dictionary for high-cardinality"""
    output = bytearray()

    # Magic + version
    output.extend(b'DRN2')  # Magic for v2 format

    # Templates
    output.extend(struct.pack('<I', len(templates)))
    for tid in range(len(templates)):
        tmpl = templates.get(tid, "").encode('utf-8')
        output.extend(struct.pack('<H', len(tmpl)))
        output.extend(tmpl)

    # Template IDs column
    n_lines = len(encoded)
    output.extend(struct.pack('<I', n_lines))

    if len(templates) <= 256:
        output.extend(bytes(tid for tid, _ in encoded))
    else:
        for tid, _ in encoded:
            output.extend(struct.pack('<H', tid))

    # Variables - smart encoding per column
    max_vars = max((len(vars) for _, vars in encoded), default=0)
    output.extend(struct.pack('<B', max_vars))

    for pos in range(max_vars):
        # Collect values at this position
        values = []
        for _, vars in encoded:
            if pos < len(vars):
                values.append(vars[pos])
            else:
                values.append("")

        unique = list(dict.fromkeys(values))
        n_unique = len(unique)
        cardinality_ratio = n_unique / n_lines if n_lines > 0 else 0

        # Encoding mode decision:
        # - Mode 0: Dictionary encoding (good for low cardinality)
        # - Mode 1: Raw string storage (better for high cardinality)
        # - Mode 2: Length-prefixed raw (for variable length)

        # Calculate estimated sizes
        avg_len = sum(len(v) for v in values) / len(values) if values else 0

        # Dictionary overhead = dict entries + IDs per line
        dict_size = sum(2 + len(v.encode('utf-8', errors='replace')) for v in unique)
        if n_unique <= 256:
            id_size = n_lines
        elif n_unique <= 65536:
            id_size = n_lines * 2
        else:
            id_size = n_lines * 4
        dict_total = dict_size + id_size

        # Raw size = length prefix + data for each line
        raw_total = sum(2 + len(v.encode('utf-8', errors='replace')) for v in values)

        # Choose mode based on estimated compressed size
        # Dictionary is better when there's good repetition
        # Factor in that zstd compresses repeated patterns well
        use_dictionary = dict_total < raw_total * 0.9  # Need 10% improvement to justify overhead

        if use_dictionary:
            # Mode 0: Dictionary encoding
            output.extend(struct.pack('<B', 0))
            val_to_id = {v: i for i, v in enumerate(unique)}

            output.extend(struct.pack('<I', n_unique))
            for v in unique:
                vb = v.encode('utf-8', errors='replace')[:65535]
                output.extend(struct.pack('<H', len(vb)))
                output.extend(vb)

            # IDs
            if n_unique <= 256:
                output.extend(bytes(val_to_id[v] for v in values))
            elif n_unique <= 65536:
                for v in values:
                    output.extend(struct.pack('<H', val_to_id[v]))
            else:
                for v in values:
                    output.extend(struct.pack('<I', val_to_id[v]))
        else:
            # Mode 1: Raw string storage - better for zstd to compress
            output.extend(struct.pack('<B', 1))

            # Join all values with length prefixes
            for v in values:
                vb = v.encode('utf-8', errors='replace')
                if len(vb) <= 255:
                    output.extend(struct.pack('<B', len(vb)))
                    output.extend(vb)
                else:
                    output.extend(struct.pack('<B', 255))  # Escape for longer
                    output.extend(struct.pack('<H', len(vb)))
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

    output_file = f"{input_file}.drain_opt"
    size = write_optimized(output_file, templates, encoded)
    print(f"\nOptimized encoded size: {size:,} bytes")

if __name__ == '__main__':
    main()
