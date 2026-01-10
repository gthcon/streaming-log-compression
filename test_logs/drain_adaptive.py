#!/usr/bin/env python3
"""
Adaptive Drain encoding - only use Drain preprocessing when beneficial.
For small files, just output raw text (let zstd handle it).
For large files, use hybrid encoding.
"""
import sys
import struct
import time
from drain3 import TemplateMiner
from drain3.template_miner_config import TemplateMinerConfig

# Threshold: only use Drain if > 10k lines
MIN_LINES_FOR_DRAIN = 10000

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

def write_adaptive(output_file, lines):
    """Adaptive format - raw for small files, Drain for large."""
    output = bytearray()
    n_lines = len(lines)

    if n_lines < MIN_LINES_FOR_DRAIN:
        # Mode 0: Raw text - just newline-separated
        output.extend(b'DRN5')
        output.extend(struct.pack('<B', 0))  # Mode 0 = raw
        output.extend(struct.pack('<I', n_lines))

        for line in lines:
            lb = line.encode('utf-8', errors='replace')
            output.extend(struct.pack('<H', len(lb)))
            output.extend(lb)
    else:
        # Mode 1: Hybrid Drain encoding
        output.extend(b'DRN5')
        output.extend(struct.pack('<B', 1))  # Mode 1 = drain

        templates, encoded = encode_lossless(lines)

        # Templates
        output.extend(struct.pack('<H', len(templates)))
        for tid in range(len(templates)):
            tmpl = templates.get(tid, "").encode('utf-8')
            output.extend(struct.pack('<H', len(tmpl)))
            output.extend(tmpl)

        output.extend(struct.pack('<I', n_lines))

        # Template IDs
        if len(templates) <= 256:
            output.extend(bytes(tid for tid, _ in encoded))
        else:
            for tid, _ in encoded:
                output.extend(struct.pack('<H', tid))

        # Variables - hybrid per-column
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

            # Use dictionary if < 30% unique
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
    mode = "Drain" if len(lines) >= MIN_LINES_FOR_DRAIN else "Raw"
    print(f"Mode: {mode} (threshold: {MIN_LINES_FOR_DRAIN})")

    start = time.time()
    output_file = f"{input_file}.drain_a"
    size = write_adaptive(output_file, lines)
    encode_time = time.time() - start

    print(f"Encode time: {encode_time:.2f}s ({len(lines)/encode_time:.0f} lines/sec)")
    print(f"Encoded size: {size:,} bytes")

if __name__ == '__main__':
    main()
