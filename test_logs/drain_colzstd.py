#!/usr/bin/env python3
"""
Drain + Per-column Zstd compression.
Each column gets its own zstd compression context for better compression.
"""
import sys
import struct
import time
import zstandard as zstd
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

def write_colzstd(output_file, templates, encoded, compression_level=3):
    """Write with per-column zstd compression"""
    cctx = zstd.ZstdCompressor(level=compression_level)

    output = bytearray()
    output.extend(b'DRN9')

    # Templates (compressed)
    tmpl_data = bytearray()
    tmpl_data.extend(struct.pack('<H', len(templates)))
    for tid in range(len(templates)):
        tmpl = templates.get(tid, "").encode('utf-8')
        tmpl_data.extend(struct.pack('<H', len(tmpl)))
        tmpl_data.extend(tmpl)

    tmpl_compressed = cctx.compress(bytes(tmpl_data))
    output.extend(struct.pack('<I', len(tmpl_compressed)))
    output.extend(tmpl_compressed)

    n_lines = len(encoded)
    output.extend(struct.pack('<I', n_lines))

    # Template IDs (compressed separately)
    if len(templates) <= 256:
        tid_data = bytes(tid for tid, _ in encoded)
    else:
        tid_data = b''.join(struct.pack('<H', tid) for tid, _ in encoded)

    tid_compressed = cctx.compress(tid_data)
    output.extend(struct.pack('<I', len(tid_compressed)))
    output.extend(tid_compressed)

    # Variables - each column compressed separately
    max_vars = max((len(vars) for _, vars in encoded), default=0)
    output.extend(struct.pack('<B', max_vars))

    for pos in range(max_vars):
        values = []
        for _, vars in encoded:
            values.append(vars[pos] if pos < len(vars) else "")

        # Store as length-prefixed strings, then compress
        col_data = bytearray()
        for v in values:
            vb = v.encode('utf-8', errors='replace')
            if len(vb) < 128:
                col_data.append(len(vb))
            else:
                col_data.append(0x80 | ((len(vb) >> 8) & 0x7F))
                col_data.append(len(vb) & 0xFF)
            col_data.extend(vb)

        col_compressed = cctx.compress(bytes(col_data))
        output.extend(struct.pack('<I', len(col_compressed)))
        output.extend(col_compressed)

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

    output_file = f"{input_file}.drain_cz"
    size = write_colzstd(output_file, templates, encoded)
    print(f"Column-zstd encoded size: {size:,} bytes")

if __name__ == '__main__':
    main()
