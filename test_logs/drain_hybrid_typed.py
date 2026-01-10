#!/usr/bin/env python3
"""
Hybrid approach combining:
- drain_smart's text-based delta encoding (best for zstd)
- Type-specific optimizations where they actually help

Key insight: Binary encodings hurt zstd compression.
Instead, we use TEXT-BASED type-aware encoding:
- Timestamps: text delta ("0", "1000", "1000")
- IPs: text delta of numeric value ("0", "1", "256")
- HTTP status: single digit category + 2 digits ("2 00", "3 04", "4 04")
- Integers: text delta when sorted
- Strings: dictionary with frequency-sorted indices
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

# Type detection patterns
PATTERNS = {
    'ipv4': re.compile(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'),
    'clf_timestamp': re.compile(r'^\[?(\d{2})/(\w{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})'),
    'iso_timestamp': re.compile(r'^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})'),
    'http_status': re.compile(r'^([1-5]\d{2})$'),
    'integer': re.compile(r'^(-?\d+)$'),
}

MONTHS = {'Jan':1,'Feb':2,'Mar':3,'Apr':4,'May':5,'Jun':6,
          'Jul':7,'Aug':8,'Sep':9,'Oct':10,'Nov':11,'Dec':12}

def classify_value(val):
    """Classify a value and extract numeric representation"""
    if not val:
        return 'empty', None, val

    # HTTP status first (before integer)
    m = PATTERNS['http_status'].match(val)
    if m:
        code = int(m.group(1))
        return 'http_status', code, val

    # Integer
    m = PATTERNS['integer'].match(val)
    if m:
        return 'integer', int(m.group(1)), val

    # IPv4 - convert to single number for delta encoding
    m = PATTERNS['ipv4'].match(val)
    if m:
        octets = [int(x) for x in m.groups()]
        if all(0 <= o <= 255 for o in octets):
            ip_num = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]
            return 'ipv4', ip_num, val

    # CLF Timestamp - convert to seconds
    m = PATTERNS['clf_timestamp'].match(val)
    if m:
        day, mon, year, hour, minute, sec = m.groups()
        y, mo, d = int(year), MONTHS.get(mon, 1), int(day)
        h, mi, s = int(hour), int(minute), int(sec)
        # Approximate seconds since epoch
        days = (y - 1970) * 365 + (y - 1969) // 4 + (mo - 1) * 30 + d
        secs = days * 86400 + h * 3600 + mi * 60 + s
        return 'clf_timestamp', secs, val

    # ISO Timestamp
    m = PATTERNS['iso_timestamp'].match(val)
    if m:
        year, mon, day, hour, minute, sec = m.groups()
        y, mo, d = int(year), int(mon), int(day)
        h, mi, s = int(hour), int(minute), int(sec)
        days = (y - 1970) * 365 + (y - 1969) // 4 + (mo - 1) * 30 + d
        secs = days * 86400 + h * 3600 + mi * 60 + s
        return 'iso_timestamp', secs, val

    return 'string', None, val

def detect_column_type(values):
    """Detect predominant type for a column"""
    sample = [v for v in values[:1000] if v]
    if not sample:
        return 'string'

    classifications = [classify_value(v) for v in sample]
    types = [c[0] for c in classifications]
    type_counts = Counter(types)
    top_type, count = type_counts.most_common(1)[0]

    if count >= len(sample) * 0.9:
        return top_type
    return 'string'

def encode_column_smart(values, col_type):
    """
    Encode column using TEXT-BASED representations optimized for zstd.
    Returns list of encoded string values.
    """
    n_lines = len(values)

    if col_type in ('clf_timestamp', 'iso_timestamp', 'ipv4'):
        # Delta encoding as TEXT - this is the key insight!
        # Text deltas like "0,1000,1000" compress better than binary
        encoded = []
        prev_val = 0
        for v in values:
            _, num, orig = classify_value(v)
            if num is not None:
                delta = num - prev_val
                encoded.append(str(delta))
                prev_val = num
            else:
                encoded.append(orig)  # Fallback to original
        return 'delta-text', encoded

    elif col_type == 'http_status':
        # HTTP status: use dictionary since there are only ~20 unique codes
        unique = set(values)
        n_unique = len(unique)

        freq = Counter(values)
        sorted_vals = [v for v, _ in freq.most_common()]
        val_to_id = {v: i for i, v in enumerate(sorted_vals)}

        encoded = [str(val_to_id[v]) for v in values]
        return 'dictionary', encoded, sorted_vals

    elif col_type == 'integer':
        # Check if sorted for delta encoding
        sample_nums = []
        for v in values[:1000]:
            _, num, _ = classify_value(v)
            if num is not None:
                sample_nums.append(num)

        if len(sample_nums) >= 10:
            sorted_count = sum(1 for i in range(1, len(sample_nums))
                             if sample_nums[i] >= sample_nums[i-1])
            is_sorted = sorted_count >= len(sample_nums) * 0.8
        else:
            is_sorted = False

        if is_sorted:
            # Delta encoding as text
            encoded = []
            prev_val = 0
            for v in values:
                _, num, orig = classify_value(v)
                if num is not None:
                    delta = num - prev_val
                    encoded.append(str(delta))
                    prev_val = num
                else:
                    encoded.append(orig)
            return 'integer-delta', encoded
        else:
            # Raw integers as text (already compact)
            return 'integer-raw', values

    else:
        # String - check for dictionary encoding benefit
        unique = set(values)
        n_unique = len(unique)

        if n_unique < 0.3 * n_lines:
            # Dictionary encoding with frequency-sorted indices
            freq = Counter(values)
            sorted_vals = [v for v, _ in freq.most_common()]
            val_to_id = {v: i for i, v in enumerate(sorted_vals)}

            encoded = [str(val_to_id[v]) for v in values]
            return 'dictionary', encoded, sorted_vals
        else:
            # Raw strings
            return 'raw', values

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

def write_hybrid(output_file, templates, encoded):
    """Write with hybrid text-based type-aware encoding"""
    output = bytearray()
    output.extend(b'DRNH')  # Magic: Drain Hybrid

    # Templates
    output.extend(struct.pack('<H', len(templates)))
    for tid in range(len(templates)):
        tmpl = templates.get(tid, "").encode('utf-8')
        output.extend(struct.pack('<H', len(tmpl)))
        output.extend(tmpl)

    n_lines = len(encoded)
    output.extend(struct.pack('<I', n_lines))

    # Template IDs - use smallest width that fits
    if len(templates) <= 256:
        output.extend(bytes(tid for tid, _ in encoded))
    else:
        for tid, _ in encoded:
            output.extend(struct.pack('<H', tid))

    max_vars = max((len(vars) for _, vars in encoded), default=0)
    output.extend(struct.pack('<B', max_vars))

    col_decisions = []

    for pos in range(max_vars):
        values = [vars[pos] if pos < len(vars) else "" for _, vars in encoded]

        # Detect column type
        col_type = detect_column_type(values)

        # Encode column with type-aware strategy
        result = encode_column_smart(values, col_type)

        if len(result) == 3:
            decision, encoded_vals, dictionary = result
            col_decisions.append(decision)

            # Write dictionary
            output.extend(struct.pack('<B', 1))  # Has dictionary
            output.extend(struct.pack('<I', len(dictionary)))
            for v in dictionary:
                vb = v.encode('utf-8', errors='replace')[:65535]
                output.extend(struct.pack('<H', len(vb)))
                output.extend(vb)

            # Write indices as text (for zstd to compress)
            all_text = '\n'.join(encoded_vals)
            text_bytes = all_text.encode('utf-8')
            output.extend(struct.pack('<I', len(text_bytes)))
            output.extend(text_bytes)
        else:
            decision, encoded_vals = result
            col_decisions.append(decision)

            # No dictionary
            output.extend(struct.pack('<B', 0))

            # Write values as newline-separated text
            all_text = '\n'.join(encoded_vals)
            text_bytes = all_text.encode('utf-8')
            output.extend(struct.pack('<I', len(text_bytes)))
            output.extend(text_bytes)

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

    output_file = f"{input_file}.drain_hybrid_typed"
    size, col_decisions = write_hybrid(output_file, templates, encoded)
    print(f"Column decisions: {col_decisions}")
    print(f"Hybrid typed size: {size:,} bytes")

if __name__ == '__main__':
    main()
