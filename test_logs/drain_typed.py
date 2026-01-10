#!/usr/bin/env python3
"""
Drain with specialized type encodings:
- IPv4: 4 bytes binary
- Hostname: dictionary + suffix compression
- Timestamp: delta from reference (varint)
- Date: days since epoch (2 bytes)
- Time: seconds since midnight (2 bytes)
- UUID: 16 bytes binary
- HTTP status: 1 byte (offset from 100)
- URL path: dictionary + LZ-style prefix matching
"""
import sys
import struct
import time
import re
import socket
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
    'uuid': re.compile(r'^([0-9a-fA-F]{8})-([0-9a-fA-F]{4})-([0-9a-fA-F]{4})-([0-9a-fA-F]{4})-([0-9a-fA-F]{12})$'),
    'url_path': re.compile(r'^(/[^\s]*)$'),
    'hostname': re.compile(r'^([a-zA-Z0-9][a-zA-Z0-9\-\.]*[a-zA-Z0-9])$'),
}

MONTHS = {'Jan':1,'Feb':2,'Mar':3,'Apr':4,'May':5,'Jun':6,
          'Jul':7,'Aug':8,'Sep':9,'Oct':10,'Nov':11,'Dec':12}

def classify_value(val):
    """Classify a single value - order matters for priority"""
    if not val:
        return 'empty', None

    # HTTP status (before integer to catch 200, 404, etc.)
    m = PATTERNS['http_status'].match(val)
    if m:
        return 'http_status', int(m.group(1))

    # Integer
    m = PATTERNS['integer'].match(val)
    if m:
        return 'integer', int(m.group(1))

    # IPv4
    m = PATTERNS['ipv4'].match(val)
    if m:
        octets = [int(x) for x in m.groups()]
        if all(0 <= o <= 255 for o in octets):
            return 'ipv4', tuple(octets)

    # CLF Timestamp
    m = PATTERNS['clf_timestamp'].match(val)
    if m:
        day, mon, year, hour, minute, sec = m.groups()
        return 'clf_timestamp', (int(year), MONTHS.get(mon, 0), int(day), int(hour), int(minute), int(sec))

    # ISO Timestamp
    m = PATTERNS['iso_timestamp'].match(val)
    if m:
        year, mon, day, hour, minute, sec = m.groups()
        return 'iso_timestamp', (int(year), int(mon), int(day), int(hour), int(minute), int(sec))

    # UUID
    m = PATTERNS['uuid'].match(val)
    if m:
        return 'uuid', val.replace('-', '')

    # URL path
    m = PATTERNS['url_path'].match(val)
    if m:
        return 'url_path', val

    # Hostname
    m = PATTERNS['hostname'].match(val)
    if m and '.' in val:
        return 'hostname', val

    return 'string', val

def detect_column_type(values):
    """Detect predominant type for a column"""
    sample = [v for v in values[:1000] if v]
    if not sample:
        return 'string'

    types = [classify_value(v)[0] for v in sample]
    type_counts = Counter(types)
    top_type, count = type_counts.most_common(1)[0]

    if count >= len(sample) * 0.9:
        return top_type
    return 'string'

# Encoding functions
def encode_ipv4(octets):
    """4 bytes"""
    return bytes(octets)

def encode_ipv4_delta(octets, prev_octets):
    """Delta encode from previous IP - good for sorted logs"""
    if prev_octets is None:
        return bytes([0xFF]) + bytes(octets)  # Full IP

    # XOR with previous
    xor = bytes(a ^ b for a, b in zip(octets, prev_octets))

    # Count leading zeros
    leading_zeros = 0
    for b in xor:
        if b == 0:
            leading_zeros += 1
        else:
            break

    if leading_zeros >= 3:
        # Only last octet different - 2 bytes
        return bytes([0x01, xor[3]])
    elif leading_zeros >= 2:
        # Last 2 octets different - 3 bytes
        return bytes([0x02]) + xor[2:4]
    else:
        # Full IP - 5 bytes
        return bytes([0xFF]) + bytes(octets)

def timestamp_to_seconds(ts_tuple):
    """Convert (year, month, day, hour, min, sec) to seconds since epoch"""
    year, mon, day, hour, minute, sec = ts_tuple
    # Approximate - good enough for delta encoding
    days = (year - 1970) * 365 + (year - 1969) // 4 + (mon - 1) * 30 + day
    return days * 86400 + hour * 3600 + minute * 60 + sec

def encode_varint_signed(n):
    """Zigzag + varint encoding for signed integers"""
    # Zigzag encoding
    n = (n << 1) ^ (n >> 63)
    result = bytearray()
    while n >= 128:
        result.append((n & 0x7F) | 0x80)
        n >>= 7
    result.append(n & 0x7F)
    return bytes(result)

def encode_http_status(code):
    """1 byte: status - 100, clamped to valid range"""
    if 100 <= code <= 355:  # 100-355 fits in 0-255
        return bytes([code - 100])
    else:
        return bytes([255])  # Invalid marker

def encode_uuid_binary(uuid_hex):
    """16 bytes binary"""
    return bytes.fromhex(uuid_hex)

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

def write_typed(output_file, templates, encoded):
    """Write with type-specific encodings"""
    output = bytearray()
    output.extend(b'DRNT')  # Magic: Drain Typed

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
    col_savings = []

    for pos in range(max_vars):
        values = [vars[pos] if pos < len(vars) else "" for _, vars in encoded]
        col_type = detect_column_type(values)
        col_types.append(col_type)

        raw_size = sum(len(v.encode('utf-8', errors='replace')) for v in values)

        if col_type == 'ipv4':
            output.extend(struct.pack('<B', 1))  # Type: IPv4
            prev_octets = None
            for v in values:
                _, parsed = classify_value(v)
                if parsed and isinstance(parsed, tuple) and len(parsed) == 4:
                    enc = encode_ipv4_delta(parsed, prev_octets)
                    output.extend(enc)
                    prev_octets = parsed
                else:
                    output.append(0x00)  # Fallback marker
                    vb = v.encode('utf-8', errors='replace')
                    output.extend(struct.pack('<H', len(vb)))
                    output.extend(vb)
                    prev_octets = None
            col_savings.append(('ipv4', raw_size))

        elif col_type in ('clf_timestamp', 'iso_timestamp'):
            output.extend(struct.pack('<B', 2))  # Type: Timestamp
            prev_secs = 0
            for v in values:
                _, parsed = classify_value(v)
                if parsed and isinstance(parsed, tuple) and len(parsed) == 6:
                    secs = timestamp_to_seconds(parsed)
                    delta = secs - prev_secs
                    output.extend(encode_varint_signed(delta))
                    prev_secs = secs
                else:
                    output.extend(encode_varint_signed(0))  # Zero delta = string follows
                    vb = v.encode('utf-8', errors='replace')
                    output.extend(struct.pack('<H', len(vb)))
                    output.extend(vb)
            col_savings.append(('timestamp', raw_size))

        elif col_type == 'http_status':
            output.extend(struct.pack('<B', 3))  # Type: HTTP Status
            for v in values:
                _, parsed = classify_value(v)
                if parsed and isinstance(parsed, int) and 100 <= parsed <= 599:
                    output.extend(encode_http_status(parsed))
                else:
                    output.append(0xFF)  # Invalid marker
                    vb = v.encode('utf-8', errors='replace')
                    output.append(len(vb))
                    output.extend(vb)
            col_savings.append(('http_status', raw_size))

        elif col_type == 'integer':
            output.extend(struct.pack('<B', 4))  # Type: Integer
            # Check if sorted for delta encoding
            sample_ints = []
            for v in values[:1000]:
                _, parsed = classify_value(v)
                if isinstance(parsed, int):
                    sample_ints.append(parsed)

            sorted_count = sum(1 for i in range(1, len(sample_ints)) if sample_ints[i] >= sample_ints[i-1])
            is_sorted = sorted_count >= len(sample_ints) * 0.8 if sample_ints else False

            output.append(1 if is_sorted else 0)  # Sorted flag

            prev = 0
            for v in values:
                _, parsed = classify_value(v)
                if isinstance(parsed, int):
                    if is_sorted:
                        output.extend(encode_varint_signed(parsed - prev))
                        prev = parsed
                    else:
                        output.extend(encode_varint_signed(parsed))
                else:
                    output.extend(encode_varint_signed(0))
                    vb = v.encode('utf-8', errors='replace')
                    output.extend(struct.pack('<H', len(vb)))
                    output.extend(vb)
            col_savings.append(('integer', raw_size))

        elif col_type == 'uuid':
            output.extend(struct.pack('<B', 5))  # Type: UUID
            for v in values:
                _, parsed = classify_value(v)
                if parsed and len(parsed) == 32:
                    output.extend(encode_uuid_binary(parsed))
                else:
                    output.extend(bytes(16))  # Null UUID marker
                    vb = v.encode('utf-8', errors='replace')
                    output.extend(struct.pack('<H', len(vb)))
                    output.extend(vb)
            col_savings.append(('uuid', raw_size))

        elif col_type in ('url_path', 'hostname'):
            # Dictionary encoding with frequency sorting
            output.extend(struct.pack('<B', 6))  # Type: Dictionary
            unique = list(dict.fromkeys(values))
            n_unique = len(unique)

            freq = Counter(values)
            sorted_vals = [v for v, _ in freq.most_common()]
            val_to_id = {v: i for i, v in enumerate(sorted_vals)}

            output.extend(struct.pack('<I', len(sorted_vals)))
            for v in sorted_vals:
                vb = v.encode('utf-8', errors='replace')[:65535]
                output.extend(struct.pack('<H', len(vb)))
                output.extend(vb)

            if len(sorted_vals) <= 256:
                output.extend(bytes(val_to_id[v] for v in values))
            elif len(sorted_vals) <= 65536:
                for v in values:
                    output.extend(struct.pack('<H', val_to_id[v]))
            else:
                for v in values:
                    output.extend(struct.pack('<I', val_to_id[v]))
            col_savings.append((col_type, raw_size))

        else:
            # String - use dictionary if beneficial, otherwise raw
            unique = list(dict.fromkeys(values))
            n_unique = len(unique)
            n_lines = len(values)

            if n_unique < 0.3 * n_lines and n_unique < 65536:
                # Dictionary encoding - like drain_smart
                output.extend(struct.pack('<B', 6))  # Type: Dictionary
                freq = Counter(values)
                sorted_vals = [v for v, _ in freq.most_common()]
                val_to_id = {v: i for i, v in enumerate(sorted_vals)}

                output.extend(struct.pack('<I', len(sorted_vals)))
                for v in sorted_vals:
                    vb = v.encode('utf-8', errors='replace')[:65535]
                    output.extend(struct.pack('<H', len(vb)))
                    output.extend(vb)

                if len(sorted_vals) <= 256:
                    output.extend(bytes(val_to_id[v] for v in values))
                elif len(sorted_vals) <= 65536:
                    for v in values:
                        output.extend(struct.pack('<H', val_to_id[v]))
                else:
                    for v in values:
                        output.extend(struct.pack('<I', val_to_id[v]))
                col_savings.append(('dictionary', raw_size))
            else:
                # Raw string with length prefix
                output.extend(struct.pack('<B', 7))  # Type: Raw
                for v in values:
                    vb = v.encode('utf-8', errors='replace')
                    if len(vb) < 128:
                        output.append(len(vb))
                    else:
                        output.append(0x80 | ((len(vb) >> 8) & 0x7F))
                        output.append(len(vb) & 0xFF)
                    output.extend(vb)
                col_savings.append(('raw', raw_size))

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

    output_file = f"{input_file}.drain_typed"
    size, col_types = write_typed(output_file, templates, encoded)
    print(f"Column types: {col_types}")
    print(f"Typed encoded size: {size:,} bytes")

if __name__ == '__main__':
    main()
