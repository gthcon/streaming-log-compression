#!/usr/bin/env python3
"""
Drain + CLP-style encoding:
1. Binary integer encoding (not ASCII)
2. Compact float encoding (sign + digits + decimal pos)
3. Adaptive-width timestamp delta (1/2/4/8 bytes)
4. Auto-detect variable types (int/float/dict string)
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

# CLP-style encoding functions
def encode_clp_integer(val_str):
    """Encode integer as binary (like CLP) - returns None if not valid int"""
    try:
        n = int(val_str)
        # Use smallest width that fits
        if -128 <= n <= 127:
            return struct.pack('<b', n)  # 1 byte signed
        elif -32768 <= n <= 32767:
            return struct.pack('<h', n)  # 2 bytes signed
        elif -2147483648 <= n <= 2147483647:
            return struct.pack('<i', n)  # 4 bytes signed
        else:
            return struct.pack('<q', n)  # 8 bytes signed
    except:
        return None

def encode_clp_float(val_str):
    """Encode float in CLP compact format - returns None if not valid"""
    if '.' not in val_str:
        return None

    try:
        # Parse the float string
        is_negative = val_str.startswith('-')
        s = val_str[1:] if is_negative else val_str

        # Split on decimal
        parts = s.split('.')
        if len(parts) != 2:
            return None

        int_part, frac_part = parts
        digits_str = int_part + frac_part

        # Remove leading zeros but keep at least one digit
        digits_str = digits_str.lstrip('0') or '0'

        if len(digits_str) > 16:  # Too many digits
            return None

        digits = int(digits_str) if digits_str else 0
        num_digits = len(int_part) + len(frac_part)
        decimal_pos = len(frac_part)

        if num_digits > 16 or decimal_pos > 15:
            return None

        # Pack: 1 bit sign, 54 bits digits, 4 bits num_digits-1, 4 bits decimal_pos-1
        encoded = 0
        if is_negative:
            encoded = 1
        encoded <<= 55
        encoded |= digits & ((1 << 54) - 1)
        encoded <<= 4
        encoded |= (num_digits - 1) & 0x0F
        encoded <<= 4
        encoded |= (decimal_pos) & 0x0F  # decimal_pos can be 0

        return struct.pack('<Q', encoded)
    except:
        return None

MONTHS = {'Jan':1,'Feb':2,'Mar':3,'Apr':4,'May':5,'Jun':6,
          'Jul':7,'Aug':8,'Sep':9,'Oct':10,'Nov':11,'Dec':12}

def parse_timestamp_ms(ts):
    """Parse CLF timestamp to milliseconds since epoch"""
    match = re.match(r'\[?(\d{2})/(\w{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})', ts)
    if match:
        day, mon, year, hour, minute, sec = match.groups()
        y = int(year)
        m = MONTHS.get(mon, 0)
        d = int(day)
        # Approximate days since 1970
        days = (y - 1970) * 365 + (y - 1969) // 4 + (m - 1) * 30 + d
        ms = (days * 86400 + int(hour) * 3600 + int(minute) * 60 + int(sec)) * 1000
        return ms
    return None

def encode_timestamp_delta(delta_ms):
    """CLP-style adaptive width timestamp delta"""
    if -128 <= delta_ms <= 127:
        return bytes([0x01]) + struct.pack('<b', delta_ms)  # 1 byte
    elif -32768 <= delta_ms <= 32767:
        return bytes([0x02]) + struct.pack('<h', delta_ms)  # 2 bytes
    elif -2147483648 <= delta_ms <= 2147483647:
        return bytes([0x04]) + struct.pack('<i', delta_ms)  # 4 bytes
    else:
        return bytes([0x08]) + struct.pack('<q', delta_ms)  # 8 bytes

def classify_variable(val_str):
    """Classify variable as int, float, timestamp, or string"""
    # Check integer
    if re.match(r'^-?\d+$', val_str):
        return 'int'

    # Check float
    if re.match(r'^-?\d+\.\d+$', val_str):
        return 'float'

    # Check timestamp
    if parse_timestamp_ms(val_str) is not None:
        return 'timestamp'

    return 'string'

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

def write_clp_style(output_file, templates, encoded):
    """Write with CLP-style binary encoding"""
    output = bytearray()
    output.extend(b'DRNC')  # Magic: Drain + CLP

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

    col_stats = []

    for pos in range(max_vars):
        values = [vars[pos] if pos < len(vars) else "" for _, vars in encoded]

        # Classify column type based on first non-empty values
        sample = [v for v in values[:1000] if v]
        if not sample:
            col_type = 'string'
        else:
            types = [classify_variable(v) for v in sample]
            type_counts = Counter(types)
            col_type, count = type_counts.most_common(1)[0]
            if count < len(sample) * 0.9:
                col_type = 'string'  # Mixed types -> treat as string

        col_stats.append(col_type)

        if col_type == 'int':
            # Binary integer encoding
            output.extend(struct.pack('<B', 1))  # Type marker
            for v in values:
                enc = encode_clp_integer(v) if v else None
                if enc:
                    output.append(len(enc))  # Width marker
                    output.extend(enc)
                else:
                    # Fallback to string
                    vb = v.encode('utf-8', errors='replace')
                    output.append(0x80 | min(len(vb), 127))
                    if len(vb) >= 127:
                        output.extend(struct.pack('<H', len(vb)))
                    output.extend(vb)

        elif col_type == 'float':
            # CLP compact float encoding
            output.extend(struct.pack('<B', 2))  # Type marker
            for v in values:
                enc = encode_clp_float(v) if v else None
                if enc:
                    output.append(0x00)  # Valid float marker
                    output.extend(enc)
                else:
                    # Fallback to string
                    vb = v.encode('utf-8', errors='replace')
                    output.append(0xFF)  # String fallback marker
                    output.extend(struct.pack('<H', len(vb)))
                    output.extend(vb)

        elif col_type == 'timestamp':
            # Delta timestamp encoding
            output.extend(struct.pack('<B', 3))  # Type marker
            prev_ts = 0
            for v in values:
                ts = parse_timestamp_ms(v) if v else None
                if ts is not None:
                    delta = ts - prev_ts
                    output.extend(encode_timestamp_delta(delta))
                    prev_ts = ts
                else:
                    # Fallback: store as string
                    vb = v.encode('utf-8', errors='replace')
                    output.append(0x00)  # Zero-width delta = string follows
                    output.extend(struct.pack('<H', len(vb)))
                    output.extend(vb)

        else:
            # String - use dictionary if low cardinality
            unique = list(dict.fromkeys(values))
            n_unique = len(unique)

            if n_unique < 0.3 * n_lines and n_unique < 65536:
                # Dictionary encoding
                output.extend(struct.pack('<B', 4))  # Dict string type
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
                else:
                    for v in values:
                        output.extend(struct.pack('<H', val_to_id[v]))
            else:
                # Raw string
                output.extend(struct.pack('<B', 5))  # Raw string type
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

    return len(output), col_stats

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

    output_file = f"{input_file}.drain_clp"
    size, col_stats = write_clp_style(output_file, templates, encoded)
    print(f"Column types: {col_stats}")
    print(f"CLP-style encoded size: {size:,} bytes")

if __name__ == '__main__':
    main()
