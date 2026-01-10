#!/usr/bin/env python3
"""
Drain-based lossless compression v3 - optimized for post-zstd compression.

Key insight: Store only what's needed to reconstruct exactly.
For timestamps/IPs: store delta AND format template, not full original.

Format improvements:
- Timestamps: delta + format index (reconstructible)
- IP addresses: delta encoding
- Binary dictionary indices for small dictionaries
"""
import sys
import struct
import time
import re
from collections import Counter
from drain3 import TemplateMiner
from drain3.template_miner_config import TemplateMinerConfig

# Encoding types
ENC_RAW = 0
ENC_DICTIONARY = 1
ENC_DELTA_INTEGER = 2
ENC_DELTA_TIMESTAMP = 3

MULTI_SPACE_PREFIX = '•'

# Type detection patterns
# Match timestamps with optional leading [ that may be split from timezone
CLF_TIMESTAMP_RE = re.compile(r'^\[?(\d{2})/(\w{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s*([+-]\d{4})?$')
ISO_TIMESTAMP_RE = re.compile(r'^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(\.\d+)?([+-]\d{2}:?\d{2}|Z)?$')
IPV4_RE = re.compile(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$')

MONTHS = {'Jan':1,'Feb':2,'Mar':3,'Apr':4,'May':5,'Jun':6,
          'Jul':7,'Aug':8,'Sep':9,'Oct':10,'Nov':11,'Dec':12}
MONTHS_REV = {v:k for k,v in MONTHS.items()}

SAFE_INT_RE = re.compile(r'^(-?[1-9]\d*|0)$')


def preprocess_line(line):
    def replace_spaces(match):
        count = len(match.group(0))
        if count <= 9:
            return MULTI_SPACE_PREFIX + str(count)
        else:
            result = []
            while count > 0:
                chunk = min(count, 9)
                result.append(MULTI_SPACE_PREFIX + str(chunk))
                count -= chunk
            return ''.join(result)
    return re.sub(r'  +', replace_spaces, line)


def postprocess_line(line):
    def restore_spaces(match):
        count = int(match.group(1))
        return ' ' * count
    while MULTI_SPACE_PREFIX in line:
        line = re.sub(MULTI_SPACE_PREFIX + r'(\d)', restore_spaces, line)
    return line


def get_line_delta(template, line):
    """Extract variables from line using template."""
    parts = template.split('<*>')
    if len(parts) == 1:
        if template == line:
            return (True, [])
        else:
            return (False, [line])

    variables = []
    remaining = line
    for part in parts:
        if not part:
            continue
        idx = remaining.find(part)
        if idx == -1:
            return (False, [line])
        if idx > 0:
            variables.append(remaining[:idx])
        remaining = remaining[idx + len(part):]
    if remaining:
        variables.append(remaining)

    return (True, variables)


def reconstruct_line(template, variables, matched):
    """Reconstruct original line from template and variables."""
    if not matched:
        return variables[0] if variables else template

    parts = template.split('<*>')
    if len(parts) == 1:
        return template if not variables else variables[0]

    result = []
    var_idx = 0
    for i, part in enumerate(parts):
        if i > 0 and var_idx < len(variables):
            result.append(variables[var_idx])
            var_idx += 1
        result.append(part)

    if var_idx < len(variables):
        result.append(variables[var_idx])

    return ''.join(result)


def parse_clf_timestamp(ts):
    """Parse CLF timestamp, return (seconds, tz_suffix, has_bracket) or (None, None, None)"""
    m = CLF_TIMESTAMP_RE.match(ts)
    if not m:
        return None, None, None, ts

    has_bracket = ts.startswith('[')
    day, mon, year, h, mi, s, tz = m.groups()
    y, mo, d = int(year), MONTHS.get(mon, 1), int(day)
    hr, mn, sc = int(h), int(mi), int(s)

    # Simple epoch calculation (doesn't need to be exact, just consistent)
    days = (y - 1970) * 365 + (y - 1969) // 4 + (mo - 1) * 30 + d
    secs = days * 86400 + hr * 3600 + mn * 60 + sc

    return secs, tz or '', has_bracket, ts


def reconstruct_clf_timestamp(secs, tz, has_bracket):
    """Reconstruct CLF timestamp from seconds, timezone, and bracket flag"""
    # Reverse the epoch calculation
    days = secs // 86400
    rem = secs % 86400
    h = rem // 3600
    rem = rem % 3600
    mi = rem // 60
    s = rem % 60

    # Approximate year/month/day (same algorithm as encoding)
    year = 1970 + days // 365
    day_of_year = days - (year - 1970) * 365 - (year - 1969) // 4

    # Adjust if we went too far
    while day_of_year < 0:
        year -= 1
        day_of_year = days - (year - 1970) * 365 - (year - 1969) // 4

    month = day_of_year // 30 + 1
    if month > 12:
        month = 12
    day = day_of_year - (month - 1) * 30
    if day <= 0:
        month -= 1
        if month <= 0:
            month = 12
            year -= 1
        day = day_of_year - (month - 1) * 30

    month_name = MONTHS_REV.get(month, 'Jan')

    result = f"{day:02d}/{month_name}/{year}:{h:02d}:{mi:02d}:{s:02d}"
    if tz:
        result += f" {tz}"
    if has_bracket:
        result = '[' + result
    return result


def detect_column_type(values):
    """Detect column type from sample values"""
    sample = [v for v in values[:1000] if v]
    if not sample:
        return 'string'

    # Check for CLF timestamps
    clf_count = sum(1 for v in sample if CLF_TIMESTAMP_RE.match(v))
    if clf_count >= len(sample) * 0.9:
        return 'clf_timestamp'

    # Check for integers (without leading zeros)
    int_count = sum(1 for v in sample if SAFE_INT_RE.match(v))
    if int_count >= len(sample) * 0.9:
        nums = [int(v) for v in sample if SAFE_INT_RE.match(v)]
        sorted_count = sum(1 for i in range(1, len(nums)) if nums[i] >= nums[i-1])
        if sorted_count >= len(nums) * 0.7:
            return 'integer_sorted'
        return 'integer'

    return 'string'


def encode_lossless(lines):
    config = TemplateMinerConfig()
    config.profiling_enabled = False
    miner = TemplateMiner(config=config)

    preprocessed = [preprocess_line(line) for line in lines]

    results = []
    for line in preprocessed:
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
        matched, variables = get_line_delta(template, line)
        encoded.append((tid, matched, variables))

    return templates, encoded


def encode_to_bytes(templates, encoded):
    output = bytearray()
    output.extend(b'DRN5')  # Version 5 - optimized for zstd

    output.extend(struct.pack('<H', len(templates)))
    for tid in range(len(templates)):
        tmpl = templates.get(tid, "").encode('utf-8')
        output.extend(struct.pack('<H', len(tmpl)))
        output.extend(tmpl)

    n_lines = len(encoded)
    output.extend(struct.pack('<I', n_lines))

    if len(templates) <= 256:
        output.append(1)
        output.extend(bytes(tid for tid, _, _ in encoded))
    else:
        output.append(2)
        for tid, _, _ in encoded:
            output.extend(struct.pack('<H', tid))

    # Write match flags as bits
    match_bytes = bytearray()
    for i in range(0, n_lines, 8):
        byte = 0
        for j in range(8):
            if i + j < n_lines:
                _, matched, _ = encoded[i + j]
                if matched:
                    byte |= (1 << j)
        match_bytes.append(byte)
    output.extend(match_bytes)

    max_vars = max((len(vars) for _, _, vars in encoded), default=0)
    output.extend(struct.pack('<B', max_vars))

    col_info = []

    for pos in range(max_vars):
        values = [vars[pos] if pos < len(vars) else "" for _, _, vars in encoded]
        col_type = detect_column_type(values)

        if col_type == 'clf_timestamp':
            output.append(ENC_DELTA_TIMESTAMP)

            # Parse all timestamps, collect timezone suffixes
            parsed = []
            tz_set = set()
            all_have_bracket = True
            any_have_bracket = False
            for v in values:
                secs, tz, has_bracket, orig = parse_clf_timestamp(v)
                if secs is not None:
                    parsed.append((secs, tz, has_bracket, None))
                    tz_set.add(tz)
                    if has_bracket:
                        any_have_bracket = True
                    else:
                        all_have_bracket = False
                else:
                    parsed.append((None, None, False, orig))

            # Write timezone dictionary
            tz_list = sorted(tz_set)
            tz_to_id = {tz: i for i, tz in enumerate(tz_list)}
            output.extend(struct.pack('<B', len(tz_list)))
            for tz in tz_list:
                tzb = tz.encode('utf-8')
                output.extend(struct.pack('<B', len(tzb)))
                output.extend(tzb)

            # Write bracket flag (0=none, 1=all have bracket, 2=mixed/per-line)
            if all_have_bracket and any_have_bracket:
                output.append(1)  # All have bracket
            elif not any_have_bracket:
                output.append(0)  # None have bracket
            else:
                output.append(2)  # Mixed - need per-line flags

            # Write deltas and timezone indices
            deltas = []
            tz_indices = []
            bracket_flags = []
            prev = 0
            for secs, tz, has_bracket, orig in parsed:
                if secs is not None:
                    deltas.append(str(secs - prev))
                    prev = secs
                    tz_indices.append(str(tz_to_id[tz]))
                    bracket_flags.append('1' if has_bracket else '0')
                else:
                    # Fallback - store original
                    escaped = orig.replace('\\', '\\\\').replace('\n', '\\n')
                    deltas.append(f"R{escaped}")
                    tz_indices.append("0")  # Dummy
                    bracket_flags.append('0')

            delta_text = '\n'.join(deltas)
            delta_bytes = delta_text.encode('utf-8')
            output.extend(struct.pack('<I', len(delta_bytes)))
            output.extend(delta_bytes)

            tz_text = '\n'.join(tz_indices)
            tz_bytes = tz_text.encode('utf-8')
            output.extend(struct.pack('<I', len(tz_bytes)))
            output.extend(tz_bytes)

            # Only write bracket flags if mixed
            if not all_have_bracket and any_have_bracket:
                bracket_text = '\n'.join(bracket_flags)
                bracket_bytes = bracket_text.encode('utf-8')
                output.extend(struct.pack('<I', len(bracket_bytes)))
                output.extend(bracket_bytes)

            col_info.append('timestamp-delta')

        elif col_type == 'integer_sorted':
            output.append(ENC_DELTA_INTEGER)

            deltas = []
            prev = 0
            for v in values:
                if v and SAFE_INT_RE.match(v):
                    n = int(v)
                    deltas.append(str(n - prev))
                    prev = n
                else:
                    escaped = v.replace('\\', '\\\\').replace('\n', '\\n')
                    deltas.append(f"R{escaped}")

            all_text = '\n'.join(deltas)
            text_bytes = all_text.encode('utf-8')
            output.extend(struct.pack('<I', len(text_bytes)))
            output.extend(text_bytes)
            col_info.append('integer-delta')

        else:
            unique = set(values)
            if len(unique) < 0.3 * n_lines:
                output.append(ENC_DICTIONARY)
                freq = Counter(values)
                sorted_vals = [v for v, _ in freq.most_common()]
                val_to_id = {v: i for i, v in enumerate(sorted_vals)}

                output.extend(struct.pack('<I', len(sorted_vals)))
                for v in sorted_vals:
                    vb = v.encode('utf-8', errors='replace')
                    output.extend(struct.pack('<H', len(vb)))
                    output.extend(vb)

                # Use binary indices if dictionary is small
                if len(sorted_vals) <= 256:
                    output.append(1)
                    output.extend(bytes(val_to_id[v] for v in values))
                else:
                    output.append(0)
                    indices = '\n'.join(str(val_to_id[v]) for v in values)
                    idx_bytes = indices.encode('utf-8')
                    output.extend(struct.pack('<I', len(idx_bytes)))
                    output.extend(idx_bytes)
                col_info.append('dictionary')
            else:
                output.append(ENC_RAW)
                escaped_values = [v.replace('\\', '\\\\').replace('\n', '\\n') for v in values]
                all_text = '\n'.join(escaped_values)
                text_bytes = all_text.encode('utf-8')
                output.extend(struct.pack('<I', len(text_bytes)))
                output.extend(text_bytes)
                col_info.append('raw')

    return bytes(output), col_info


def decode_from_bytes(data):
    pos = 0

    magic = data[pos:pos+4]
    pos += 4
    if magic != b'DRN5':
        raise ValueError(f"Invalid magic: {magic}, expected DRN5")

    num_templates = struct.unpack('<H', data[pos:pos+2])[0]
    pos += 2

    templates = {}
    for tid in range(num_templates):
        tmpl_len = struct.unpack('<H', data[pos:pos+2])[0]
        pos += 2
        templates[tid] = data[pos:pos+tmpl_len].decode('utf-8')
        pos += tmpl_len

    n_lines = struct.unpack('<I', data[pos:pos+4])[0]
    pos += 4

    tid_width = data[pos]
    pos += 1

    if tid_width == 1:
        template_ids = list(data[pos:pos+n_lines])
        pos += n_lines
    else:
        template_ids = []
        for _ in range(n_lines):
            template_ids.append(struct.unpack('<H', data[pos:pos+2])[0])
            pos += 2

    # Read match flags
    n_match_bytes = (n_lines + 7) // 8
    match_bytes = data[pos:pos+n_match_bytes]
    pos += n_match_bytes

    match_flags = []
    for i in range(n_lines):
        byte_idx = i // 8
        bit_idx = i % 8
        matched = bool(match_bytes[byte_idx] & (1 << bit_idx))
        match_flags.append(matched)

    max_vars = data[pos]
    pos += 1

    columns = []
    for col_idx in range(max_vars):
        enc_type = data[pos]
        pos += 1

        if enc_type == ENC_DICTIONARY:
            dict_len = struct.unpack('<I', data[pos:pos+4])[0]
            pos += 4
            dictionary = []
            for _ in range(dict_len):
                val_len = struct.unpack('<H', data[pos:pos+2])[0]
                pos += 2
                dictionary.append(data[pos:pos+val_len].decode('utf-8', errors='replace'))
                pos += val_len

            idx_mode = data[pos]
            pos += 1

            if idx_mode == 1:
                indices = list(data[pos:pos+n_lines])
                pos += n_lines
            else:
                idx_len = struct.unpack('<I', data[pos:pos+4])[0]
                pos += 4
                idx_text = data[pos:pos+idx_len].decode('utf-8')
                pos += idx_len
                indices = [int(x) for x in idx_text.split('\n')]

            values = [dictionary[i] for i in indices]
            columns.append(values)

        elif enc_type == ENC_DELTA_INTEGER:
            text_len = struct.unpack('<I', data[pos:pos+4])[0]
            pos += 4
            text = data[pos:pos+text_len].decode('utf-8')
            pos += text_len

            deltas = text.split('\n')
            values = []
            current = 0
            for d in deltas:
                if d.startswith('R'):
                    raw = d[1:].replace('\\n', '\n').replace('\\\\', '\\')
                    values.append(raw)
                else:
                    current += int(d)
                    values.append(str(current))
            columns.append(values)

        elif enc_type == ENC_DELTA_TIMESTAMP:
            # Read timezone dictionary
            n_tz = data[pos]
            pos += 1
            tz_list = []
            for _ in range(n_tz):
                tz_len = data[pos]
                pos += 1
                tz_list.append(data[pos:pos+tz_len].decode('utf-8'))
                pos += tz_len

            # Read bracket flag
            bracket_mode = data[pos]
            pos += 1

            # Read deltas
            delta_len = struct.unpack('<I', data[pos:pos+4])[0]
            pos += 4
            delta_text = data[pos:pos+delta_len].decode('utf-8')
            pos += delta_len
            deltas = delta_text.split('\n')

            # Read timezone indices
            tz_len = struct.unpack('<I', data[pos:pos+4])[0]
            pos += 4
            tz_text = data[pos:pos+tz_len].decode('utf-8')
            pos += tz_len
            tz_indices = [int(x) for x in tz_text.split('\n')]

            # Read bracket flags if mixed mode
            bracket_flags = None
            if bracket_mode == 2:
                bf_len = struct.unpack('<I', data[pos:pos+4])[0]
                pos += 4
                bf_text = data[pos:pos+bf_len].decode('utf-8')
                pos += bf_len
                bracket_flags = [x == '1' for x in bf_text.split('\n')]

            # Reconstruct timestamps
            values = []
            current = 0
            for i, d in enumerate(deltas):
                if d.startswith('R'):
                    raw = d[1:].replace('\\n', '\n').replace('\\\\', '\\')
                    values.append(raw)
                else:
                    current += int(d)
                    tz = tz_list[tz_indices[i]] if tz_indices[i] < len(tz_list) else ''
                    if bracket_mode == 1:
                        has_bracket = True
                    elif bracket_mode == 0:
                        has_bracket = False
                    else:
                        has_bracket = bracket_flags[i] if bracket_flags and i < len(bracket_flags) else False
                    values.append(reconstruct_clf_timestamp(current, tz, has_bracket))
            columns.append(values)

        else:  # ENC_RAW
            text_len = struct.unpack('<I', data[pos:pos+4])[0]
            pos += 4
            text = data[pos:pos+text_len].decode('utf-8')
            pos += text_len

            raw_values = text.split('\n')
            values = [v.replace('\\n', '\n').replace('\\\\', '\\') for v in raw_values]
            columns.append(values)

    lines = []
    for i in range(n_lines):
        tid = template_ids[i]
        template = templates[tid]
        matched = match_flags[i]

        variables = []
        for col in columns:
            if i < len(col):
                variables.append(col[i])

        while variables and variables[-1] == "":
            variables.pop()

        line = reconstruct_line(template, variables, matched)
        line = postprocess_line(line)
        lines.append(line)

    return lines


def verify_file(input_file):
    with open(input_file, 'r', errors='replace') as f:
        original_lines = [l.rstrip('\n') for l in f]

    print(f"Verifying {len(original_lines)} lines...")

    start = time.time()
    templates, encoded = encode_lossless(original_lines)
    binary_data, col_info = encode_to_bytes(templates, encoded)
    encode_time = time.time() - start

    unmatched = sum(1 for _, matched, _ in encoded if not matched)

    start = time.time()
    decoded_lines = decode_from_bytes(binary_data)
    decode_time = time.time() - start

    if len(decoded_lines) != len(original_lines):
        print(f"✗ Line count mismatch: {len(decoded_lines)} vs {len(original_lines)}")
        return False, None

    errors = 0
    for i, (orig, dec) in enumerate(zip(original_lines, decoded_lines)):
        if orig != dec:
            errors += 1
            if errors <= 5:
                print(f"✗ Line {i} mismatch")
                print(f"  orig: {repr(orig[:100])}")
                print(f"  dec:  {repr(dec[:100])}")

    orig_size = sum(len(l.encode('utf-8')) + 1 for l in original_lines)

    if errors == 0:
        print(f"✓ All {len(original_lines)} lines verified LOSSLESS!")
        print(f"  Templates: {len(templates)}")
        print(f"  Unmatched lines: {unmatched}")
        print(f"  Column encoding: {col_info}")
        print(f"  Encode: {encode_time:.2f}s ({len(original_lines)/encode_time:.0f} lines/sec)")
        print(f"  Decode: {decode_time:.2f}s ({len(original_lines)/decode_time:.0f} lines/sec)")
        print(f"  Size: {len(binary_data):,} bytes ({len(binary_data)*100/orig_size:.1f}% of original)")
        return True, binary_data
    else:
        print(f"✗ {errors} lines with mismatches")
        return False, None


def main():
    if len(sys.argv) < 2:
        print("Usage: drain_lossless_v3.py verify <input_file>")
        sys.exit(1)

    if sys.argv[1] == 'verify':
        result = verify_file(sys.argv[2])
        success = result[0] if isinstance(result, tuple) else result
        sys.exit(0 if success else 1)
    else:
        print(f"Unknown command: {sys.argv[1]}")
        sys.exit(1)


if __name__ == '__main__':
    main()
